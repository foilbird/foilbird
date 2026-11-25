// SPDX-License-Identifier: Apache-2.0
//! Read-only facts about the node: os-release, EFI variables, boot entry,
//! health checks. No command execution; only /proc, /sys, /boot (read) and
//! D-Bus property reads.

use crate::pb::{BootConfirmation, BootState, CheckStatus, HealthCheck, Profile, VarProtection};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const EFI_GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const LOADER: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

pub fn os_release() -> HashMap<String, String> {
    let text = fs::read_to_string("/etc/os-release")
        .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        .collect()
}

pub fn read_trim(p: impl AsRef<Path>) -> String {
    fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default()
}

pub fn hostname() -> String {
    read_trim("/proc/sys/kernel/hostname")
}

pub fn kernel_release() -> String {
    read_trim("/proc/sys/kernel/osrelease")
}

pub fn uptime_seconds() -> i64 {
    read_trim("/proc/uptime").split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn efivar(name: &str, guid: &str) -> Option<Vec<u8>> {
    let data = fs::read(format!("/sys/firmware/efi/efivars/{name}-{guid}")).ok()?;
    // first 4 bytes are the attributes
    (data.len() >= 4).then(|| data[4..].to_vec())
}

fn efivar_utf16(name: &str, guid: &str) -> Option<String> {
    let d = efivar(name, guid)?;
    let u: Vec<u16> = d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    String::from_utf16(&u).ok()
}

pub fn secure_boot() -> bool {
    efivar("SecureBoot", EFI_GLOBAL).is_some_and(|d| d.first() == Some(&1))
}

pub fn tpm_present() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/sys/class/tpm/tpm0").exists()
}

pub fn profile(osr: &HashMap<String, String>, has_k8s: bool) -> Profile {
    match osr.get("FOILBIRD_PROFILE").map(String::as_str) {
        Some("k8s-worker") => Profile::K8s,
        Some("container-host") => Profile::ContainerHost,
        _ if has_k8s => Profile::K8s,
        _ => Profile::Unspecified,
    }
}

// ------------------------------------------------------------- boot state

/// Remaining tries of the selected entry, from the UKI file name on the ESP:
/// `<id-stem>+<left>[-<done>].efi`; -1 when the file has no counter.
/// Read at most every ESP_PROBE_EVERY per mount instance of the ESP (mountinfo mount id). A read_dir of an idle
/// automount mounts it again (a GetHealth every few seconds kept the FAT mounted and dirty), and a read_dir of a mounted
/// ESP is an access that restarts its idle timeout (reading on every call while mounted, a GetHealth every 10-30 s kept
/// it mounted for 15 min). A new mount instance (bless, sysupdate,
/// foil-rollback@ mount it themselves after the idle unmount) is read again; renames under the same mount instance
/// show up within 10 min; an agent's StageUpdate or Rollback drops the cache (esp_names_changed), a new boot is a new
/// process. Report only: BootState.confirmation and every decision (gate, Rollback, commit) do not use it.
static TRIES_CACHE: std::sync::Mutex<Option<TriesCache>> = std::sync::Mutex::new(None);

struct TriesCache {
    entry: String,
    left: i32,
    at: Instant,
    /// mount id of the ESP right after the read (None: not mounted)
    mount: Option<String>,
}

/// The agent's own installer or rollback unit renamed ESP entries: the next GetHealth reads them again.
pub fn esp_names_changed() {
    *TRIES_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// mount id of the ESP filesystem (not the autofs trigger), None while the automount is idle
fn esp_mount_id(mounts: &[MountEntry]) -> Option<String> {
    mounts.iter().rev().find(|m| m.point == ESP_MOUNT && m.fstype != "autofs").map(|m| m.id.clone())
}

/// Cached counter still good: same entry, younger than ESP_PROBE_EVERY, and the ESP is either at rest or still the mount
/// instance the value was read from.
fn tries_cache_hit(c: &TriesCache, age: Duration, entry: &str, now_mount: Option<&str>) -> bool {
    c.entry == entry && age < ESP_PROBE_EVERY && (now_mount.is_none() || now_mount == c.mount.as_deref())
}

fn tries_left(entry: &str) -> i32 {
    let read = || parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").unwrap_or_default());
    let mut c = TRIES_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let now_mount = esp_mount_id(&read());
    if let Some(hit) = c.as_ref().filter(|c| tries_cache_hit(c, c.at.elapsed(), entry, now_mount.as_deref())) {
        return hit.left;
    }
    let left = tries_left_in(&Path::new(ESP_MOUNT).join("EFI/Linux"), entry);
    *c = Some(TriesCache { entry: entry.to_string(), left, at: Instant::now(), mount: esp_mount_id(&read()) });
    left
}

fn tries_left_in(dir: &Path, entry: &str) -> i32 {
    let stem = entry.strip_suffix(".efi").unwrap_or(entry);
    let Ok(rd) = fs::read_dir(dir) else { return -1 };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = n.strip_prefix(stem).and_then(|r| r.strip_suffix(".efi")) else { continue };
        if rest.is_empty() {
            return -1;
        }
        if let Some(c) = rest.strip_prefix('+') {
            let left = c.split('-').next().unwrap_or("");
            if let Ok(v) = left.parse() {
                return v;
            }
        }
    }
    -1
}

async fn unit_active(conn: &zbus::Connection, unit: &str) -> Option<bool> {
    let reply = conn
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "GetUnit",
            &(unit,),
        )
        .await
        .ok()?;
    let path: zbus::OwnedObjectPath = reply.body().deserialize().ok()?;
    let reply = conn
        .call_method(
            Some("org.freedesktop.systemd1"),
            path.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.systemd1.Unit", "ActiveState"),
        )
        .await
        .ok()?;
    let v: zbus::OwnedVariant = reply.body().deserialize().ok()?;
    let s: String = v.try_into().ok()?;
    Some(s == "active")
}

/// LoadState of a unit as systemd sees it, with /etc overrides, masks and drop-ins applied ("loaded", "not-found",
/// "masked", "bad-setting", "error"). Manager.LoadUnit answers for a unit that does not exist too (an object with
/// LoadState=not-found), GetUnit does not. None = D-Bus did not answer.
async fn unit_load_state(conn: &zbus::Connection, unit: &str) -> Option<String> {
    let reply = conn
        .call_method(Some("org.freedesktop.systemd1"), "/org/freedesktop/systemd1", Some("org.freedesktop.systemd1.Manager"), "LoadUnit", &(unit,))
        .await
        .ok()?;
    let path: zbus::OwnedObjectPath = reply.body().deserialize().ok()?;
    let reply = conn
        .call_method(Some("org.freedesktop.systemd1"), path.as_str(), Some("org.freedesktop.DBus.Properties"), "Get", &("org.freedesktop.systemd1.Unit", "LoadState"))
        .await
        .ok()?;
    let v: zbus::OwnedVariant = reply.body().deserialize().ok()?;
    v.try_into().ok()
}

/// One property of a unit (GetUnit -> Properties.Get), e.g. ("org.freedesktop.systemd1.Service", "NRestarts").
async fn unit_prop(conn: &zbus::Connection, unit: &str, iface: &str, prop: &str) -> Option<zbus::OwnedVariant> {
    let reply = conn
        .call_method(Some("org.freedesktop.systemd1"), "/org/freedesktop/systemd1", Some("org.freedesktop.systemd1.Manager"), "GetUnit", &(unit,))
        .await
        .ok()?;
    let path: zbus::OwnedObjectPath = reply.body().deserialize().ok()?;
    let reply = conn
        .call_method(Some("org.freedesktop.systemd1"), path.as_str(), Some("org.freedesktop.DBus.Properties"), "Get", &(iface, prop))
        .await
        .ok()?;
    reply.body().deserialize().ok()
}

pub async fn boot_state(run_dir: &Path) -> BootState {
    let entry = efivar_utf16("LoaderEntrySelected", LOADER).unwrap_or_default();
    let tries = if entry.is_empty() { -1 } else { tries_left(&entry) };
    let counted = efivar("LoaderBootCountPath", LOADER).is_some();
    let result = read_trim(run_dir.join("boot-check.result"));
    let complete = match zbus::Connection::system().await {
        Ok(c) => unit_active(&c, "boot-complete.target").await.unwrap_or(false),
        Err(_) => false,
    };
    let confirmation = if result == "FAIL" {
        BootConfirmation::Failed
    } else if complete || (!counted && result == "PASS") {
        // no counter: entry already committed (blessed) earlier
        BootConfirmation::Confirmed
    } else {
        BootConfirmation::Pending
    };
    BootState { confirmation: confirmation as i32, entry, tries_left: tries, rollback: None }
}

// ------------------------------------------------------------- health

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> HealthCheck {
    let mut d: String = detail.into();
    d.truncate(256);
    HealthCheck { name: name.into(), status: status as i32, detail: d }
}

fn mountinfo() -> Vec<(String, String, String)> {
    // (major:minor, mount point, source)
    read_trim("/proc/self/mountinfo")
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            Some((f.get(2)?.to_string(), f.get(4)?.to_string(), f.get(sep + 2)?.to_string()))
        })
        .collect()
}

fn check_usr_verity(mi: &[(String, String, String)]) -> HealthCheck {
    let Some((dev, _, src)) = mi.iter().rev().find(|m| m.1 == "/usr") else {
        return check("usr-verity", CheckStatus::Fail, "/usr is not a separate mount");
    };
    let uuid = read_trim(format!("/sys/dev/block/{dev}/dm/uuid"));
    if uuid.starts_with("CRYPT-VERITY-") {
        check("usr-verity", CheckStatus::Pass, format!("{src} dm-verity"))
    } else {
        check("usr-verity", CheckStatus::Fail, format!("{src} is not dm-verity"))
    }
}

/// /var at rest, from the dm uuid of its block device:
/// CRYPT-LUKS2-* -> LUKS2_TPM2, other dm -> OTHER, no dm -> NONE.
pub fn var_protection_from(mi: &[(String, String, String)], dm_uuid: impl Fn(&str) -> Option<String>) -> VarProtection {
    let Some((dev, _, _)) = mi.iter().rev().find(|m| m.1 == "/var") else { return VarProtection::Unspecified };
    match dm_uuid(dev) {
        Some(u) if u.starts_with("CRYPT-LUKS2-") => VarProtection::Luks2Tpm2,
        Some(u) if !u.is_empty() => VarProtection::Other,
        _ => VarProtection::None,
    }
}

pub fn var_protection() -> VarProtection {
    var_protection_from(&mountinfo(), |dev| {
        let d = format!("/sys/dev/block/{dev}/dm");
        std::path::Path::new(&d).exists().then(|| read_trim(format!("{d}/uuid")))
    })
}

/// /var missing is the most severe state a running node can be in (e.g. the
/// TPM was reset and the LUKS volume cannot be opened): containerd and
/// kubelet do not start and no gate runs on a committed entry. The detail
/// names the failed units behind it (var.mount, systemd-cryptsetup@*).
/// Report of the image's foil-var-epoch unit on the LUKS key slots of /var (format shared
/// with that unit): key=value lines, `schema=1` first, lists of numbers comma-separated ascending, empty = none. Rewritten
/// atomically by every run (sync-booted at boot, enroll, raise); absent = /var not LUKS2 or the unit did not run.
pub const VAR_SLOTS_REPORT: &str = "/run/foilbird/var-epoch/slots";

/// Keys whose non-empty value is an incident (unknown or foreign key material on /var): CRITICAL, never gating.
const SLOT_ALERTS: &[(&str, &str)] = &[
    ("unknown_tpm2_slots", "unknown LUKS key slot {} (TPM2 token of an unknown epoch)"),
    ("tokenless_slots", "unknown LUKS key slot {} (no token)"),
    ("foreign_token_slots", "unknown LUKS key slot {} (token of another type)"),
    ("foreign_tokens", "foreign LUKS token {} (not systemd-tpm2)"),
    ("tpm2_bad_tokens", "LUKS token {} (systemd-tpm2 without exactly one key slot)"),
    ("duplicate_epoch_tokens", "LUKS token {} (second systemd-tpm2 token of one epoch)"),
    // epoch-keys/ is an unsigned cache; a key filed under two epochs or above the staged release is root at work
    ("epoch_keys_suspect", "epoch key file for epoch {} (same key as another epoch, or above the staged release)"),
];
/// Keys that only report what the run did.
const SLOT_DONE: &[&str] = &["wiped_unknown_slots", "wiped_extra_slots", "interrupted_enroll_removed", "orphan_tokens_removed", "removed_tokens"];

/// var-key-slots (pure, for tests): None = no report. Unknown keys are ignored (new keys come without a schema change);
/// schema other than 1 or a malformed list is a WARN (the report is not trusted, nothing is claimed).
pub fn var_slots_status(text: Option<&str>) -> (CheckStatus, String) {
    let Some(text) = text else {
        return (CheckStatus::Skipped, "no key slot report (/var not LUKS2 or foil-var-epoch did not run)".into());
    };
    let kv: Vec<(&str, &str)> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim(), v.trim())).collect();
    let get = |k: &str| kv.iter().find(|(x, _)| *x == k).map(|(_, v)| *v).unwrap_or("");
    if get("schema") != "1" {
        return (CheckStatus::Warn, format!("key slot report: schema {:?} not understood", get("schema")));
    }
    let list = |k: &str| -> Result<Vec<u32>, String> {
        let v = get(k);
        if v.is_empty() {
            return Ok(vec![]);
        }
        v.split(',').map(|x| x.trim().parse::<u32>().map_err(|_| format!("key slot report: {k}={v:?} is not a list of numbers"))).collect()
    };
    let mut alerts = vec![];
    for (k, msg) in SLOT_ALERTS {
        match list(k) {
            Ok(l) if l.is_empty() => {}
            Ok(l) => alerts.push(msg.replace("{}", &l.iter().map(u32::to_string).collect::<Vec<_>>().join(", "))),
            Err(e) => return (CheckStatus::Warn, e),
        }
    }
    let mut done = vec![];
    for k in SLOT_DONE {
        match list(k) {
            Ok(l) if l.is_empty() => {}
            Ok(l) => done.push(format!("{k}={}", l.iter().map(u32::to_string).collect::<Vec<_>>().join(","))),
            Err(e) => return (CheckStatus::Warn, e),
        }
    }
    let op = get("op").chars().filter(|c| c.is_ascii_alphanumeric() || "-._~+".contains(*c)).take(80).collect::<String>();
    let at = get("time_unix").parse::<u64>().unwrap_or(0);
    let tail = format!("{}(report of {op} at {at})", if done.is_empty() { String::new() } else { format!("done: {}; ", done.join(" ")) });
    if alerts.is_empty() {
        (CheckStatus::Pass, format!("no unknown key material on /var; {tail}"))
    } else {
        (CheckStatus::Fail, format!("CRITICAL: {}; {tail}", alerts.join("; ")))
    }
}

/// var-key-slots: CRITICAL on unknown or foreign key material (an incident, not a broken release: outside the gate).
/// The first sight of each new report content is written to the audit log.
fn check_var_slots(path: &Path) -> HealthCheck {
    use std::io::Read;
    let text = fs::File::open(path).ok().and_then(|f| {
        let mut b = String::new();
        f.take(64 * 1024).read_to_string(&mut b).ok().map(|_| b)
    });
    let (st, d) = var_slots_status(text.as_deref());
    static LAST: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
    if st == CheckStatus::Fail {
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        if *last != d {
            tracing::warn!(target: "audit", detail = %d, "var-key-slots: unknown key material on /var");
            *last = d.clone();
        }
    }
    check("var-key-slots", st, d)
}

/// ESP mount point (systemd-gpt-auto-generator automount, idle timeout: not mounted at rest is normal).
pub const ESP_MOUNT: &str = "/boot";
/// Set by systemd-boot: the firmware booted from an ESP, so one is expected at /boot.
const LOADER_DEVICE_PART_UUID: &str = "/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// A /proc/self/mountinfo line: mount point, per-mount options, fs type, source, super block options.
#[derive(Debug, Clone, PartialEq)]
pub struct MountEntry {
    /// mountinfo mount id (field 1): a new mount of the same path gets a new id
    pub id: String,
    pub point: String,
    pub opts: String,
    pub fstype: String,
    pub source: String,
    pub super_opts: String,
}

pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            Some(MountEntry {
                id: f.first()?.to_string(),
                point: f.get(4)?.replace("\\040", " "),
                opts: f.get(5)?.to_string(),
                fstype: f.get(sep + 1)?.to_string(),
                source: f.get(sep + 2)?.to_string(),
                super_opts: f.get(sep + 3).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

/// esp-writable (pure, for tests): `mounts` read right after an access to the ESP path (which triggers
/// the automount), `access_err` = the error of that access, `expected` = the boot loader named an ESP. A read-only super
/// block (vfat errors=remount-ro after a dirty FAT, or a remount ro) or a failed mount -> CRITICAL: without a writable ESP
/// the node cannot bless a boot, stage an update or roll back. Outside the gate: the booted image is not what is broken.
/// The per-mount flags are not used: the agent runs with ProtectSystem=strict, so in its namespace every mount is ro.
pub fn esp_status(mounts: &[MountEntry], point: &str, access_err: Option<&str>, expected: bool) -> (CheckStatus, String) {
    let ro = |o: &str| o.split(',').any(|x| x == "ro");
    let autofs = mounts.iter().any(|m| m.point == point && m.fstype == "autofs");
    match mounts.iter().rev().find(|m| m.point == point && m.fstype != "autofs") {
        Some(m) if ro(&m.super_opts) => (
            CheckStatus::Fail,
            format!("CRITICAL: ESP {} at {point} is read-only ({}): no bless, StageUpdate or Rollback; reboot the node (fsck runs before the first mount)", m.source, m.super_opts),
        ),
        Some(m) => (CheckStatus::Pass, format!("{} {} at {point}, read-write", m.source, m.fstype)),
        None if autofs || expected => (
            CheckStatus::Fail,
            format!(
                "CRITICAL: ESP not mounted at {point}{}{}: no bless, StageUpdate or Rollback",
                if autofs { " (automount did not mount it)" } else { "" },
                access_err.map(|e| format!(", access: {e}")).unwrap_or_default()
            ),
        ),
        None => (CheckStatus::Skipped, format!("no ESP at {point} (the boot loader names none)")),
    }
}

/// How often an ESP at rest (automount idle) is mounted just to look at it. Linux marks a FAT dirty while it is mounted
/// read-write, so a probe on every GetHealth (the controller polls) would keep it mounted and dirty across power losses.
const ESP_PROBE_EVERY: Duration = Duration::from_secs(600);

fn check_esp() -> HealthCheck {
    static CACHE: std::sync::Mutex<Option<(Instant, CheckStatus, String)>> = std::sync::Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let read = || parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").unwrap_or_default());
    let expected = Path::new(LOADER_DEVICE_PART_UUID).exists();
    let mut mounts = read();
    let mounted = mounts.iter().any(|m| m.point == ESP_MOUNT && m.fstype != "autofs");
    let (st, d) = match cache.as_ref() {
        // at rest and probed recently: the last result, the automount stays idle
        Some((at, st, d)) if !mounted && at.elapsed() < ESP_PROBE_EVERY => (*st, format!("{d} (at rest; probed {}s ago)", at.elapsed().as_secs())),
        _ => {
            // mounted already: mountinfo is enough; at rest: the access mounts the idle automount, mountinfo is read after it
            let err = if mounted { None } else { fs::read_dir(Path::new(ESP_MOUNT).join("loader")).err().map(|e| e.to_string()) };
            if !mounted {
                mounts = read();
            }
            let (st, d) = esp_status(&mounts, ESP_MOUNT, err.as_deref(), expected);
            if st == CheckStatus::Fail && cache.as_ref().map(|c| &c.2) != Some(&d) {
                tracing::warn!(detail = %d, "esp-writable: the ESP cannot be written");
            }
            *cache = Some((Instant::now(), st, d.clone()));
            (st, d)
        }
    };
    check("esp-writable", st, d)
}

async fn check_var(mi: &[(String, String, String)]) -> HealthCheck {
    if let Some((_, _, src)) = mi.iter().rev().find(|m| m.1 == "/var") {
        return check("var-mounted", CheckStatus::Pass, src.clone());
    }
    let why: Option<Vec<String>> = async {
        type Row = (String, String, String, String, String, String, zbus::OwnedObjectPath, u32, String, zbus::OwnedObjectPath);
        let c = zbus::Connection::system().await.ok()?;
        let rows: Vec<Row> = c
            .call_method(Some("org.freedesktop.systemd1"), "/org/freedesktop/systemd1", Some("org.freedesktop.systemd1.Manager"), "ListUnits", &())
            .await
            .ok()?
            .body()
            .deserialize()
            .ok()?;
        Some(
            rows.into_iter()
                .filter(|r| r.0 == "var.mount" || (r.0.starts_with("systemd-cryptsetup@") && r.3 == "failed"))
                .map(|r| format!("{}: {}/{}", r.0, r.3, r.4))
                .collect(),
        )
    }
    .await;
    let detail = match why {
        Some(v) if !v.is_empty() => format!("CRITICAL: /var is not mounted; {}", v.join(", ")),
        _ => "CRITICAL: /var is not mounted".to_string(),
    };
    check("var-mounted", CheckStatus::Fail, detail)
}

/// Default route (v4 or v6). Reported only: it depends on the environment (a router can be down while a release
/// boots), not on the image, so it never gates the boot; WARN when missing.
fn check_default_route() -> HealthCheck {
    let v4 = read_trim("/proc/net/route").lines().skip(1).any(|l| l.split_whitespace().nth(1) == Some("00000000"));
    let v6 = read_trim("/proc/net/ipv6_route")
        .lines()
        .any(|l| l.starts_with("00000000000000000000000000000000 00 ") && !l.trim_end().ends_with(" lo"));
    if v4 || v6 {
        check("network-online", CheckStatus::Pass, format!("default route v4={v4} v6={v6}"))
    } else {
        check("network-online", CheckStatus::Warn, "no default route")
    }
}

/// One networkd file rendered from NodeConfig (`/run/systemd/network/50-foil-*.network`): its `[Match]`,
/// static addresses and whether DHCP is on.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NetMatch {
    pub file: String,
    pub mac: Option<String>,
    pub name: Option<String>,
    pub ether: bool,
    /// `Address=` without the prefix length (static addresses, required on the host).
    pub addresses: Vec<std::net::IpAddr>,
    pub dhcp: bool,
}

/// One kernel link as seen in /sys/class/net (+ addresses) and networkd's state for it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LinkInfo {
    pub name: String,
    pub mac: String,
    pub arphrd: u32,
    pub up: bool,
    pub addr: bool,
    /// networkd AdministrativeState (pending, initialized, configuring, configured, unmanaged, failed, linger); None = unknown.
    pub admin: Option<String>,
    /// Physical carrier (networkd CarrierState, else /sys/class/net/<if>/carrier).
    pub carrier: bool,
}

pub fn parse_net_match(file: &str, text: &str) -> NetMatch {
    let mut m = NetMatch { file: file.to_string(), ..Default::default() };
    let mut sec = "";
    for l in text.lines().map(str::trim) {
        if l.starts_with('[') {
            sec = match l {
                "[Match]" => "match",
                "[Network]" => "network",
                "[Address]" => "address",
                _ => "",
            };
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match (sec, k) {
            ("match", "MACAddress") => m.mac = Some(v.to_ascii_lowercase()),
            ("match", "Name") => m.name = Some(v.to_string()),
            ("match", "Type") => m.ether = v == "ether",
            ("network" | "address", "Address") => {
                if let Ok(a) = v.split('/').next().unwrap_or("").parse() {
                    m.addresses.push(a);
                }
            }
            ("network", "DHCP") => m.dhcp = matches!(v, "yes" | "true" | "ipv4" | "ipv6"),
            _ => {}
        }
    }
    m
}

/// networkd-style name glob: `*` and `?` only.
fn glob(p: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    fn go(p: &[char], s: &[char]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(&p, &s)
}

fn link_matches(m: &NetMatch, l: &LinkInfo) -> bool {
    l.name != "lo"
        && m.mac.as_ref().is_none_or(|x| *x == l.mac)
        && m.name.as_ref().is_none_or(|g| g.split_whitespace().any(|g| glob(g, &l.name)))
        && (!m.ether || l.arphrd == 1)
}

/// Local addresses of the host: IPv4 from /proc/net/fib_trie (the `/32 host LOCAL` entries), IPv6 from
/// /proc/net/if_inet6. Pure, for tests.
pub fn host_addresses(fib_trie: &str, if_inet6: &str) -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    let mut last: Option<std::net::IpAddr> = None;
    for l in fib_trie.lines() {
        let t = l.trim_start().trim_start_matches(['|', '+', '-', ' ']);
        if let Ok(a) = t.trim().parse::<std::net::Ipv4Addr>() {
            last = Some(a.into());
        } else if l.contains("/32 host LOCAL") {
            if let Some(a) = last {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    for l in if_inet6.lines() {
        let Some(h) = l.split_whitespace().next().filter(|h| h.len() == 32) else { continue };
        if let Ok(v) = u128::from_str_radix(h, 16) {
            out.push(std::net::Ipv6Addr::from(v).into());
        }
    }
    out
}

/// network-config (pure, for tests), as Talos: required = networkd applied the NodeConfig
/// interfaces without an error and their static addresses are on the host. Carrier and a DHCP address are
/// only a WARN: an unplugged cable or a DHCP outage during an A/B update must not roll back a healthy release.
///   no matching link / state unknown / pending, initialized, unmanaged / static address missing -> Pending
///   AdministrativeState failed or linger -> Fail
///   configuring or configured, static addresses present -> Pass, or Warn (no carrier; DHCP without address)
/// No rendered interfaces = nothing to check.
pub fn network_config_status(files: &[NetMatch], links: &[LinkInfo], host: &[std::net::IpAddr]) -> (CheckStatus, String) {
    if files.is_empty() {
        return (CheckStatus::Skipped, "no interfaces rendered from NodeConfig".into());
    }
    let (mut fail, mut pending, mut warn, mut ok) = (vec![], vec![], vec![], vec![]);
    for f in files {
        let cand: Vec<&LinkInfo> = links.iter().filter(|l| link_matches(f, l)).collect();
        if cand.is_empty() {
            pending.push(format!("{}: no matching link", f.file));
            continue;
        }
        // per link: Ok(warnings) | Err((status, why)); the file counts as applied if one link is
        let eval = |l: &LinkInfo| -> Result<Vec<String>, (CheckStatus, String)> {
            match l.admin.as_deref() {
                Some("failed" | "linger") => return Err((CheckStatus::Fail, format!("{} networkd state {}", l.name, l.admin.as_deref().unwrap_or("")))),
                Some("configuring" | "configured") => {}
                Some(a) => return Err((CheckStatus::Pending, format!("{} networkd state {a}", l.name))),
                None => return Err((CheckStatus::Pending, format!("{} networkd state unknown", l.name))),
            }
            let missing: Vec<String> = f.addresses.iter().filter(|a| !host.contains(a)).map(|a| a.to_string()).collect();
            if !missing.is_empty() {
                return Err((CheckStatus::Pending, format!("{}: static {} not on the host", l.name, missing.join(" "))));
            }
            let mut w = vec![];
            if !l.carrier {
                w.push(format!("{}: no carrier", l.name));
            }
            if f.dhcp && f.addresses.is_empty() && !l.addr {
                w.push(format!("{}: no DHCP address", l.name));
            }
            Ok(w)
        };
        let res: Vec<_> = cand.iter().map(|l| (l, eval(l))).collect();
        if let Some((l, Ok(w))) = res.iter().find(|(_, r)| r.as_ref().is_ok_and(|w| w.is_empty())).or_else(|| res.iter().find(|(_, r)| r.is_ok())) {
            ok.push(format!("{}={}", f.file, l.name));
            warn.extend(w.iter().map(|x| format!("{}: {x}", f.file)));
        } else if let Some((_, Err((_, why)))) = res.iter().find(|(_, r)| matches!(r, Err((CheckStatus::Fail, _)))) {
            fail.push(format!("{}: {why}", f.file));
        } else {
            let why: Vec<String> = res.iter().filter_map(|(_, r)| r.as_ref().err().map(|e| e.1.clone())).collect();
            pending.push(format!("{}: {}", f.file, why.join(", ")));
        }
    }
    if !fail.is_empty() {
        (CheckStatus::Fail, fail.join("; "))
    } else if !pending.is_empty() {
        (CheckStatus::Pending, pending.join("; "))
    } else if !warn.is_empty() {
        (CheckStatus::Warn, format!("applied: {}; {}", ok.join(" "), warn.join("; ")))
    } else {
        (CheckStatus::Pass, format!("applied, carrier, addresses: {}", ok.join(" ")))
    }
}

/// networkd's view of the links over D-Bus (org.freedesktop.network1, read-only properties): name ->
/// (AdministrativeState, CarrierState). None = network1 not reachable.
async fn network1_links(conn: &zbus::Connection) -> Option<std::collections::HashMap<String, (String, String)>> {
    let reply = conn
        .call_method(Some("org.freedesktop.network1"), "/org/freedesktop/network1", Some("org.freedesktop.network1.Manager"), "ListLinks", &())
        .await
        .ok()?;
    let list: Vec<(i32, String, zbus::OwnedObjectPath)> = reply.body().deserialize().ok()?;
    let mut out = std::collections::HashMap::new();
    for (_, name, path) in list {
        let get = |prop: &'static str| {
            let path = path.clone();
            async move {
                let r = conn
                    .call_method(Some("org.freedesktop.network1"), path.as_str(), Some("org.freedesktop.DBus.Properties"), "Get", &("org.freedesktop.network1.Link", prop))
                    .await
                    .ok()?;
                let v: zbus::OwnedVariant = r.body().deserialize().ok()?;
                String::try_from(v).ok()
            }
        };
        let admin = get("AdministrativeState").await.unwrap_or_default();
        let carrier = get("CarrierState").await.unwrap_or_default();
        out.insert(name, (admin, carrier));
    }
    Some(out)
}

/// Fallback when network1 is not reachable: networkd's state file /run/systemd/netif/links/<ifindex>
/// (internal format, not a stable interface): ADMIN_STATE=, CARRIER_STATE=.
fn netif_state_file(ifindex: &str) -> Option<(String, String)> {
    let t = std::fs::read_to_string(format!("/run/systemd/netif/links/{ifindex}")).ok()?;
    let get = |k: &str| t.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string())).unwrap_or_default();
    Some((get("ADMIN_STATE="), get("CARRIER_STATE=")))
}

/// IPv4 address on an interface (SIOCGIFADDR on an AF_INET socket: the gate unit allows AF_INET, not AF_NETLINK).
fn has_ipv4(ifname: &str) -> bool {
    if ifname.len() >= libc::IFNAMSIZ {
        return false;
    }
    // SAFETY: plain socket/ioctl/close on a zeroed ifreq with a NUL-terminated name shorter than IFNAMSIZ.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in ifname.bytes().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
        let r = libc::ioctl(fd, libc::SIOCGIFADDR as _, &mut ifr);
        libc::close(fd);
        r == 0
    }
}

/// Kernel links with networkd's state: from network1 over D-Bus, else the /run state file. Returns the source.
async fn links(conn: Option<&zbus::Connection>) -> (Vec<LinkInfo>, &'static str) {
    let v6 = read_trim("/proc/net/if_inet6");
    let nd = match conn {
        Some(c) => network1_links(c).await,
        None => None,
    };
    let src = if nd.is_some() { "networkd state over D-Bus" } else { "networkd state from /run/systemd/netif (D-Bus not reachable)" };
    let Ok(rd) = fs::read_dir("/sys/class/net") else { return (vec![], src) };
    let v = rd
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let d = e.path();
            // if_inet6: addr idx prefix scope flags name; scope 00 = global
            let g6 = v6.lines().any(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.len() == 6 && f[5] == name && f[3] == "00"
            });
            let state = match &nd {
                Some(m) => m.get(&name).cloned(),
                None => netif_state_file(&read_trim(d.join("ifindex"))),
            };
            let sys_carrier = read_trim(d.join("carrier")) == "1";
            let carrier = match state.as_ref().map(|s| s.1.as_str()) {
                Some("carrier" | "enslaved" | "degraded-carrier") => true,
                Some("" ) | None => sys_carrier,
                Some(_) => false,
            };
            LinkInfo {
                mac: read_trim(d.join("address")).to_ascii_lowercase(),
                arphrd: read_trim(d.join("type")).parse().unwrap_or(0),
                up: read_trim(d.join("operstate")) == "up",
                addr: has_ipv4(&name) || g6,
                admin: state.map(|s| s.0).filter(|a| !a.is_empty()),
                carrier,
                name,
            }
        })
        .collect();
    (v, src)
}

/// network-config: NodeConfig interfaces applied by networkd; carrier and DHCP address only WARN.
async fn check_network_config(conn: Option<&zbus::Connection>, networkd_dir: &Path) -> HealthCheck {
    let mut files: Vec<NetMatch> = fs::read_dir(networkd_dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    (n.starts_with("50-foil-") && n.ends_with(".network")).then(|| parse_net_match(&n, &read_trim(e.path())))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort_by(|a, b| a.file.cmp(&b.file));
    let (links, src) = links(conn).await;
    let host = host_addresses(&read_trim("/proc/net/fib_trie"), &read_trim("/proc/net/if_inet6"));
    let (st, d) = network_config_status(&files, &links, &host);
    check("network-config", st, if st == CheckStatus::Skipped { d } else { format!("{d} ({src})") })
}

/// The agent counts only when it serves its API: an active unit whose listener is missing (e.g. a product build
/// without TLS material) would otherwise commit a release nobody can reach. TCP connect to the default
/// listener; TLS is not negotiated here (the gate has no client certificate).
pub const AGENT_API: &str = "127.0.0.1:7443";

async fn check_agent_api(unit: HealthCheck) -> HealthCheck {
    if unit.status != CheckStatus::Pass as i32 {
        return unit;
    }
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(AGENT_API)).await {
        Ok(Ok(_)) => check("agent", CheckStatus::Pass, format!("{}; API {AGENT_API} listening", unit.detail)),
        _ => check("agent", CheckStatus::Pending, format!("{}; API {AGENT_API} not listening", unit.detail)),
    }
}

/// State of a required unit (pure, for tests): active = Pass, failed = Fail, an Assert*= that failed in this boot
/// (AssertResult=no) = Fail, skipped by a Condition*= evaluated in this boot (ConditionResult=no) = Skipped; anything
/// else (not started yet, its condition met but no job yet, activating, auto-restart) = Pending. `condition_ok` and
/// `assert_ok` are None when not evaluated in this boot. A service's ExecCondition is not a skip here: none of the
/// checked units uses one.
pub fn unit_status(active: &str, condition_ok: Option<bool>, assert_ok: Option<bool>) -> CheckStatus {
    if assert_ok == Some(false) {
        return CheckStatus::Fail;
    }
    match active {
        "active" => CheckStatus::Pass,
        "failed" => CheckStatus::Fail,
        "inactive" if condition_ok == Some(false) => CheckStatus::Skipped,
        _ => CheckStatus::Pending,
    }
}

/// State of a unit over D-Bus as (status, detail); None = not readable.
async fn unit_state(conn: Option<&zbus::Connection>, unit: &str) -> Option<(CheckStatus, String)> {
    const U: &str = "org.freedesktop.systemd1.Unit";
    let c = conn?;
    let a: String = unit_prop(c, unit, U, "ActiveState").await?.try_into().ok()?;
    let r: String = match unit_prop(c, unit, "org.freedesktop.systemd1.Service", "Result").await {
        Some(v) => v.try_into().unwrap_or_default(),
        None => String::new(),
    };
    let cond: Option<bool> = unit_prop(c, unit, U, "ConditionResult").await.and_then(|v| v.try_into().ok());
    let ct: u64 = unit_prop(c, unit, U, "ConditionTimestamp").await.and_then(|v| v.try_into().ok()).unwrap_or(0);
    let asr: Option<bool> = unit_prop(c, unit, U, "AssertResult").await.and_then(|v| v.try_into().ok());
    let at: u64 = unit_prop(c, unit, U, "AssertTimestamp").await.and_then(|v| v.try_into().ok()).unwrap_or(0);
    let (cond, asr) = (cond.filter(|_| ct != 0), asr.filter(|_| at != 0));
    let why = match (cond, asr) {
        (_, Some(false)) => " AssertResult=no",
        (Some(false), _) => " ConditionResult=no",
        _ => "",
    };
    Some((unit_status(&a, cond, asr), format!("{unit}: ActiveState={a} Result={r}{why}")))
}

async fn check_unit(conn: Option<&zbus::Connection>, name: &str, unit: &str) -> HealthCheck {
    match unit_state(conn, unit).await {
        Some((st, d)) => check(name, st, d),
        None => check(name, CheckStatus::Pending, format!("{unit}: state not readable over D-Bus")),
    }
}

/// Kernel clock synchronized (adjtimex without STA_UNSYNC: timesyncd clears it on sync).
pub fn clock_synced() -> bool {
    // SAFETY: zeroed timex with modes=0 is a read-only query.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    let st = unsafe { libc::adjtimex(&mut tx) };
    st >= 0 && st != libc::TIME_ERROR
}

/// Written by `foil-agent wait-time-sync` when its wait before the first join
/// timed out; removed once the clock is synchronized.
pub const TIME_WAIT_RESULT: &str = "time-sync.result";

/// time-synced (pure, for tests). Before the first join (owner policy) an
/// unsynchronized clock blocks the join: PENDING while the join waits, FAIL
/// once the wait timed out. Otherwise it is only WARN. Never gates a boot.
pub fn time_check(synced: bool, first_join_pending: bool, wait_timeout: Option<&str>, servers: &str) -> (CheckStatus, String) {
    match (synced, first_join_pending, wait_timeout) {
        (true, _, _) => (CheckStatus::Pass, format!("clock synchronized; {servers}")),
        (false, true, Some(t)) => (CheckStatus::Fail, format!("first join blocked: clock not synchronized ({t}); {servers}")),
        (false, true, None) => (CheckStatus::Pending, format!("first join waits for time sync; {servers}")),
        (false, false, _) => (CheckStatus::Warn, format!("clock not synchronized; {servers}")),
    }
}

/// NTP servers as timesyncd sees them (D-Bus org.freedesktop.timesync1).
pub async fn ntp_servers() -> String {
    let r: Option<String> = async {
        let c = zbus::Connection::system().await.ok()?;
        let get = |p: &'static str| {
            let c = c.clone();
            async move {
                let reply = c
                    .call_method(
                        Some("org.freedesktop.timesync1"),
                        "/org/freedesktop/timesync1",
                        Some("org.freedesktop.DBus.Properties"),
                        "Get",
                        &("org.freedesktop.timesync1.Manager", p),
                    )
                    .await
                    .ok()?;
                reply.body().deserialize::<zbus::OwnedVariant>().ok()
            }
        };
        let list = |v: Option<zbus::OwnedVariant>| -> String {
            v.and_then(|v| Vec::<String>::try_from(v).ok()).map(|l| l.join(",")).unwrap_or_default()
        };
        let system = list(get("SystemNTPServers").await);
        let link = list(get("LinkNTPServers").await);
        let current = get("ServerName").await.and_then(|v| String::try_from(v).ok()).unwrap_or_default();
        Some(format!("ntp system=[{system}] link=[{link}] current={}", if current.is_empty() { "-" } else { &current }))
    }
    .await;
    r.unwrap_or_else(|| "timesyncd not reachable over D-Bus".into())
}

async fn check_time(profile: Profile, run_dir: &Path) -> HealthCheck {
    let synced = clock_synced();
    let first_join = profile == Profile::K8s && !Path::new(KUBELET_CONF).exists();
    let wait = read_trim(run_dir.join(TIME_WAIT_RESULT));
    let servers = ntp_servers().await;
    let (st, detail) = time_check(synced, first_join, (!wait.is_empty()).then_some(wait.as_str()), &servers);
    check("time-synced", st, detail)
}

async fn check_failed_units() -> HealthCheck {
    let r: Option<u32> = async {
        let c = zbus::Connection::system().await.ok()?;
        let reply = c
            .call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.systemd1.Manager", "NFailedUnits"),
            )
            .await
            .ok()?;
        let v: zbus::OwnedVariant = reply.body().deserialize().ok()?;
        v.try_into().ok()
    }
    .await;
    match r {
        Some(0) => check("no-failed-units", CheckStatus::Pass, "0 failed units"),
        Some(n) => check("no-failed-units", CheckStatus::Warn, format!("{n} failed units")),
        None => check("no-failed-units", CheckStatus::Warn, "systemd D-Bus not reachable"),
    }
}

async fn check_kubelet(profile: Profile) -> HealthCheck {
    if profile != Profile::K8s {
        return check("kubelet-healthy", CheckStatus::Skipped, "profile is not k8s-worker");
    }
    if !Path::new("/usr/bin/kubelet").exists() {
        return check("kubelet-healthy", CheckStatus::Fail, "kubelet not in image");
    }
    // required only once the node is in the cluster. Before the first join kubelet restarts until kubeadm writes
    // its configuration; whether the join itself can happen depends on the cluster and the clock (p.22), not on the
    // image. The probe is local (127.0.0.1:10248): no required check talks to the API server.
    if !Path::new(KUBELET_CONF).exists() {
        return check("kubelet-healthy", CheckStatus::Skipped, "node not joined yet: kubelet not required");
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let probe = async {
        let mut s = tokio::net::TcpStream::connect("127.0.0.1:10248").await.ok()?;
        s.write_all(b"GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").await.ok()?;
        let mut buf = Vec::new();
        s.take(4096).read_to_end(&mut buf).await.ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    };
    match tokio::time::timeout(Duration::from_secs(3), probe).await {
        Ok(Some(r)) if r.starts_with("HTTP/1.") && r.contains(" 200 ") && r.ends_with("ok") => {
            check("kubelet-healthy", CheckStatus::Pass, "healthz ok")
        }
        Ok(Some(r)) => check("kubelet-healthy", CheckStatus::Pending, r.lines().next().unwrap_or("").to_string()),
        _ => check("kubelet-healthy", CheckStatus::Pending, "healthz not reachable"),
    }
}

/// Automatic restarts of kubelet after which a joined node's gate fails at once. kubelet.service has
/// Restart=always RestartSec=10, so a kubelet that dies at start reaches this in ~30-40 s; a healthy start after the
/// join has 0-1.
pub const KUBELET_MAX_RESTARTS: u32 = 3;

/// Fail-fast decision for kubelet (pure, for tests): Some(detail) when kubelet of a node that is already in the
/// cluster is failed, hit its start limit or keeps restarting. Before the join kubelet restarts until kubeadm writes
/// its configuration, so an unjoined node never fails here (a first boot must not roll back).
pub fn kubelet_crashloop(active: &str, result: &str, n_restarts: u32, joined: bool) -> Option<String> {
    if !joined {
        return None;
    }
    if active == "failed" || result == "start-limit-hit" || n_restarts >= KUBELET_MAX_RESTARTS {
        Some(format!("kubelet crash-looping on a joined node: ActiveState={active} Result={result} NRestarts={n_restarts}"))
    } else {
        None
    }
}

/// The node is in the cluster: kubeadm join wrote the kubelet kubeconfig (same condition as foil-kubeadm-join's
/// ConditionPathExists=!).
const KUBELET_CONF: &str = "/etc/kubernetes/kubelet.conf";

/// Joined before this boot (pure, for tests). A join during this boot does not count: kubelet restarted until the
/// join wrote its config, so NRestarts says nothing yet. Two signs, both required:
/// - foil-kubeadm-join.service was checked in this boot and skipped (ConditionResult=false, ConditionTimestamp!=0):
///   kubelet.conf already existed when it was evaluated; this does not depend on the clock;
/// - the kubeconfig is older than the boot (btime follows the clock: a slow RTC fixed by NTP after the join could make
///   a fresh file look old, hence not alone).
/// Anything unknown (unit not evaluated yet, no file, no btime) only disables the fail-fast (the gate then waits).
pub fn joined_before_boot(conf_mtime: Option<u64>, boot_time: Option<u64>, join_unit: Option<(bool, u64)>) -> bool {
    let unit_skipped = matches!(join_unit, Some((false, ts)) if ts != 0);
    unit_skipped && matches!((conf_mtime, boot_time), (Some(m), Some(b)) if m < b)
}

fn boot_time() -> Option<u64> {
    fs::read_to_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
}

fn mtime_secs(p: &str) -> Option<u64> {
    fs::metadata(p).ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// kubelet-crashloop: evaluated only while kubelet-healthy is not passing; Fail is a hard failure of the boot gate.
async fn check_kubelet_crashloop(profile: Profile, healthy: bool) -> HealthCheck {
    const N: &str = "kubelet-crashloop";
    if profile != Profile::K8s {
        return check(N, CheckStatus::Skipped, "profile is not k8s-worker");
    }
    if healthy {
        return check(N, CheckStatus::Skipped, "kubelet healthy");
    }
    let conf = mtime_secs(KUBELET_CONF);
    if conf.is_none() {
        return check(N, CheckStatus::Skipped, "node not joined yet");
    }
    let conn = zbus::Connection::system().await.ok();
    let join_unit = async {
        let c = conn.as_ref()?;
        let r: bool = unit_prop(c, "foil-kubeadm-join.service", "org.freedesktop.systemd1.Unit", "ConditionResult").await?.try_into().ok()?;
        let t: u64 = unit_prop(c, "foil-kubeadm-join.service", "org.freedesktop.systemd1.Unit", "ConditionTimestamp").await?.try_into().ok()?;
        Some((r, t))
    }
    .await;
    let joined = joined_before_boot(conf, boot_time(), join_unit);
    if !joined {
        return check(N, CheckStatus::Skipped, format!("not joined before this boot (join unit condition {join_unit:?})"));
    }
    let st = async {
        let c = conn.as_ref()?;
        let a: String = unit_prop(c, "kubelet.service", "org.freedesktop.systemd1.Unit", "ActiveState").await?.try_into().ok()?;
        let r: String = unit_prop(c, "kubelet.service", "org.freedesktop.systemd1.Service", "Result").await?.try_into().ok()?;
        let n: u32 = unit_prop(c, "kubelet.service", "org.freedesktop.systemd1.Service", "NRestarts").await?.try_into().ok()?;
        Some((a, r, n))
    }
    .await;
    match st {
        Some((a, r, n)) => match kubelet_crashloop(&a, &r, n, joined) {
            Some(d) => check(N, CheckStatus::Fail, d),
            None => check(N, CheckStatus::Pass, format!("not crash-looping: ActiveState={a} Result={r} NRestarts={n}")),
        },
        None => check(N, CheckStatus::Pending, "kubelet.service state not readable over D-Bus"),
    }
}

/// gpu (pure over a root directory, for tests): every NVIDIA display/3D controller on PCI is driven by the loaded
/// nvidia module. No NVIDIA on PCI = Skipped (never Fail). Module missing: Pending until the driver had its chance
/// (`settled`: foil-nvidia-cdi finished, it runs nvidia-modprobe), then Fail - a hard failure of the gate.
pub fn gpu_status(root: &Path, settled: bool) -> (CheckStatus, String) {
    let nvidia_pci = fs::read_dir(root.join("sys/bus/pci/devices"))
        .map(|rd| {
            rd.flatten()
                .filter(|e| read_trim(e.path().join("vendor")) == "0x10de" && read_trim(e.path().join("class")).starts_with("0x03"))
                .count()
        })
        .unwrap_or(0);
    if nvidia_pci == 0 {
        return (CheckStatus::Skipped, "no NVIDIA GPU on PCI".into());
    }
    if !root.join("sys/module/nvidia").exists() {
        let st = if settled { CheckStatus::Fail } else { CheckStatus::Pending };
        return (st, format!("{nvidia_pci} NVIDIA GPU, module nvidia not loaded"));
    }
    let seen = fs::read_dir(root.join("proc/driver/nvidia/gpus")).map(|r| r.count()).unwrap_or(0);
    let st = if seen == nvidia_pci { CheckStatus::Pass } else { CheckStatus::Fail };
    (st, format!("{seen}/{nvidia_pci} GPU visible to the driver"))
}

/// CDI spec foil-nvidia-cdi writes for containerd (a tmpfs: generated on every boot).
pub const NVIDIA_CDI_SPEC: &str = "var/run/cdi/nvidia.yaml";
/// The CDI generator: only images with the NVIDIA userspace carry it.
pub const CDI_UNIT: &str = "foil-nvidia-cdi.service";

/// What the gpu check knows about the CDI generator: not expected (not k8s-worker), absent from the image
/// (LoadState=not-found), or the state of the unit (a masked unit counts as skipped: no spec will be written).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cdi {
    NotExpected,
    Absent,
    Unit(CheckStatus),
}

/// The CDI generator on k8s-worker (pure, for tests) from systemd's LoadState of the unit (None = D-Bus did not
/// answer), the unit's state when loaded (None = not readable) and the uptime. Returns the status and detail of the
/// nvidia-cdi check, what the gpu check gets, and `settled` (the driver had its chance, the gpu check may end):
/// - not-found: not applicable, settled at once; masked: skipped (no spec), settled at once
/// - loaded: the unit's state; settled when it is no longer Pending (no time limit of its own: the unit's
///   TimeoutStartSec turns a hung start into failed)
/// - bad-setting, error, anything else: Fail (the unit is there but broken)
/// - not readable over D-Bus: Pending, and from 120 s after boot Fail (an unknown state never ends as green)
pub fn cdi_state(load: Option<&str>, unit: Option<(CheckStatus, String)>, uptime: i64) -> (CheckStatus, String, Cdi, bool) {
    let silent = |what: &str| {
        if uptime >= 120 {
            (CheckStatus::Fail, format!("{CDI_UNIT}: {what} not readable over D-Bus for {uptime} s"), Cdi::Unit(CheckStatus::Fail), true)
        } else {
            (CheckStatus::Pending, format!("{CDI_UNIT}: {what} not readable over D-Bus"), Cdi::Unit(CheckStatus::Pending), false)
        }
    };
    match load {
        None => silent("LoadState"),
        Some("not-found") => (CheckStatus::Skipped, format!("{CDI_UNIT}: not in this image (LoadState=not-found)"), Cdi::Absent, true),
        Some("masked") => (CheckStatus::Skipped, format!("{CDI_UNIT}: masked (LoadState=masked)"), Cdi::Unit(CheckStatus::Skipped), true),
        Some("loaded") => match unit {
            Some((st, d)) => (st, d, Cdi::Unit(st), st != CheckStatus::Pending),
            None => silent("state"),
        },
        Some(s) => (CheckStatus::Fail, format!("{CDI_UNIT}: LoadState={s}"), Cdi::Unit(CheckStatus::Fail), true),
    }
}

/// gpu on k8s-worker (pure, for tests): the GPUs are usable by pods only through the CDI spec. A GPU driven by the
/// module (Pass) while the image has no CDI unit, the unit was skipped or masked, or it finished without the spec is a
/// Fail: kubelet would offer no GPU to the pods. Every other gpu result is kept: a pending or failed unit is reported by
/// the nvidia-cdi check itself, and without a driven GPU (cp, a machine without GPU) no CDI is needed.
pub fn gpu_cdi_status(root: &Path, gpu: (CheckStatus, String), cdi: Cdi) -> (CheckStatus, String) {
    let (st, d) = gpu;
    match (st, cdi) {
        (CheckStatus::Pass, Cdi::Absent) => (CheckStatus::Fail, format!("{d}, but the image has no CDI unit ({CDI_UNIT} not-found): no CDI spec for containerd")),
        (CheckStatus::Pass, Cdi::Unit(CheckStatus::Skipped)) => (CheckStatus::Fail, format!("{d}, but {CDI_UNIT} was skipped: no CDI spec for containerd")),
        (CheckStatus::Pass, Cdi::Unit(CheckStatus::Pass)) if !root.join(NVIDIA_CDI_SPEC).exists() => (CheckStatus::Fail, format!("{d}, but /{NVIDIA_CDI_SPEC} is missing")),
        _ => (st, d),
    }
}

fn check_gpu(settled: bool, cdi: Cdi) -> HealthCheck {
    let root = Path::new("/");
    let (st, d) = gpu_cdi_status(root, gpu_status(root, settled), cdi);
    check("gpu", st, d)
}

pub async fn health(profile: Profile) -> Vec<HealthCheck> {
    health_in(profile, Path::new("/run/foilbird")).await
}

/// Name the local kube-apiserver is checked against. kubeadm always puts the DNS name `kubernetes` into the
/// apiserver certificate (with kubernetes.default, the service IP and the advertise address), but 127.0.0.1 only
/// when the operator lists it in certSANs: the probe connects to 127.0.0.1 and verifies this name.
pub const APISERVER_NAME: &str = "kubernetes";

/// GET https://`addr`/livez?verbose against the cluster CA `ca_pem`, the server certificate verified for
/// [`APISERVER_NAME`] whatever `addr` is. None: no connection, TLS failure (unknown CA, wrong name) or no response.
pub async fn apiserver_livez(addr: &str, ca_pem: &[u8]) -> Option<(u16, String)> {
    use http_body_util::BodyExt;
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem).flatten() {
        roots.add(c).ok()?;
    }
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(APISERVER_NAME).ok()?;
    let conn = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .with_server_name_resolver(hyper_rustls::FixedServerNameResolver::new(name))
        .enable_http1()
        .build();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(conn);
    let req = hyper::Request::get(format!("https://{addr}/livez?verbose")).body(http_body_util::Empty::<bytes::Bytes>::new()).ok()?;
    let resp = client.request(req).await.ok()?;
    let st = resp.status().as_u16();
    let body = resp.into_body().collect().await.ok()?.to_bytes();
    Some((st, String::from_utf8_lossy(&body).into_owned()))
}

/// apiserver check from a livez result (pure, for tests).
pub fn apiserver_status(r: Option<(u16, String)>) -> (CheckStatus, String) {
    match r {
        Some((200, b)) => (CheckStatus::Pass, format!("livez ok ({} checks{})", b.lines().filter(|l| l.starts_with("[+]")).count(), if b.contains("[+]etcd ok") { ", etcd ok" } else { "" })),
        Some((st, b)) => {
            let bad: Vec<&str> = b.lines().filter(|l| l.starts_with("[-]")).collect();
            (CheckStatus::Warn, format!("livez HTTP {st}: {}", bad.join(" ")))
        }
        None => (CheckStatus::Warn, format!("https://127.0.0.1:6443/livez not reachable or not verified as {APISERVER_NAME}")),
    }
}

/// apiserver (control plane v0 only, never gating): `/livez?verbose` of the local kube-apiserver over TLS against the
/// cluster CA; its verbose body includes the etcd check. WARN when not live, Skipped on a worker.
async fn check_apiserver(run_dir: &Path) -> HealthCheck {
    const N: &str = "apiserver";
    if !run_dir.join("config/k8s.init").exists() {
        return check(N, CheckStatus::Skipped, "not a control plane");
    }
    let Ok(pem) = fs::read("/etc/kubernetes/pki/ca.crt") else {
        return check(N, CheckStatus::Warn, "no /etc/kubernetes/pki/ca.crt yet (kubeadm init not done)");
    };
    let r = tokio::time::timeout(Duration::from_secs(5), apiserver_livez("127.0.0.1:6443", &pem)).await.ok().flatten();
    let (st, d) = apiserver_status(r);
    check(N, st, d)
}

pub async fn health_in(profile: Profile, run_dir: &Path) -> Vec<HealthCheck> {
    let mi = mountinfo();
    let conn = zbus::Connection::system().await.ok();
    let k8s = profile == Profile::K8s;
    let kubelet = check_kubelet(profile).await;
    // required units: the agent and its configuration; on k8s-worker also containerd and the CDI generator
    let mut units = vec![check_agent_api(check_unit(conn.as_ref(), "agent", "foil-agent.service").await).await, check_unit(conn.as_ref(), "foil-config", "foil-config.service").await];
    // the driver had its chance: on k8s-worker by the CDI unit (cdi_state: finished, absent, masked, broken, or D-Bus
    // silent for 120 s); elsewhere 2 minutes after boot
    let (cdi, settled) = if k8s {
        let load = match conn.as_ref() {
            Some(c) => unit_load_state(c, CDI_UNIT).await,
            None => None,
        };
        let unit = if load.as_deref() == Some("loaded") { unit_state(conn.as_ref(), CDI_UNIT).await } else { None };
        let (st, d, cdi, settled) = cdi_state(load.as_deref(), unit, uptime_seconds());
        units.push(check_unit(conn.as_ref(), "containerd", "containerd.service").await);
        units.push(check("nvidia-cdi", st, d));
        (cdi, settled)
    } else {
        (Cdi::NotExpected, uptime_seconds() >= 120)
    };
    let mut v = vec![check_usr_verity(&mi), check_var(&mi).await, check_var_slots(Path::new(VAR_SLOTS_REPORT)), check_esp()];
    v.extend(units);
    v.extend([
        check_network_config(conn.as_ref(), Path::new("/run/systemd/network")).await,
        check_default_route(),
        check_time(profile, run_dir).await,
        check_failed_units().await,
        kubelet.clone(),
        check_kubelet_crashloop(profile, kubelet.status == CheckStatus::Pass as i32).await,
        check_gpu(settled, cdi),
        check_apiserver(run_dir).await,
    ]);
    v
}

pub fn overall(checks: &[HealthCheck]) -> CheckStatus {
    let st = |s| checks.iter().any(|c| c.status == s as i32);
    if st(CheckStatus::Fail) {
        CheckStatus::Fail
    } else if st(CheckStatus::Pending) {
        CheckStatus::Pending
    } else if st(CheckStatus::Warn) {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a4_network_config() {
        use std::net::IpAddr;
        let f = parse_net_match("50-foil-0.network", "[Match]\nMACAddress=52:54:00:AA:BB:01\n\n[Network]\nAddress=192.0.2.15/24\nConfigureWithoutCarrier=yes\n");
        assert_eq!(f.mac.as_deref(), Some("52:54:00:aa:bb:01"));
        assert_eq!(f.addresses, vec!["192.0.2.15".parse::<IpAddr>().unwrap()]);
        assert!(!f.dhcp);
        let ip: Vec<IpAddr> = vec!["192.0.2.15".parse().unwrap()];
        let l = |n: &str, mac: &str, admin: Option<&str>, carrier: bool, addr: bool| LinkInfo {
            name: n.into(),
            mac: mac.into(),
            arphrd: 1,
            up: carrier,
            addr,
            admin: admin.map(String::from),
            carrier,
        };
        let m = "52:54:00:aa:bb:01";
        let lo = l("lo", "00:00:00:00:00:00", Some("unmanaged"), true, true);
        let st = |files: &[NetMatch], links: &[LinkInfo], host: &[IpAddr]| network_config_status(files, links, host).0;
        assert_eq!(st(&[], &[lo.clone()], &ip), CheckStatus::Skipped);
        assert_eq!(st(&[f.clone()], &[lo.clone()], &ip), CheckStatus::Pending, "no matching link");
        // networkd not done yet / not readable
        for a in [None, Some("pending"), Some("initialized"), Some("unmanaged")] {
            assert_eq!(st(&[f.clone()], &[l("ens3", m, a, true, true)], &ip), CheckStatus::Pending, "{a:?}");
        }
        // networkd failed to apply the config: a real failure
        for a in ["failed", "linger"] {
            let (s, d) = network_config_status(&[f.clone()], &[l("ens3", m, Some(a), true, true)], &ip);
            assert_eq!(s, CheckStatus::Fail);
            assert!(d.contains(a), "{d}");
        }
        // static address missing on the host -> pending, even when configured
        assert_eq!(st(&[f.clone()], &[l("ens3", m, Some("configured"), true, true)], &[]), CheckStatus::Pending);
        assert_eq!(st(&[f.clone()], &[l("ens3", m, Some("configured"), true, true)], &ip), CheckStatus::Pass);
        // no carrier (cable out) with the static address kept -> WARN, not gating
        let (s, d) = network_config_status(&[f.clone()], &[l("ens3", m, Some("configuring"), false, true)], &ip);
        assert_eq!(s, CheckStatus::Warn);
        assert!(d.contains("no carrier"), "{d}");
        // DHCP: no lease (DHCP server down) -> WARN; a default route is not needed
        let g = parse_net_match("50-foil-0.network", "[Match]\nType=ether\nKind=!*\n[Network]\nDHCP=ipv4\n");
        assert!(g.ether && g.mac.is_none() && g.dhcp && g.addresses.is_empty());
        let (s, d) = network_config_status(&[g.clone()], &[lo.clone(), l("enp1s0", "x", Some("configuring"), true, false)], &[]);
        assert_eq!(s, CheckStatus::Warn);
        assert!(d.contains("no DHCP address"), "{d}");
        assert_eq!(st(&[g.clone()], &[lo, l("enp1s0", "x", Some("configured"), true, true)], &[]), CheckStatus::Pass);
        let n = parse_net_match("50-foil-0.network", "[Match]\nName=en* eth0\n");
        assert_eq!(st(&[n.clone()], &[l("enp1s0", "x", Some("configured"), true, true)], &[]), CheckStatus::Pass);
        assert_eq!(st(&[n.clone()], &[l("wlan0", "x", Some("configured"), true, true)], &[]), CheckStatus::Pending);
        // two candidates: one applied is enough
        assert_eq!(st(&[n], &[l("en0", "x", Some("failed"), true, true), l("en1", "y", Some("configured"), true, true)], &[]), CheckStatus::Pass);
        // [Address] section and IPv6
        let v6 = parse_net_match("50-foil-1.network", "[Match]\nName=e*\n[Address]\nAddress=fd00::5/64\n");
        assert_eq!(v6.addresses, vec!["fd00::5".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn tries_left_from_names() {
        let d = std::env::temp_dir().join(format!("foil-tries-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        for n in ["foilbird_2+2-1.efi", "foilbird_1.efi", "foilbird_3+3.efi"] {
            fs::write(d.join(n), b"").unwrap();
        }
        assert_eq!(tries_left_in(&d, "foilbird_2.efi"), 2);
        assert_eq!(tries_left_in(&d, "foilbird_1.efi"), -1);
        assert_eq!(tries_left_in(&d, "foilbird_3.efi"), 3);
        assert_eq!(tries_left_in(&d.join("missing"), "foilbird_2.efi"), -1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tries_cache_per_mount() {
        let c = |mount: Option<&str>| TriesCache { entry: "foilbird_2.efi".into(), left: 2, at: Instant::now(), mount: mount.map(str::to_string) };
        let s = Duration::from_secs;
        // at rest: the cached value until 10 min, no access
        assert!(tries_cache_hit(&c(Some("90")), s(30), "foilbird_2.efi", None));
        assert!(!tries_cache_hit(&c(Some("90")), s(601), "foilbird_2.efi", None));
        // still the mount instance it was read from: no access, so the idle timeout runs out
        assert!(tries_cache_hit(&c(Some("90")), s(30), "foilbird_2.efi", Some("90")));
        // a new mount instance (bless, sysupdate, foil-rollback@ mounted it) or a read at rest that did not mount: read again
        assert!(!tries_cache_hit(&c(Some("90")), s(30), "foilbird_2.efi", Some("97")));
        assert!(!tries_cache_hit(&c(None), s(30), "foilbird_2.efi", Some("97")));
        // another entry
        assert!(!tries_cache_hit(&c(Some("90")), s(30), "foilbird_3.efi", None));
        let mi = parse_mountinfo(
            "40 1 0:40 / /boot rw,relatime shared:20 - autofs systemd-1 rw,fd=50\n97 40 253:1 / /boot rw,relatime shared:50 - vfat /dev/vda1 rw",
        );
        assert_eq!(esp_mount_id(&mi).as_deref(), Some("97"));
        assert_eq!(esp_mount_id(&mi[..1]), None);
    }

    #[test]
    fn esp_writable() {
        use CheckStatus::*;
        let mi = |lines: &[&str]| parse_mountinfo(&lines.join("\n"));
        let auto = "40 1 0:40 / /boot rw,relatime shared:20 - autofs systemd-1 rw,fd=50,pgrp=1,timeout=60,minproto=5,maxproto=5,direct";
        let rw = "90 40 253:1 / /boot rw,nosuid,nodev,noexec,relatime shared:50 - vfat /dev/vda1 rw,fmask=0077,dmask=0077,errors=remount-ro";
        let sb_ro = "90 40 253:1 / /boot rw,nosuid,nodev,noexec,relatime shared:50 - vfat /dev/vda1 ro,fmask=0077,dmask=0077,errors=remount-ro";
        let mnt_ro = "90 40 253:1 / /boot ro,nosuid,nodev,noexec,relatime shared:50 - vfat /dev/vda1 rw,fmask=0077";
        let other = "30 1 253:2 / /var rw,relatime - ext4 /dev/mapper/var rw";
        assert_eq!(parse_mountinfo(rw)[0], MountEntry { id: "90".into(), point: "/boot".into(), opts: "rw,nosuid,nodev,noexec,relatime".into(), fstype: "vfat".into(), source: "/dev/vda1".into(), super_opts: "rw,fmask=0077,dmask=0077,errors=remount-ro".into() });
        // automount triggered, vfat on top of autofs, read-write
        let (s, d) = esp_status(&mi(&[other, auto, rw]), "/boot", None, true);
        assert_eq!((s, d.contains("/dev/vda1 vfat")), (Pass, true), "{d}");
        // FAT remounted read-only by the kernel (super block ro) -> CRITICAL
        let (s, d) = esp_status(&mi(&[auto, sb_ro]), "/boot", None, true);
        assert_eq!((s, d.starts_with("CRITICAL: ESP /dev/vda1 at /boot is read-only (ro,")), (Fail, true), "{d}");
        assert!(d.ends_with("reboot the node (fsck runs before the first mount)"), "{d}");
        // ro only per mount: the agent's own ProtectSystem=strict namespace, not the ESP
        assert_eq!(esp_status(&mi(&[auto, mnt_ro]), "/boot", None, true).0, Pass);
        // automount that did not mount (access failed) -> CRITICAL with the error
        let (s, d) = esp_status(&mi(&[auto]), "/boot", Some("No such device (os error 19)"), true);
        assert_eq!((s, d.contains("automount did not mount it") && d.contains("os error 19")), (Fail, true), "{d}");
        // no automount and nothing mounted although the loader booted from an ESP -> CRITICAL; no ESP at all -> Skipped
        assert_eq!(esp_status(&mi(&[other]), "/boot", None, true).0, Fail);
        assert_eq!(esp_status(&mi(&[other]), "/boot", None, false).0, Skipped);
    }

    #[test]
    fn var_slots_report() {
        use CheckStatus::*;
        let st = |t: &str| var_slots_status(Some(t));
        assert_eq!(var_slots_status(None).0, Skipped);
        let clean = "schema=1\nop=sync-booted\ntime_unix=1794800000\nunknown_tpm2_slots=\nwiped_unknown_slots=\ntokenless_slots=\ninterrupted_enroll_removed=\norphan_tokens_removed=6\n";
        let (s, d) = st(clean);
        assert_eq!(s, Pass);
        assert!(d.contains("orphan_tokens_removed=6") && d.contains("sync-booted"), "{d}");
        // unknown TPM2 slot and a tokenless slot -> CRITICAL, both named
        let (s, d) = st("schema=1\nop=sync-booted\nunknown_tpm2_slots=3,4\ntokenless_slots=2\n");
        assert_eq!(s, Fail);
        assert!(d.starts_with("CRITICAL: unknown LUKS key slot 3, 4 (TPM2") && d.contains("unknown LUKS key slot 2 (no token)"), "{d}");
        // epoch keys (same schema), "token N" vs "key slot N"
        for (k, want) in [
            ("foreign_tokens=3", "foreign LUKS token 3"),
            ("foreign_token_slots=5", "unknown LUKS key slot 5 (token of another type)"),
            ("tpm2_bad_tokens=0", "LUKS token 0 (systemd-tpm2 without"),
            ("duplicate_epoch_tokens=4", "LUKS token 4 (second"),
            ("epoch_keys_suspect=99", "epoch key file for epoch 99"),
        ] {
            let (s, d) = st(&format!("schema=1\n{k}\n"));
            assert_eq!((s, d.contains(want)), (Fail, true), "{k}: {d}");
        }
        // info only
        assert_eq!(st("schema=1\nwiped_extra_slots=5\nremoved_tokens=4\n").0, Pass);
        // unknown keys ignored; other schema or garbage -> WARN, nothing claimed
        assert_eq!(st("schema=1\nnew_key_from_m1=7\n").0, Pass);
        assert_eq!(st("schema=2\nunknown_tpm2_slots=3\n").0, Warn);
        assert_eq!(st("op=x\n").0, Warn);
        assert_eq!(st("schema=1\nunknown_tpm2_slots=3,x\n").0, Warn);
        // op is reduced to a safe character set
        assert!(!st("schema=1\nop=a\u{1b}[31mb\n").1.contains('\u{1b}'));
    }

    #[test]
    fn host_addresses_from_proc() {
        let fib = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\nLocal:\n  +-- 192.0.2.0/24 2 0 2\n     |-- 192.0.2.0\n        /32 link BROADCAST\n        /24 link UNICAST\n     |-- 192.0.2.50\n        /32 host LOCAL\n  |-- 127.0.0.1\n     /32 host LOCAL\n";
        let v6 = "fd000000000000000000000000000005 02 40 00 80 ens3\nfe80000000000000505400fffe123456 02 40 20 80 ens3\n";
        let h = host_addresses(fib, v6);
        let has = |a: &str| h.contains(&a.parse().unwrap());
        assert!(has("192.0.2.50") && has("127.0.0.1") && has("fd00::5"));
        assert!(!has("192.0.2.0") && !has("0.0.0.0"));
    }

    #[test]
    fn a4_unit_status() {
        assert_eq!(unit_status("active", Some(true), None), CheckStatus::Pass);
        assert_eq!(unit_status("failed", Some(true), None), CheckStatus::Fail);
        // skipped only by a condition evaluated in this boot
        assert_eq!(unit_status("inactive", Some(false), None), CheckStatus::Skipped);
        assert_eq!(unit_status("inactive", None, None), CheckStatus::Pending);
        // condition met, no job yet (the queue, or the unit is in no target): waiting, not skipped
        assert_eq!(unit_status("inactive", Some(true), None), CheckStatus::Pending);
        assert_eq!(unit_status("activating", None, None), CheckStatus::Pending);
        // an assertion that failed is a failure, whatever the active state
        assert_eq!(unit_status("inactive", Some(true), Some(false)), CheckStatus::Fail);
    }

    #[test]
    fn a4_gpu_fail_fast() {
        let root = std::env::temp_dir().join(format!("foil-gpu-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dev = |id: &str, vendor: &str, class: &str| {
            let d = root.join("sys/bus/pci/devices").join(id);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("vendor"), format!("{vendor}\n")).unwrap();
            fs::write(d.join("class"), format!("{class}\n")).unwrap();
        };
        // no NVIDIA on PCI (virtio GPU, NVIDIA audio function): never Fail, settled or not
        dev("0000:00:01.0", "0x1af4", "0x030000");
        dev("0000:00:02.1", "0x10de", "0x040300");
        assert_eq!(gpu_status(&root, false).0, CheckStatus::Skipped);
        assert_eq!(gpu_status(&root, true).0, CheckStatus::Skipped);
        // NVIDIA 3D controller, module not loaded: wait while the driver may still load, then hard Fail
        dev("0000:01:00.0", "0x10de", "0x030200");
        assert_eq!(gpu_status(&root, false).0, CheckStatus::Pending);
        let (st, d) = gpu_status(&root, true);
        assert_eq!(st, CheckStatus::Fail);
        assert!(d.contains("module nvidia not loaded"), "{d}");
        // module loaded, GPU not seen by the driver / seen
        fs::create_dir_all(root.join("sys/module/nvidia")).unwrap();
        assert_eq!(gpu_status(&root, true).0, CheckStatus::Fail);
        fs::create_dir_all(root.join("proc/driver/nvidia/gpus/0000:01:00.0")).unwrap();
        assert_eq!(gpu_status(&root, true).0, CheckStatus::Pass);

        // k8s-worker: GPU driven, but the CDI unit skipped or the spec missing -> Fail (pods get no GPU)
        let gpu = || gpu_status(&root, true);
        let (st, d) = gpu_cdi_status(&root, gpu(), Cdi::Unit(CheckStatus::Skipped));
        assert_eq!(st, CheckStatus::Fail);
        assert!(d.contains("foil-nvidia-cdi.service was skipped"), "{d}");
        let (st, d) = gpu_cdi_status(&root, gpu(), Cdi::Unit(CheckStatus::Pass));
        assert_eq!(st, CheckStatus::Fail);
        assert!(d.contains("/var/run/cdi/nvidia.yaml is missing"), "{d}");
        fs::create_dir_all(root.join("var/run/cdi")).unwrap();
        fs::write(root.join(NVIDIA_CDI_SPEC), "cdiVersion: 0.5.0\n").unwrap();
        assert_eq!(gpu_cdi_status(&root, gpu(), Cdi::Unit(CheckStatus::Pass)).0, CheckStatus::Pass);
        // a skipped unit stays Fail even with a spec file present
        assert_eq!(gpu_cdi_status(&root, gpu(), Cdi::Unit(CheckStatus::Skipped)).0, CheckStatus::Fail);
        // unit pending or failed: gpu unchanged (the nvidia-cdi check reports it); off k8s-worker: no CDI expected
        assert_eq!(gpu_cdi_status(&root, gpu(), Cdi::Unit(CheckStatus::Pending)).0, CheckStatus::Pass);
        assert_eq!(gpu_cdi_status(&root, gpu(), Cdi::Unit(CheckStatus::Fail)).0, CheckStatus::Pass);
        fs::remove_file(root.join(NVIDIA_CDI_SPEC)).unwrap();
        assert_eq!(gpu_cdi_status(&root, gpu(), Cdi::NotExpected).0, CheckStatus::Pass);
        // no NVIDIA GPU (QEMU): Skipped stays Skipped with the CDI unit skipped
        let none = (CheckStatus::Skipped, "no NVIDIA GPU on PCI".to_string());
        assert_eq!(gpu_cdi_status(&root, none, Cdi::Unit(CheckStatus::Skipped)).0, CheckStatus::Skipped);
        fs::remove_dir_all(&root).unwrap();
    }

    /// nvidia-cdi expected only where systemd loads the unit (LoadState over D-Bus), never Pending for good.
    #[test]
    fn cdi_optional() {
        use CheckStatus::*;
        let root = Path::new("/nonexistent-foil-cdi-test");
        let no_gpu = || (Skipped, "no NVIDIA GPU on PCI".to_string());
        let gpu = || (Pass, "1/1 GPU visible to the driver".to_string());
        // 1 cp, no unit in the image: not applicable, settled at once (uptime 0), gpu stays Skipped
        let (st, d, cdi, settled) = cdi_state(Some("not-found"), None, 0);
        assert_eq!((st, cdi, settled), (Skipped, Cdi::Absent, true));
        assert!(d.contains("not in this image"), "{d}");
        assert_eq!(gpu_cdi_status(root, no_gpu(), cdi).0, Skipped);
        // 2 gpu image with a GPU: the unit active
        let u = (unit_status("active", Some(true), None), "foil-nvidia-cdi.service: ActiveState=active Result=success".to_string());
        assert_eq!(cdi_state(Some("loaded"), Some(u), 0).2, Cdi::Unit(Pass));
        let (st, _, cdi, settled) = cdi_state(Some("loaded"), Some((Pass, String::new())), 0);
        assert_eq!((st, cdi, settled), (Pass, Cdi::Unit(Pass), true));
        // 3 gpu image on a machine without a GPU: skipped by its condition -> settled, neither Pending nor Fail
        let u = (unit_status("inactive", Some(false), None), "foil-nvidia-cdi.service: ActiveState=inactive Result=success ConditionResult=no".to_string());
        let (st, _, cdi, settled) = cdi_state(Some("loaded"), Some(u), 0);
        assert_eq!((st, cdi, settled), (Skipped, Cdi::Unit(Skipped), true));
        assert_eq!(gpu_cdi_status(root, no_gpu(), cdi).0, Skipped);
        // 4 a driven GPU, but no CDI unit in the image -> Fail, not a silent Pass
        let (_, _, cdi, _) = cdi_state(Some("not-found"), None, 0);
        let (st, d) = gpu_cdi_status(root, gpu(), cdi);
        assert_eq!(st, Fail);
        assert!(d.contains("the image has no CDI unit"), "{d}");
        // 5 masked: skipped for gpu - with a driven GPU Fail, without a GPU Skipped
        let (st, d, cdi, settled) = cdi_state(Some("masked"), None, 0);
        assert_eq!((st, cdi, settled), (Skipped, Cdi::Unit(Skipped), true));
        assert!(d.contains("masked"), "{d}");
        assert_eq!(gpu_cdi_status(root, gpu(), cdi).0, Fail);
        assert_eq!(gpu_cdi_status(root, no_gpu(), cdi).0, Skipped);
        // 6 loaded, its condition met, no job yet: Pending (not Skipped), and time does not settle it
        let u = (unit_status("inactive", Some(true), None), "foil-nvidia-cdi.service: ActiveState=inactive Result=success".to_string());
        assert_eq!(u.0, Pending);
        let (st, _, cdi, settled) = cdi_state(Some("loaded"), Some(u), 600);
        assert_eq!((st, cdi, settled), (Pending, Cdi::Unit(Pending), false));
        // D-Bus silent: Pending before 120 s, Fail "not readable" from 120 s (settled) - never a quiet green
        let (st, _, _, settled) = cdi_state(None, None, 119);
        assert_eq!((st, settled), (Pending, false));
        let (st, d, cdi, settled) = cdi_state(None, None, 120);
        assert_eq!((st, cdi, settled), (Fail, Cdi::Unit(Fail), true));
        assert!(d.contains("not readable over D-Bus"), "{d}");
        // loaded but its properties not readable: the same rule
        assert_eq!(cdi_state(Some("loaded"), None, 119).0, Pending);
        assert_eq!(cdi_state(Some("loaded"), None, 120).0, Fail);
        // a broken unit
        assert_eq!(cdi_state(Some("bad-setting"), None, 0).0, Fail);
        assert_eq!(cdi_state(Some("error"), None, 0).0, Fail);
        // off k8s-worker nothing changes
        assert_eq!(gpu_cdi_status(root, gpu(), Cdi::NotExpected).0, Pass);
    }

    #[test]
    fn time_policy() {
        use super::*;
        let s = "ntp system=[192.0.2.123] link=[] current=-";
        assert_eq!(time_check(true, true, None, s).0, CheckStatus::Pass);
        assert_eq!(time_check(true, false, Some("timeout 120s"), s).0, CheckStatus::Pass);
        assert_eq!(time_check(false, true, None, s).0, CheckStatus::Pending);
        let (st, d) = time_check(false, true, Some("timeout 120s"), s);
        assert_eq!(st, CheckStatus::Fail);
        assert!(d.contains("first join blocked") && d.contains("192.0.2.123"), "{d}");
        assert_eq!(time_check(false, false, None, s).0, CheckStatus::Warn);
        assert_eq!(time_check(false, false, Some("timeout 120s"), s).0, CheckStatus::Warn);
    }

    use super::*;

    #[test]
    fn var_protection_kinds() {
        let mi = vec![("253:1".to_string(), "/var".to_string(), "/dev/mapper/var".to_string())];
        assert_eq!(var_protection_from(&mi, |_| Some("CRYPT-LUKS2-0123-var".into())), VarProtection::Luks2Tpm2);
        assert_eq!(var_protection_from(&mi, |_| Some("CRYPT-VERITY-x".into())), VarProtection::Other);
        assert_eq!(var_protection_from(&mi, |_| None), VarProtection::None);
        assert_eq!(var_protection_from(&[], |_| None), VarProtection::Unspecified);
    }

    #[test]
    fn kubelet_crashloop_decision() {
        // not joined: never fails (kubelet restarts until kubeadm join writes its config)
        assert_eq!(kubelet_crashloop("failed", "start-limit-hit", 9, false), None);
        assert_eq!(kubelet_crashloop("activating", "exit-code", 5, false), None);
        // joined, healthy start / short restarts
        assert_eq!(kubelet_crashloop("active", "success", 0, true), None);
        assert_eq!(kubelet_crashloop("activating", "exit-code", KUBELET_MAX_RESTARTS - 1, true), None);
        // joined, crash loop / failed / start limit
        assert!(kubelet_crashloop("activating", "exit-code", KUBELET_MAX_RESTARTS, true).unwrap().contains("NRestarts=3"));
        assert!(kubelet_crashloop("failed", "exit-code", 0, true).is_some());
        assert!(kubelet_crashloop("failed", "start-limit-hit", 1, true).unwrap().contains("start-limit-hit"));
    }

    #[test]
    fn joined_before_this_boot() {
        // first boot with a join: kubelet.conf written after the boot started -> not joined before, so even
        // NRestarts=9 (restarts before the join) never fails
        let boot = 1_800_000_000;
        let skipped = Some((false, 5_000_000)); // join unit evaluated, condition failed: kubelet.conf existed
        let ran = Some((true, 5_000_000)); // join unit ran in this boot
        assert!(!joined_before_boot(Some(boot + 40), Some(boot), ran));
        assert_eq!(kubelet_crashloop("activating", "exit-code", 9, joined_before_boot(Some(boot + 40), Some(boot), ran)), None);
        // slow RTC fixed by NTP after the join: the file looks older than the boot, the join unit says it ran
        assert!(!joined_before_boot(Some(boot - 3600), Some(boot), ran));
        assert_eq!(kubelet_crashloop("activating", "exit-code", 9, joined_before_boot(Some(boot - 3600), Some(boot), ran)), None);
        // joined in an earlier boot
        assert!(joined_before_boot(Some(boot - 3600), Some(boot), skipped));
        // unknown: no fail-fast
        assert!(!joined_before_boot(Some(boot - 3600), Some(boot), Some((false, 0)))); // join unit not evaluated yet
        assert!(!joined_before_boot(Some(boot - 3600), Some(boot), None));
        assert!(!joined_before_boot(None, Some(boot), skipped));
        assert!(!joined_before_boot(Some(boot - 1), None, skipped));
    }

    #[test]
    fn overall_status() {
        let p = check("a", CheckStatus::Pass, "");
        let s = check("b", CheckStatus::Skipped, "");
        let w = check("c", CheckStatus::Pending, "");
        let f = check("d", CheckStatus::Fail, "");
        assert_eq!(overall(&[p.clone(), s.clone()]), CheckStatus::Pass);
        assert_eq!(overall(&[p.clone(), w.clone()]), CheckStatus::Pending);
        let warn = check("e", CheckStatus::Warn, "");
        assert_eq!(overall(&[p.clone(), warn.clone()]), CheckStatus::Warn);
        assert_eq!(overall(&[warn, w.clone()]), CheckStatus::Pending);
        assert_eq!(overall(&[w, f, p]), CheckStatus::Fail);
    }

    /// One-thread HTTPS server answering every request with a kube-apiserver style livez body; the server certificate
    /// has `sans` and is signed by a CA whose PEM is returned.
    fn livez_server(sans: &[&str]) -> (String, String) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::io::{Read, Write};
        let mut cp = CertificateParams::new(vec![]).unwrap();
        cp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ck = KeyPair::generate().unwrap();
        let ca = cp.self_signed(&ck).unwrap();
        let issuer = Issuer::new(cp, ck);
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap().signed_by(&key, &issuer).unwrap();
        let cfg = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![CertificateDer::from(cert.der().to_vec())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
                .unwrap(),
        );
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut t = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg.clone()).unwrap(), s);
                let mut buf = [0u8; 4096];
                if t.read(&mut buf).is_err() {
                    continue; // handshake refused by the client (unknown CA, wrong name)
                }
                let body = "[+]ping ok\n[+]log ok\n[+]etcd ok\nlivez check passed\n";
                let _ = write!(t, "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                t.conn.send_close_notify();
                let _ = t.flush();
            }
        });
        (addr, ca.pem())
    }

    /// kubeadm's default apiserver certificate has no 127.0.0.1 (only with certSANs); the probe connects to
    /// 127.0.0.1 and verifies the name `kubernetes`, so the check passes without certSANs.
    #[tokio::test]
    async fn r6_apiserver_livez_verifies_name_kubernetes() {
        // kubeadm default SANs (no 127.0.0.1)
        let (addr, ca) = livez_server(&["cp-1", "kubernetes", "kubernetes.default", "kubernetes.default.svc", "198.51.100.1", "192.0.2.10"]);
        let (st, d) = apiserver_status(apiserver_livez(&addr, ca.as_bytes()).await);
        assert_eq!((st, d.as_str()), (CheckStatus::Pass, "livez ok (3 checks, etcd ok)"));
        // a certificate for 127.0.0.1 only is not the cluster's apiserver name: not verified
        let (addr, ca) = livez_server(&["127.0.0.1"]);
        assert_eq!(apiserver_livez(&addr, ca.as_bytes()).await, None);
        // right name, foreign CA: not verified
        let (addr, _) = livez_server(&["kubernetes"]);
        let (_, other_ca) = livez_server(&["kubernetes"]);
        let r = apiserver_livez(&addr, other_ca.as_bytes()).await;
        assert_eq!(r, None);
        assert_eq!(apiserver_status(r).0, CheckStatus::Warn);
        // not live
        assert_eq!(apiserver_status(Some((500, "[+]ping ok\n[-]etcd failed: reason withheld\n".into()))), (CheckStatus::Warn, "livez HTTP 500: [-]etcd failed: reason withheld".into()));
    }
}
