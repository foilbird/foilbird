// SPDX-License-Identifier: Apache-2.0
//! Rollback detection: a boot that did not start the expected release is reported as rolled back, with its reason.
//!
//! `Reboot` into a staged release records the expected version in
//! `/var/lib/foil-agent/pending-boot`. At start the agent compares it with the
//! booted version: if another version is running, systemd-boot fell back.
//! The reason comes from the ESP (`<id>_<ver>+0-N.efi`: tries exhausted), the
//! failed gate checks from the journal of the boots in between. The record is
//! kept in `last-rollback` until the node runs another version. A pending
//! boot is cleared once that version is confirmed.
//!
//! The `Rollback` RPC (operator rollback of a committed release) records
//! `operator-rollback` before the reboot; at the next start the agent reports
//! it with reason OPERATOR if the node runs the expected previous release.

use crate::config::{Paths, write_atomic};
use crate::journal;
use crate::pb::{RollbackInfo, RollbackReason, Version};
use std::collections::HashMap;
use std::path::Path;

const PENDING: &str = "pending-boot";
const LAST: &str = "last-rollback";
const OPERATOR: &str = "operator-rollback";

fn kv(text: &str) -> HashMap<String, String> {
    text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Called by Reboot when a release is staged.
pub fn record_pending(paths: &Paths, version: &str, boot_id: &str, now_unix: u64) -> std::io::Result<()> {
    write_atomic(
        &paths.state_dir.join(PENDING),
        format!("version={}\nboot_id={}\nat={now_unix}\n", one_line(version), one_line(boot_id)).as_bytes(),
        0o600,
    )
}

pub fn pending_version(paths: &Paths) -> Option<String> {
    let m = kv(&std::fs::read_to_string(paths.state_dir.join(PENDING)).ok()?);
    m.get("version").cloned()
}

/// The pending version booted and was confirmed: the update is done.
pub fn confirm(paths: &Paths, booted: &str) {
    if pending_version(paths).as_deref() == Some(booted) {
        let _ = std::fs::remove_file(paths.state_dir.join(PENDING));
        tracing::info!(version = booted, "update confirmed");
    }
}

/// Entry of `version` on the ESP: (tries left, tries done) if it has a counter.
pub fn esp_counter(esp_linux: &Path, image_id: &str, version: &str) -> Option<Option<(u32, u32)>> {
    let prefix = format!("{image_id}_{version}");
    for e in std::fs::read_dir(esp_linux).ok()?.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = n.strip_prefix(&prefix).and_then(|r| r.strip_suffix(".efi")) else { continue };
        if rest.is_empty() {
            return Some(None);
        }
        if let Some(c) = rest.strip_prefix('+') {
            let (l, d) = c.split_once('-').unwrap_or((c, "0"));
            if let (Ok(l), Ok(d)) = (l.parse(), d.parse()) {
                return Some(Some((l, d)));
            }
        }
    }
    None
}

/// Entries of `image_id` on the ESP: (version, counter, path), names
/// `<id>_<v>.efi`, `<id>_<v>+<left>.efi`, `<id>_<v>+<left>-<done>.efi`.
pub fn esp_entries(esp_linux: &Path, image_id: &str) -> Vec<(String, Option<(u32, u32)>, std::path::PathBuf)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(esp_linux) else { return out };
    let prefix = format!("{image_id}_");
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = n.strip_prefix(&prefix).and_then(|r| r.strip_suffix(".efi")) else { continue };
        let (v, counter) = match rest.split_once('+') {
            None => (rest.to_string(), None),
            Some((v, c)) => {
                let (l, d) = c.split_once('-').unwrap_or((c, "0"));
                match (l.parse(), d.parse()) {
                    (Ok(l), Ok(d)) => (v.to_string(), Some((l, d))),
                    _ => continue,
                }
            }
        };
        if crate::update::valid_version(&v) {
            out.push((v, counter, e.path()));
        }
    }
    out
}

/// The release systemd-boot falls back to once `booted` is out of its choice:
/// the newest entry older than `booted` that is not bad (tries left > 0 or no counter).
pub fn previous_release(esp_linux: &Path, image_id: &str, booted: &str) -> Option<(String, std::path::PathBuf)> {
    use std::cmp::Ordering;
    esp_entries(esp_linux, image_id)
        .into_iter()
        .filter(|(v, c, _)| crate::update::vercmp(v, booted) == Ordering::Less && c.is_none_or(|(l, _)| l > 0))
        .max_by(|a, b| crate::update::vercmp(&a.0, &b.0))
        .map(|(v, _, p)| (v, p))
}

/// PE32+ sections of an image: name -> (file offset, size). Structural only.
fn pe_sections(data: &[u8]) -> Result<(HashMap<String, (usize, usize)>, u32), String> {
    let u16_at = |o: usize| data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| data.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if data.get(0..2) != Some(b"MZ") {
        return Err("not a PE image (no MZ)".into());
    }
    let pe = u32_at(0x3c).ok_or("truncated")? as usize;
    if data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE image (no PE signature)".into());
    }
    let nsec = u16_at(pe + 6).ok_or("truncated")? as usize;
    let opt_size = u16_at(pe + 20).ok_or("truncated")? as usize;
    let opt = pe + 24;
    // PE32+ (0x20b): data directories start at 112; entry 4 = certificate table (file offset, size)
    if u16_at(opt) != Some(0x20b) {
        return Err("not a PE32+ image".into());
    }
    let cert_size = u32_at(opt + 112 + 4 * 8 + 4).ok_or("truncated")?;
    let mut sec: HashMap<String, (usize, usize)> = HashMap::new();
    for i in 0..nsec {
        let h = opt + opt_size + 40 * i;
        let raw = data.get(h..h + 8).ok_or("truncated section table")?;
        let name = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
        let vsize = u32_at(h + 8).ok_or("truncated")? as usize;
        let rsize = u32_at(h + 16).ok_or("truncated")? as usize;
        let roff = u32_at(h + 20).ok_or("truncated")? as usize;
        if roff.checked_add(rsize.min(vsize.max(rsize))).is_none_or(|end| end > data.len()) {
            return Err(format!("section {name} beyond the end of the file"));
        }
        sec.entry(name).or_insert((roff, rsize.min(if vsize > 0 { vsize } else { rsize })));
    }
    Ok((sec, cert_size))
}

fn section_text(data: &[u8], sec: &HashMap<String, (usize, usize)>, s: &str) -> Option<String> {
    sec.get(s).map(|(o, n)| String::from_utf8_lossy(&data[*o..*o + *n]).trim_end_matches('\0').to_string())
}

/// `.osrel` of a UKI as key/value pairs (quotes removed). Not a signature check.
pub fn uki_osrel(data: &[u8]) -> Result<HashMap<String, String>, String> {
    let (sec, _) = pe_sections(data)?;
    let t = section_text(data, &sec, ".osrel").ok_or("no .osrel section")?;
    Ok(kv(&t.replace('"', "")))
}

/// `FOILBIRD_PCR_EPOCH` of a UKI (its `.osrel`); None = absent or not a number.
pub fn uki_epoch(data: &[u8]) -> Result<Option<u32>, String> {
    Ok(uki_osrel(data)?.get("FOILBIRD_PCR_EPOCH").and_then(|e| e.trim().parse().ok()))
}

/// Recovery UKI next to the slot UKIs (decision 0003, images/debian/recovery).
pub const RECOVERY_UKI: &str = "foilbird-recovery.efi";

/// ESP layout a Rollback relies on: no good entry of `image_id`
/// newer than `booted` (systemd-boot would boot it, not the previous release;
/// a bad one, no tries left, is sorted last and stays: the release abandoned by
/// an earlier rollback)
/// and a non-empty recovery UKI (the good entry left once the previous release
/// is bad too; without it systemd-boot picks among bad entries, the abandoned one first).
pub fn esp_rollback_layout(esp_linux: &Path, image_id: &str, booted: &str) -> Result<(), String> {
    let mut newer: Vec<String> = esp_entries(esp_linux, image_id)
        .into_iter()
        .filter(|(v, c, _)| crate::update::vercmp(v, booted) == std::cmp::Ordering::Greater && c.is_none_or(|(l, _)| l > 0))
        .filter_map(|(_, _, p)| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    if !newer.is_empty() {
        newer.sort();
        return Err(format!("a newer release than {booted} is on the ESP ({}); systemd-boot would boot it", newer.join(", ")));
    }
    match std::fs::metadata(esp_linux.join(RECOVERY_UKI)) {
        Ok(m) if m.is_file() && m.len() > 0 => Ok(()),
        _ => Err(format!("no recovery UKI ({RECOVERY_UKI}) on the ESP; once the previous release fails it is the only fallback")),
    }
}

/// Structural check of a UKI before relying on it (the firmware checks the
/// signature at boot): a PE image with .linux, .initrd, .osrel and .cmdline,
/// IMAGE_VERSION = `version`, `usrhash=` on the command line and a non-empty
/// certificate table (it is signed).
pub fn check_uki(data: &[u8], version: &str) -> Result<(), String> {
    let (sec, cert_size) = pe_sections(data)?;
    if cert_size == 0 {
        return Err("UKI is not signed (empty certificate table)".into());
    }
    for s in [".linux", ".initrd", ".osrel", ".cmdline"] {
        if !sec.contains_key(s) {
            return Err(format!("no {s} section"));
        }
    }
    let osrel = kv(&section_text(data, &sec, ".osrel").unwrap_or_default().replace('"', ""));
    match osrel.get("IMAGE_VERSION") {
        Some(v) if v == version => {}
        other => return Err(format!("IMAGE_VERSION in .osrel is {other:?}, expected {version}")),
    }
    if !section_text(data, &sec, ".cmdline").unwrap_or_default().split_whitespace().any(|a| a.starts_with("usrhash=")) {
        return Err("no usrhash= on the UKI command line".into());
    }
    Ok(())
}

/// Partitions of `version` (sysupdate.d: usr_<v>, usr-verity_<v>, usr-verity-sig_<v>) missing from /sys/class/block.
pub fn missing_partitions(sys_block: &Path, version: &str) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(sys_block) {
        for e in rd.flatten() {
            if let Ok(u) = std::fs::read_to_string(e.path().join("uevent")) {
                if let Some(n) = kv(&u).get("PARTNAME") {
                    names.push(n.clone());
                }
            }
        }
    }
    ["usr", "usr-verity", "usr-verity-sig"]
        .iter()
        .map(|p| format!("{p}_{version}"))
        .filter(|n| !names.contains(n))
        .collect()
}

/// Called by the Rollback RPC once the image's unit took `from` out of systemd-boot's choice.
pub fn record_operator(paths: &Paths, from: &str, to: &str, boot_id: &str, now_unix: u64, who: &str, reason: &str) -> std::io::Result<()> {
    write_atomic(
        &paths.state_dir.join(OPERATOR),
        format!(
            "from={}\nto={}\nboot_id={}\nat={now_unix}\nwho={}\nreason={}\n",
            one_line(from),
            one_line(to),
            one_line(boot_id),
            one_line(who),
            one_line(reason)
        )
        .as_bytes(),
        0o600,
    )
}

fn store(paths: &Paths, r: &RollbackInfo) {
    let v = |x: &Option<Version>| x.as_ref().map(|v| v.image_version.clone()).unwrap_or_default();
    let text = format!(
        "from={}\nto={}\ncode={}\nreason={}\nattempts={}\nat={}\n",
        one_line(&v(&r.from)),
        one_line(&v(&r.to)),
        r.reason_code,
        one_line(&r.reason),
        r.attempts,
        r.detected_unix
    );
    let _ = write_atomic(&paths.state_dir.join(LAST), text.as_bytes(), 0o600);
}

fn load(paths: &Paths) -> Option<RollbackInfo> {
    let m = kv(&std::fs::read_to_string(paths.state_dir.join(LAST)).ok()?);
    let ver = |k: &str| m.get(k).map(|s| Version { image_version: s.clone() });
    Some(RollbackInfo {
        from: ver("from"),
        to: ver("to"),
        reason: m.get("reason").cloned().unwrap_or_default(),
        reason_code: m.get("code").and_then(|s| s.parse().ok()).unwrap_or(0),
        attempts: m.get("attempts").and_then(|s| s.parse().ok()).unwrap_or(0),
        detected_unix: m.get("at").and_then(|s| s.parse().ok()).unwrap_or(0),
    })
}

/// What failed in the boots after `since_usec` (journal): gate verdicts of
/// foil-boot-check and systemd's "Failed to start" / "Rebooting: unit … failed".
/// Returns (number of those boots, last distinct lines).
fn gate_failures(paths: &Paths, since_usec: u64, current_boot: &str) -> (u32, Vec<String>) {
    let q = journal::Query { since_usec, max_priority: Some(6), limit: 5000, ..Default::default() };
    let r = journal::query(&paths.journal_roots, &q);
    let attempts = r.boots.iter().filter(|b| b.1 >= since_usec && b.0 != current_boot).count() as u32;
    let mut lines: Vec<String> = Vec::new();
    for e in r.entries.iter().filter(|e| e.boot_id != current_boot) {
        let Some(m) = e.get("MESSAGE") else { continue };
        let gate = e.get("_SYSTEMD_UNIT") == Some("foil-boot-check.service")
            && (m.contains("boot-check FAIL") || m.contains("boot-check timeout"));
        let pid1 = e.get("_PID") == Some("1") && (m.starts_with("Failed to start ") || m.starts_with("Rebooting: "));
        if gate || pid1 {
            let l = journal::redact(m, &[]).0;
            if !lines.contains(&l) {
                lines.push(l);
            }
        }
    }
    let keep = lines.len().saturating_sub(4);
    (attempts, lines.split_off(keep))
}

/// Evaluate at agent start. Returns the rollback to report, if any.
pub fn evaluate(paths: &Paths, image_id: &str, booted: &str, boot_id: &str, now_unix: u64) -> Option<RollbackInfo> {
    if let Some(o) = std::fs::read_to_string(paths.state_dir.join(OPERATOR)).ok().map(|t| kv(&t)) {
        let g = |k: &str| o.get(k).cloned().unwrap_or_default();
        if g("boot_id") != boot_id {
            let _ = std::fs::remove_file(paths.state_dir.join(OPERATOR));
            if g("to") == booted {
                let mut reason = format!("operator rollback by {}", g("who"));
                if !g("reason").is_empty() {
                    reason.push_str(": ");
                    reason.push_str(&g("reason"));
                }
                reason.truncate(1024);
                let r = RollbackInfo {
                    from: Some(Version { image_version: g("from") }),
                    to: Some(Version { image_version: booted.to_string() }),
                    reason,
                    reason_code: RollbackReason::Operator as i32,
                    attempts: 0,
                    detected_unix: now_unix as i64,
                };
                tracing::warn!(target: "audit", from = %g("from"), to = booted, reason = %r.reason, "rolled back by operator");
                store(paths, &r);
                let _ = std::fs::remove_file(paths.state_dir.join(PENDING));
                return Some(r);
            }
            tracing::error!(from = %g("from"), to = %g("to"), booted, "operator rollback did not take effect");
        }
    }
    let pending = std::fs::read_to_string(paths.state_dir.join(PENDING)).ok().map(|t| kv(&t));
    if let Some(p) = pending {
        let want = p.get("version").cloned().unwrap_or_default();
        let at: u64 = p.get("at").and_then(|s| s.parse().ok()).unwrap_or(0);
        let rebooted = p.get("boot_id").map(String::as_str) != Some(boot_id);
        if rebooted && !want.is_empty() && want != booted {
            let counter = esp_counter(&paths.esp_linux(), image_id, &want);
            // The commit marker (written after bless) decides "committed", not the ESP name: a committed entry is <v>.efi
            // (no re-arm, decision 0003 amendment), but an entry named <v>+3.efi (an image that still re-armed) must not look fresh.
            let committed = paths.foilbird_state.join("committed").join(&want).exists();
            let (code, mut reason) = match counter {
                Some(Some((l, _))) if committed && l > 0 => {
                    (RollbackReason::NotSelected, format!("{want} is committed but {booted} was booted"))
                }
                Some(Some((0, d))) => (RollbackReason::BootAttemptsExhausted, format!("{want}: {d} boot attempts failed")),
                Some(Some((l, d))) => (RollbackReason::NotSelected, format!("{want} not booted ({l} tries left, {d} done)")),
                Some(None) => (RollbackReason::NotSelected, format!("{want} is committed but {booted} was booted")),
                None => (RollbackReason::EntryRemoved, format!("{want}: boot entry not on the ESP")),
            };
            let (attempts, fails) = gate_failures(paths, at.saturating_mul(1_000_000), &boot_id.replace('-', ""));
            if !fails.is_empty() {
                reason.push_str("; ");
                reason.push_str(&fails.join(" | "));
            }
            reason.truncate(1024);
            let r = RollbackInfo {
                from: Some(Version { image_version: want.clone() }),
                to: Some(Version { image_version: booted.to_string() }),
                reason,
                reason_code: code as i32,
                attempts,
                detected_unix: now_unix as i64,
            };
            tracing::warn!(target: "audit", from = %want, to = booted, reason = %r.reason, "rolled back");
            store(paths, &r);
            let _ = std::fs::remove_file(paths.state_dir.join(PENDING));
            return Some(r);
        }
    }
    // keep reporting the last rollback while the node still runs its target
    load(paths).filter(|r| r.to.as_ref().map(|v| v.image_version.as_str()) == Some(booted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(tag: &str) -> Paths {
        let d = std::env::temp_dir().join(format!("foil-rb-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("boot/EFI/Linux")).unwrap();
        Paths::with_root(d)
    }

    #[test]
    fn exhausted_tries_are_a_rollback() {
        let p = paths("ex");
        std::fs::write(p.esp_linux().join("foilbird_3+0-3.efi"), b"").unwrap();
        std::fs::write(p.esp_linux().join("foilbird_2.efi"), b"").unwrap();
        record_pending(&p, "3", "boot-a", 100).unwrap();
        // still the same boot: nothing to say
        assert!(evaluate(&p, "foilbird", "2", "boot-a", 101).is_none());
        let r = evaluate(&p, "foilbird", "2", "boot-b", 200).expect("rollback");
        assert_eq!(r.from.unwrap().image_version, "3");
        assert_eq!(r.to.unwrap().image_version, "2");
        assert_eq!(r.reason_code, RollbackReason::BootAttemptsExhausted as i32);
        assert!(r.reason.contains("3 boot attempts failed"), "{}", r.reason);
        // persisted, pending cleared; reported again after an agent restart
        assert!(pending_version(&p).is_none());
        let again = evaluate(&p, "foilbird", "2", "boot-b", 300).expect("still reported");
        assert_eq!(again.detected_unix, 200);
        // the node moved on to another version: no longer reported
        assert!(evaluate(&p, "foilbird", "4", "boot-c", 400).is_none());
    }

    #[test]
    fn successful_update_is_not_a_rollback() {
        let p = paths("ok");
        std::fs::write(p.esp_linux().join("foilbird_3+2-1.efi"), b"").unwrap();
        record_pending(&p, "3", "boot-a", 100).unwrap();
        assert!(evaluate(&p, "foilbird", "3", "boot-b", 200).is_none());
        assert_eq!(pending_version(&p).as_deref(), Some("3"), "kept until confirmed");
        confirm(&p, "3");
        assert!(pending_version(&p).is_none());
    }

    #[test]
    fn entry_gone_or_not_selected() {
        let p = paths("gone");
        record_pending(&p, "3", "a", 1).unwrap();
        assert_eq!(evaluate(&p, "foilbird", "2", "b", 2).unwrap().reason_code, RollbackReason::EntryRemoved as i32);
        std::fs::write(p.esp_linux().join("foilbird_5+3-0.efi"), b"").unwrap();
        record_pending(&p, "5", "b", 3).unwrap();
        assert_eq!(evaluate(&p, "foilbird", "2", "c", 4).unwrap().reason_code, RollbackReason::NotSelected as i32);
    }

    #[test]
    fn operator_rollback_is_reported() {
        let p = paths("op");
        std::fs::create_dir_all(&p.state_dir).unwrap();
        record_operator(&p, "4", "3", "boot-a", 100, "ctl (on behalf of alice)", "bad driver").unwrap();
        assert!(evaluate(&p, "foilbird", "4", "boot-a", 101).is_none(), "same boot: nothing yet");
        let r = evaluate(&p, "foilbird", "3", "boot-b", 200).expect("rollback");
        assert_eq!(r.reason_code, RollbackReason::Operator as i32);
        assert_eq!((r.from.unwrap().image_version, r.to.unwrap().image_version), ("4".into(), "3".into()));
        assert_eq!(r.attempts, 0);
        assert!(r.reason.contains("ctl (on behalf of alice): bad driver"), "{}", r.reason);
        assert!(evaluate(&p, "foilbird", "3", "boot-b", 300).is_some(), "kept while on 3");
        // did not take effect: nothing reported, record dropped
        record_operator(&p, "4", "3", "boot-c", 400, "x", "").unwrap();
        assert!(evaluate(&p, "foilbird", "4", "boot-d", 500).is_none());
        assert!(!p.state_dir.join(OPERATOR).exists());
    }

    #[test]
    fn previous_release_skips_bad_and_newer() {
        let p = paths("prev");
        let e = p.esp_linux();
        for n in ["foilbird_2.efi", "foilbird_3+0-3.efi", "foilbird_4.efi", "foilbird_5+3-0.efi", "foilbird_1.efi", "other_3.efi"] {
            std::fs::write(e.join(n), b"").unwrap();
        }
        assert_eq!(previous_release(&e, "foilbird", "4").map(|x| x.0).as_deref(), Some("2"));
        assert_eq!(previous_release(&e, "foilbird", "2").map(|x| x.0).as_deref(), Some("1"));
        assert_eq!(previous_release(&e, "foilbird", "1"), None);
    }

    fn fake_uki(version: &str, signed: bool, cmdline: &str) -> Vec<u8> {
        let secs: [(&str, Vec<u8>); 4] = [
            (".osrel", format!("ID=foilbird\nIMAGE_VERSION=\"{version}\"\nFOILBIRD_PCR_EPOCH=2\n").into_bytes()),
            (".cmdline", cmdline.as_bytes().to_vec()),
            (".linux", vec![1; 16]),
            (".initrd", vec![2; 16]),
        ];
        let (pe, opt_size) = (0x80usize, 240usize);
        let hdr_end = pe + 24 + opt_size + 40 * secs.len();
        let mut b = vec![0u8; hdr_end];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        b[pe..pe + 4].copy_from_slice(b"PE\0\0");
        b[pe + 6..pe + 8].copy_from_slice(&(secs.len() as u16).to_le_bytes());
        b[pe + 20..pe + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt = pe + 24;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        if signed {
            b[opt + 112 + 36..opt + 112 + 40].copy_from_slice(&8u32.to_le_bytes());
        }
        for (i, (n, d)) in secs.iter().enumerate() {
            let h = opt + opt_size + 40 * i;
            let off = b.len();
            b[h..h + n.len()].copy_from_slice(n.as_bytes());
            b[h + 8..h + 12].copy_from_slice(&(d.len() as u32).to_le_bytes());
            b[h + 16..h + 20].copy_from_slice(&(d.len() as u32).to_le_bytes());
            b[h + 20..h + 24].copy_from_slice(&(off as u32).to_le_bytes());
            b.extend_from_slice(d);
        }
        b
    }

    #[test]
    fn uki_checks() {
        let ok = fake_uki("3", true, "usrhash=ab rw");
        assert_eq!(check_uki(&ok, "3"), Ok(()));
        assert!(check_uki(&ok, "4").unwrap_err().contains("IMAGE_VERSION"));
        assert!(check_uki(&fake_uki("3", false, "usrhash=ab"), "3").unwrap_err().contains("not signed"));
        assert!(check_uki(&fake_uki("3", true, "quiet"), "3").unwrap_err().contains("usrhash"));
        assert!(check_uki(&ok[..ok.len() - 8], "3").is_err(), "truncated");
        assert!(check_uki(b"hello", "3").is_err());
    }

    #[test]
    fn rollback_layout() {
        let p = paths("layout");
        let e = p.esp_linux();
        for n in ["foilbird_2.efi", "foilbird_3.efi", "other_9.efi"] {
            std::fs::write(e.join(n), b"x").unwrap();
        }
        assert!(esp_rollback_layout(&e, "foilbird", "3").unwrap_err().contains("no recovery UKI"));
        std::fs::write(e.join(RECOVERY_UKI), b"").unwrap();
        assert!(esp_rollback_layout(&e, "foilbird", "3").unwrap_err().contains("no recovery UKI"), "empty file");
        std::fs::write(e.join(RECOVERY_UKI), b"MZ").unwrap();
        assert_eq!(esp_rollback_layout(&e, "foilbird", "3"), Ok(()));
        // a newer good release (counting, or without a counter) is refused
        for n in ["foilbird_4+3-0.efi", "foilbird_4+1-2.efi", "foilbird_4.efi"] {
            std::fs::write(e.join(n), b"x").unwrap();
            let err = esp_rollback_layout(&e, "foilbird", "3").unwrap_err();
            assert!(err.contains(n) && err.contains("newer"), "{n}: {err}");
            std::fs::remove_file(e.join(n)).unwrap();
        }
        // a bad newer entry (abandoned by an earlier rollback, or tries exhausted) is sorted last by systemd-boot
        std::fs::write(e.join("foilbird_4+0.efi"), b"x").unwrap();
        std::fs::write(e.join("foilbird_5+0-3.efi"), b"x").unwrap();
        assert_eq!(esp_rollback_layout(&e, "foilbird", "3"), Ok(()));
    }

    #[test]
    fn uki_epoch_from_osrel() {
        let ok = fake_uki("3", false, "quiet");
        assert_eq!(uki_epoch(&ok), Ok(Some(2)), "read without a signature check");
        assert_eq!(uki_osrel(&ok).unwrap().get("IMAGE_VERSION").map(String::as_str), Some("3"));
        assert!(uki_epoch(b"hello").is_err());
    }

    #[test]
    fn partitions_by_name() {
        let p = paths("parts");
        for (d, n) in [("vda2", "usr_3"), ("vda3", "usr-verity_3"), ("vda4", "usr-verity-sig_3"), ("vda5", "usr_4")] {
            std::fs::create_dir_all(p.sys_block.join(d)).unwrap();
            std::fs::write(p.sys_block.join(d).join("uevent"), format!("MAJOR=253\nDEVTYPE=partition\nPARTNAME={n}\n")).unwrap();
        }
        assert!(missing_partitions(&p.sys_block, "3").is_empty());
        assert_eq!(missing_partitions(&p.sys_block, "4"), vec!["usr-verity_4".to_string(), "usr-verity-sig_4".to_string()]);
    }

    #[test]
    fn committed_marker_beats_a_plus3_name() {
        // committed entries are <v>.efi (no re-arm, decision 0003 amendment); an entry named <v>+3.efi (an image that still re-armed) is
        // told apart from a fresh one by the commit marker
        let p = paths("rearm");
        std::fs::write(p.esp_linux().join("foilbird_6+3.efi"), b"").unwrap();
        record_pending(&p, "6", "a", 1).unwrap();
        let r = evaluate(&p, "foilbird", "5", "b", 2).unwrap();
        assert!(r.reason.contains("not booted"), "{}", r.reason);
        std::fs::create_dir_all(p.foilbird_state.join("committed")).unwrap();
        std::fs::write(p.foilbird_state.join("committed/6"), b"").unwrap();
        record_pending(&p, "6", "b", 3).unwrap();
        let r = evaluate(&p, "foilbird", "5", "c", 4).unwrap();
        assert_eq!(r.reason_code, RollbackReason::NotSelected as i32);
        assert!(r.reason.contains("6 is committed but 5 was booted"), "{}", r.reason);
    }
}
