// SPDX-License-Identifier: Apache-2.0
//! foil-agent — node agent (PoC, v0).
//!
//!   foil-agent serve [--listen ADDR]     gRPC API over mTLS
//!   foil-agent apply-boot                render configuration at boot
//!   foil-agent boot-check [--timeout S]  health gate for boot-complete.target
//!   foil-agent wait-time-sync [--timeout S]  before the first join: wait for the clock
//!   foil-agent version

use foil_agent::config::{self, Paths};
use foil_agent::{pb, server, system, update};
use std::sync::Arc;
use pb::{CheckStatus, ConfigSource};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    foil_agent::logfmt::init();   // `<N>` priority prefix when stdout is the journal (audit WARN = priority 4)
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths::from_env();
    let r = match args.first().map(String::as_str) {
        Some("serve") => serve(&paths, &args).await,
        Some("apply-boot") => apply_boot(&paths).await,
        Some("boot-check") => return boot_check(&paths, &args).await,
        Some("wait-time-sync") => return wait_time_sync(&paths, &args).await,
        Some("version") => {
            let f: Vec<&str> = [(ESP_BRIDGE_TLS, "esp-bridge-tls"), (config::LAB_CRASH_POINTS, "lab-crash-points")].iter().filter(|(on, _)| *on).map(|(_, n)| *n).collect();
            println!("foil-agent {} features: {}", env!("CARGO_PKG_VERSION"), if f.is_empty() { "-".to_string() } else { f.join(",") });
            Ok(())
        }
        _ => Err("usage: foil-agent serve|apply-boot|boot-check|wait-time-sync|version".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

type Res = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const TLS_CERT: &str = "agent.tls-cert";
/// Lab build only (feature `esp-bridge-tls`): TLS material may also come from the ESP bridge.
const ESP_BRIDGE_TLS: bool = cfg!(feature = "esp-bridge-tls");

/// Directory with agent.tls-cert, agent.tls-key and agent.tls-ca: --tls-dir,
/// then systemd credentials; the ESP bridge directory only in a lab build.
fn tls_dir(arg: Option<PathBuf>, creds: Option<PathBuf>, esp: &std::path::Path) -> Result<PathBuf, String> {
    let esp_dir = ESP_BRIDGE_TLS.then(|| esp.to_path_buf());
    if let Some(d) = [arg, creds, esp_dir].into_iter().flatten().find(|d| d.join(TLS_CERT).exists()) {
        return Ok(d);
    }
    if !ESP_BRIDGE_TLS && esp.join(TLS_CERT).exists() {
        return Err(format!(
            "no TLS material: {} on the ESP is ignored, this build has no ESP fallback (lab feature esp-bridge-tls); \
             provide --tls-dir or ImportCredential=agent.tls-*",
            esp.join(TLS_CERT).display()
        ));
    }
    Err(if ESP_BRIDGE_TLS {
        format!("no TLS material: --tls-dir, ImportCredential=agent.tls-* or {}", esp.display())
    } else {
        "no TLS material: --tls-dir or ImportCredential=agent.tls-*".into()
    })
}

/// Bridge configuration files read by apply-boot when nothing is persisted.
const BRIDGE_FILES: [&str; 5] = [config::NODE_HOSTNAME, config::NODE_NETWORK, config::K8S_JOIN, config::K8S_LABELS, config::K8S_TAINTS];

/// Where apply-boot reads the bridge configuration. Lab build (`lab`, feature esp-bridge-tls): the ESP
/// bridge directory, then systemd credentials, as before. Product build: systemd credentials only; bridge files on the ESP
/// are returned as ignored (for the journal): the ESP is unauthenticated, and whoever writes it before the first boot
/// would choose the host name, network, k8s join (token, apiserver), labels and taints (api/registration.md, BRIDGE).
fn bridge_source(esp: &std::path::Path, creds: &std::path::Path, lab: bool) -> (PathBuf, Vec<&'static str>) {
    if lab {
        let src = [esp, creds].into_iter().find(|d| d.join(config::NODE_HOSTNAME).exists()).unwrap_or(esp);
        return (src.to_path_buf(), Vec::new());
    }
    (creds.to_path_buf(), BRIDGE_FILES.into_iter().filter(|n| esp.join(n).exists()).collect())
}

/// At boot: the configuration applied through the API (persisted in /var)
/// wins; otherwise the temporary bridge credentials are used as is.
async fn apply_boot(paths: &Paths) -> Res {
    if let Some(p) = config::load(paths, false) {
        let errs = config::validate(&p.config);
        if !errs.is_empty() {
            return Err(format!("persisted config invalid: {} errors", errs.len()).into());
        }
        server::apply_live(paths, &p.config, p.generation, true).await?;
        config::write_atomic(&paths.config_dir.join("source"), b"api\n", 0o644)?;
        server::record_booted_k8s(paths, p.config.k8s.as_ref())?;
        tracing::info!(generation = p.generation, "applied persisted config");
        return Ok(());
    }
    // Temporary bridge (TEST): systemd credentials; plain files on the ESP in /boot/loader/foilbird/<name> only in a lab build.
    let creds = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from).unwrap_or_else(|| paths.credentials.clone());
    // the k8s section of a bridge boot counts as none, as before (the first Apply with k8s asks for a reboot)
    server::record_booted_k8s(paths, None)?;
    let (src, ignored) = bridge_source(&paths.esp_bridge, &creds, ESP_BRIDGE_TLS);
    if !ignored.is_empty() {
        tracing::warn!(
            dir = %paths.esp_bridge.display(),
            files = %ignored.join(","),
            "bridge configuration on the ESP ignored: this build has no ESP fallback (lab feature esp-bridge-tls); \
             provide systemd credentials (ImportCredential=node.* k8s.*)"
        );
    }
    tracing::info!(source = %src.display(), "bridge source");
    match config::read_bridge(&src)? {
        Some(b) => {
            config::install(paths, &b.files, 1, &[])?;
            config::install_hosts(paths, &[])?;
            config::set_hostname_syscall(paths, &b.hostname)?;
            config::write_atomic(&paths.config_dir.join("source"), b"bridge\n", 0o644)?;
            tracing::info!(files = b.files.len(), "applied bridge credentials");
        }
        None => {
            config::install_hosts(paths, &[])?;
            tracing::info!("no configuration: neither persisted nor bridge");
        }
    }
    Ok(())
}

fn load_state(paths: &Paths) -> server::State {
    if let Some(p) = config::load(paths, true) {
        let booted_k8s = server::booted_k8s(paths, Some(&p.config));
        return server::State { generation: p.generation, config: Some(p.config), source: ConfigSource::Api, booted_k8s };
    }
    let booted_k8s = server::booted_k8s(paths, None);
    if system::read_trim(paths.config_dir.join("source")) == "bridge" {
        return server::State { generation: 1, config: None, source: ConfigSource::Bridge, booted_k8s };
    }
    server::State { generation: 0, config: None, source: ConfigSource::None, booted_k8s }
}

/// Release channel, release key and version floor come from the image (and
/// the agent's own state), never from the API caller.
fn stager(paths: &Paths) -> Arc<update::Stager> {
    let osr = system::os_release();
    // Floor: max(/var/lib/foilbird/min_version written by the image's raise unit, FOILBIRD_MIN_VERSION), read on every
    // use (update::Policy::floor). The agent never writes it.
    let min_version = osr.get("FOILBIRD_MIN_VERSION").cloned().unwrap_or_default();
    Arc::new(update::Stager {
        channel: update::channel_from_image(std::path::Path::new("/usr/lib/foil-agent/channel")),
        channel_override: Default::default(),
        platform: Arc::new(server::LivePlatform { run_dir: paths.run_dir.clone() }),
        policy: update::Policy {
            image_id: osr.get("IMAGE_ID").cloned().unwrap_or_default(),
            booted: osr.get("IMAGE_VERSION").cloned().unwrap_or_default(),
            min_version: if min_version.is_empty() { "0".into() } else { min_version },
            foilbird_state: Some(paths.foilbird_state.clone()),
            // systemd 257 reads import-pubring.gpg, 259 also .pgp; the image ships both
            keyring: Arc::new(
                std::fs::read("/usr/lib/systemd/import-pubring.gpg")
                    .or_else(|_| std::fs::read("/usr/lib/systemd/import-pubring.pgp"))
                    .unwrap_or_default(),
            ),
            max_file: 8 << 30,
            booted_epoch: osr.get("FOILBIRD_PCR_EPOCH").and_then(|e| e.parse().ok()),
            var_luks2: system::var_protection() == pb::VarProtection::Luks2Tpm2,
        },
        staging_root: paths.state_dir.join("staging"),
        state: Default::default(),
    })
}

async fn serve(paths: &Paths, args: &[String]) -> Res {
    let listen = arg_value(args, "--listen").unwrap_or_else(|| "[::]:7443".into()).parse()?;
    let dir = tls_dir(arg_value(args, "--tls-dir").map(PathBuf::from), std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from), &paths.esp_bridge)?;
    tracing::info!(tls = %dir.display(), "TLS material");
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
    };
    let st = stager(paths);
    let (p, id, booted) = (paths.clone(), st.policy.image_id.clone(), st.policy.booted.clone());
    let rb = tokio::task::spawn_blocking(move || {
        let boot_id = system::read_trim("/proc/sys/kernel/random/boot_id");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        foil_agent::rollback::evaluate(&p, &id, &booted, &boot_id, now)
    })
    .await?;
    server::run(paths.clone(), load_state(paths), st, rb, listen, &dir, shutdown).await
}

/// Reported by GetHealth but not part of the boot gate: they depend on the
/// environment, not on the booted image. An unreachable NTP server, a missing
/// router or a unit that has nothing to do with the image must not roll back
/// every node that updates meanwhile. Their checks return WARN, never FAIL,
/// so this list only keeps the PENDING states of time-synced out of the gate.
/// The control plane's apiserver (CP v0) is reported too: it depends on etcd and the cluster, not only on the image.
// var-key-slots: unknown key material on /var is an incident, not a broken release
// esp-writable: a read-only or unmountable ESP is the node's disk, not the booted release
const NOT_GATING: &[&str] = &["time-synced", "network-online", "no-failed-units", "apiserver", "var-key-slots", "esp-writable"];

/// ExecStartPre of the first join (owner policy: the first join needs a
/// synchronized clock; certificates and the bootstrap token have validity
/// windows). Exit 0 once the kernel clock is synchronized; after the timeout
/// record the reason for GetHealth (time-synced FAIL) and exit non-zero, so
/// the join unit retries (Restart=on-failure).
async fn wait_time_sync(paths: &Paths, args: &[String]) -> ExitCode {
    let timeout = arg_value(args, "--timeout").and_then(|s| s.parse().ok()).unwrap_or(120u64);
    let result = paths.run_dir.join(system::TIME_WAIT_RESULT);
    let start = Instant::now();
    let mut logged = false;
    loop {
        if system::clock_synced() {
            let _ = std::fs::remove_file(&result);
            tracing::info!("time-sync: clock synchronized after {}s; {}", start.elapsed().as_secs(), system::ntp_servers().await);
            return ExitCode::SUCCESS;
        }
        if !logged {
            tracing::info!("time-sync: first join waits up to {timeout}s for the clock; {}", system::ntp_servers().await);
            logged = true;
        }
        if start.elapsed() >= Duration::from_secs(timeout) {
            let servers = system::ntp_servers().await;
            let _ = config::write_atomic(&result, format!("not synchronized within {timeout}s\n").as_bytes(), 0o644);
            tracing::error!("time-sync: clock not synchronized within {timeout}s, first join blocked; {servers}");
            return ExitCode::FAILURE;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Failures that waiting cannot fix: the image itself is wrong (or its kubelet crash-loops on a joined node;
/// or an NVIDIA GPU is on PCI and the driver did not load).
fn hard_failure(checks: &[pb::HealthCheck]) -> bool {
    checks.iter().any(|c| c.status == CheckStatus::Fail as i32 && matches!(c.name.as_str(), "usr-verity" | "var-mounted" | "kubelet-crashloop" | "gpu"))
}

/// Exit 0 when every required check passes; non-zero on a failure or when
/// the timeout expires with checks still pending. The unit maps a failure
/// to FailureAction=reboot, so boot counting eventually rolls back.
async fn boot_check(paths: &Paths, args: &[String]) -> ExitCode {
    let timeout = arg_value(args, "--timeout").and_then(|s| s.parse().ok()).unwrap_or(300u64);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let profile = {
        let has_k8s = paths.config_dir.join(config::K8S_JOIN).exists() || paths.config_dir.join(config::K8S_INIT).exists();
        system::profile(&system::os_release(), has_k8s)
    };
    let result = |s: &str| {
        let _ = config::write_atomic(&paths.run_dir.join("boot-check.result"), format!("{s}\n").as_bytes(), 0o644);
    };
    let _ = std::fs::remove_file(paths.run_dir.join("boot-check.result"));
    let mut last: Option<String> = None;
    loop {
        let all = system::health_in(profile, &paths.run_dir).await;
        // First join blocked by the clock (wait timed out): kubelet cannot come up, and
        // that is the environment, not the image; rebooting would not fix NTP.
        let join_blocked = all.iter().any(|c| c.name == "time-synced" && c.status == CheckStatus::Fail as i32);
        let checks: Vec<_> = all
            .into_iter()
            .filter(|c| !NOT_GATING.contains(&c.name.as_str()) && !(join_blocked && c.name == "kubelet-healthy"))
            .collect();
        if join_blocked {
            tracing::warn!("boot-check: kubelet-healthy not gated, first join blocked by time sync");
        }
        let overall = system::overall(&checks);
        let summary: Vec<String> = checks
            .iter()
            .map(|c| format!("{}={}", c.name, CheckStatus::try_from(c.status).map(|s| s.as_str_name()).unwrap_or("?")))
            .collect();
        match overall {
            // WARN never gates the boot
            CheckStatus::Pass | CheckStatus::Warn => {
                tracing::info!("boot-check PASS: {}", summary.join(" "));
                result("PASS");
                return ExitCode::SUCCESS;
            }
            CheckStatus::Fail if hard_failure(&checks) || Instant::now() >= deadline => {
                for c in checks.iter().filter(|c| c.status == CheckStatus::Fail as i32) {
                    tracing::error!("boot-check FAIL {}: {}", c.name, c.detail);
                }
                result("FAIL");
                return ExitCode::FAILURE;
            }
            _ if Instant::now() >= deadline => {
                tracing::error!("boot-check timeout after {timeout}s: {}", summary.join(" "));
                result("FAIL");
                return ExitCode::FAILURE;
            }
            _ => {
                if last.as_deref() != Some(summary.join(" ").as_str()) {
                    tracing::info!("boot-check waiting: {}", summary.join(" "));
                    last = Some(summary.join(" "));
                }
                tokio::time::sleep(Duration::from_secs(5)).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with_cert(root: &std::path::Path, name: &str) -> PathBuf {
        let d = root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(TLS_CERT), "x").unwrap();
        d
    }

    #[test]
    fn tls_dir_sources() {
        let root = std::env::temp_dir().join(format!("foil-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let esp = dir_with_cert(&root, "esp");
        let creds = dir_with_cert(&root, "creds");
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        // credentials win over the ESP in both builds
        assert_eq!(tls_dir(None, Some(creds.clone()), &esp).unwrap(), creds);
        assert_eq!(tls_dir(Some(creds.clone()), Some(empty.clone()), &esp).unwrap(), creds);
        let r = tls_dir(None, Some(empty.clone()), &esp);
        if ESP_BRIDGE_TLS {
            assert_eq!(r.unwrap(), esp);
        } else {
            let e = r.unwrap_err();
            assert!(e.contains("ignored") && e.contains("esp-bridge-tls"), "{e}");
        }
        let e = tls_dir(None, None, &empty).unwrap_err();
        assert!(e.starts_with("no TLS material"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bridge_source_by_build() {
        let root = std::env::temp_dir().join(format!("foil-bridge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (esp, creds, empty) = (root.join("esp"), root.join("creds"), root.join("empty"));
        for d in [&esp, &creds, &empty] {
            std::fs::create_dir_all(d).unwrap();
        }
        for n in [config::NODE_HOSTNAME, config::K8S_JOIN] {
            std::fs::write(esp.join(n), "x").unwrap();
        }
        std::fs::write(creds.join(config::NODE_HOSTNAME), "x").unwrap();
        // lab build: the ESP first, then credentials, the ESP when neither has a host name (the old order)
        assert_eq!(bridge_source(&esp, &creds, true), (esp.clone(), vec![]));
        assert_eq!(bridge_source(&empty, &creds, true), (creds.clone(), vec![]));
        assert_eq!(bridge_source(&empty, &empty.join("none"), true), (empty.clone(), vec![]));
        // product build: credentials only, files on the ESP reported as ignored, even with no credentials at all
        assert_eq!(bridge_source(&esp, &creds, false), (creds.clone(), vec![config::NODE_HOSTNAME, config::K8S_JOIN]));
        let none = root.join("none");
        assert_eq!(bridge_source(&esp, &none, false), (none.clone(), vec![config::NODE_HOSTNAME, config::K8S_JOIN]));
        assert!(config::read_bridge(&none).unwrap().is_none());
        assert_eq!(bridge_source(&empty, &creds, false), (creds.clone(), vec![]));
        // this build
        assert_eq!(bridge_source(&esp, &none, ESP_BRIDGE_TLS).0, if ESP_BRIDGE_TLS { esp.clone() } else { none.clone() });
        let _ = std::fs::remove_dir_all(&root);
    }
}
