// SPDX-License-Identifier: Apache-2.0
//! gRPC service over mTLS.
//!
//! Authorization happens before any handler, in the tower layer of
//! [`crate::authz`] (roles per RPC from the .proto, deny by default). Handlers
//! only read the authorized [`authz::Caller`] for their audit records.

use crate::config::{self, Paths};
use crate::authz;
use crate::pb::{self, node_agent_server::NodeAgent, AgentMode, ConfigSource};
use crate::journal;
use crate::rollback;
use crate::system;
use crate::update;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

pub struct State {
    pub generation: u64,
    pub config: Option<pb::NodeConfig>,
    pub source: ConfigSource,
    /// Fingerprint of the k8s section this boot runs with ([`k8s_fingerprint`]): reboot_required compares the
    /// new section with it, not with the last applied generation.
    pub booted_k8s: String,
}

pub struct Agent {
    pub paths: Paths,
    pub state: Arc<Mutex<State>>,
    pub stager: Arc<update::Stager>,
    /// Rollback detected at start (or persisted from an earlier start).
    pub rollback: Arc<Mutex<Option<pb::RollbackInfo>>>,
    /// The operator operation in flight (Rollback, RaiseMinVersion), detached from the RPC that started it.
    pub ops: Arc<Ops>,
}

/// A rollback of `version` whose unit finished but whose record or reboot did not happen: <id>_<N>+0.efi is on the ESP and
/// <id>_<N>.efi is not.
fn rollback_interrupted(esp_linux: &std::path::Path, image_id: &str, version: &str) -> bool {
    !esp_linux.join(format!("{image_id}_{version}.efi")).exists() && esp_linux.join(format!("{image_id}_{version}+0.efi")).is_file()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Result of an operator operation: its RPC's response, or an error (code, message).
#[derive(Clone, Debug)]
pub enum OpOk {
    Rollback(pb::RollbackResponse),
    Raise(pb::RaiseMinVersionResponse),
}
pub type OpResult = Result<OpOk, (tonic::Code, String)>;

struct OpSlot {
    kind: &'static str,
    version: String,
    rx: tokio::sync::watch::Receiver<Option<OpResult>>,
}

impl OpSlot {
    /// Still running: no result yet and its task still holds the sender (a task that died without a result frees the slot).
    fn running(&self) -> bool {
        self.rx.borrow().is_none() && self.rx.has_changed().is_ok()
    }
}

/// One operator operation at a time, run in its own task: a caller whose connection drops (timeout, reset) only stops
/// waiting, the operation goes on to its end (unit, record, reboot) and its result stays in `last`. A call of the same
/// operation (kind, version) while it runs waits for it and gets the same result; another one is refused.
#[derive(Default)]
pub struct Ops {
    cur: Mutex<Option<OpSlot>>,
    last: Arc<std::sync::Mutex<Option<pb::OperatorOperation>>>,
}

impl Ops {
    /// The running operation, if any: "<kind> of <version>".
    pub async fn running(&self) -> Option<String> {
        self.cur.lock().await.as_ref().filter(|s| s.running()).map(|s| format!("{} of {}", s.kind, s.version))
    }

    pub fn last(&self) -> Option<pb::OperatorOperation> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Run `f` as operation (kind, version), or join the same running one; wait for the result.
    pub async fn run<F>(&self, kind: &'static str, version: &str, f: F) -> Result<OpOk, Status>
    where
        F: std::future::Future<Output = OpResult> + Send + 'static,
    {
        let mut rx = {
            let mut cur = self.cur.lock().await;
            match cur.as_ref() {
                Some(s) if s.running() => {
                    if s.kind != kind || s.version != version {
                        return Err(Status::failed_precondition(format!("a {} of {} is running", s.kind, s.version)));
                    }
                    tracing::info!(kind, version, "operation running: waiting for it");
                    s.rx.clone()
                }
                _ => {
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    *cur = Some(OpSlot { kind, version: version.to_string(), rx: rx.clone() });
                    let op = |phase: pb::OperationPhase, detail: &str, end: i64, started: i64| pb::OperatorOperation {
                        kind: kind.to_string(),
                        version: Some(pb::Version { image_version: version.to_string() }),
                        phase: phase as i32,
                        detail: detail.to_string(),
                        started_unix: started,
                        finished_unix: end,
                    };
                    let started = unix_now();
                    *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(op(pb::OperationPhase::Running, "", 0, started));
                    let last = self.last.clone();
                    let v = version.to_string();
                    tokio::spawn(async move {
                        // f in a task of its own: a panic in it ends the operation as FAILED, never RUNNING for good (an
                        // unwinding build: tests). The release build has panic = "abort": the agent restarts instead,
                        // and GetUpdateStatus/Rollback read the ESP (REBOOT_PENDING and resume if the unit had run).
                        let r = match tokio::spawn(f).await {
                            Ok(r) => r,
                            Err(e) if e.is_panic() => Err((tonic::Code::Internal, "operation task panicked".to_string())),
                            Err(_) => Err((tonic::Code::Internal, "operation task cancelled".to_string())),
                        };
                        let (phase, detail) = match &r {
                            Ok(_) => (pb::OperationPhase::Done, String::new()),
                            Err((_, m)) if m.starts_with("reboot: ") => (pb::OperationPhase::RebootPending, m.clone()),
                            Err((_, m)) => (pb::OperationPhase::Failed, m.clone()),
                        };
                        tracing::info!(kind, version = %v, phase = phase.as_str_name(), detail = %detail, "operation finished");
                        *last.lock().unwrap_or_else(|e| e.into_inner()) = Some(pb::OperatorOperation {
                            kind: kind.to_string(),
                            version: Some(pb::Version { image_version: v.clone() }),
                            phase: phase as i32,
                            detail,
                            started_unix: started,
                            finished_unix: unix_now(),
                        });
                        let _ = tx.send(Some(r));
                    });
                    rx
                }
            }
        };
        loop {
            if let Some(r) = rx.borrow().clone() {
                return r.map_err(|(c, m)| Status::new(c, m));
            }
            if rx.changed().await.is_err() {
                return Err(Status::internal("operation ended without a result"));
            }
        }
    }
}

pub const VAR_EPOCH_RESULTS: &str = "/run/foilbird/var-epoch";

/// Start a oneshot unit of the image and wait for its job result (done,
/// failed, canceled, timeout, dependency, skipped). Subscribe before starting:
/// the unit is unloaded right after it finishes, so its Result cannot be read
/// afterwards; the result comes with JobRemoved.
async fn run_unit(unit: &str, timeout: std::time::Duration) -> Result<String, String> {
    use futures_util::StreamExt;
    let c = zbus::Connection::system().await.map_err(|e| e.to_string())?;
    const SD: &str = "org.freedesktop.systemd1";
    const MGR: &str = "org.freedesktop.systemd1.Manager";
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(SD)
        .interface(MGR)
        .member("JobRemoved")
        .build()
        .map_err(|e| e.to_string())?;
    let mut signals = zbus::MessageStream::for_match_rule(rule, &c, std::num::NonZeroUsize::new(64)).await.map_err(|e| e.to_string())?;
    c.call_method(Some(SD), "/org/freedesktop/systemd1", Some(MGR), "Subscribe", &()).await.map_err(|e| e.to_string())?;
    let job: zbus::OwnedObjectPath = c
        .call_method(Some(SD), "/org/freedesktop/systemd1", Some(MGR), "StartUnit", &(unit, "fail"))
        .await
        .map_err(|e| format!("{unit}: {e}"))?
        .body()
        .deserialize()
        .map_err(|e| e.to_string())?;
    tracing::info!(%unit, job = %job.as_str(), "unit started");
    let wait = async {
        while let Some(m) = signals.next().await {
            let Ok(m) = m else { continue };
            let Ok((_id, path, _u, result)) = m.body().deserialize::<(u32, zbus::OwnedObjectPath, String, String)>() else { continue };
            if path == job {
                return Some(result);
            }
        }
        None
    };
    let result = tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_| format!("{unit}: timeout"))?
        .ok_or_else(|| format!("{unit}: signal stream ended"))?;
    tracing::info!(%unit, %result, "unit finished");
    Ok(result)
}

/// The real node: boot state from systemd/EFI, reboot through logind. The
/// slot installer is wired to systemd-sysupdate once its staging source
/// exists; until then install fails explicitly.
pub struct LivePlatform {
    pub run_dir: std::path::PathBuf,
}

#[tonic::async_trait]
impl update::Platform for LivePlatform {
    async fn boot_confirmed(&self) -> bool {
        system::boot_state(&self.run_dir).await.confirmation == pb::BootConfirmation::Confirmed as i32
    }
    /// The image's installer unit writes the inactive slot from
    /// staging/current: `foil-install@<version>.service`, oneshot. The agent
    /// only starts it through systemd and waits for its result, so its own
    /// sandbox needs no access to disks or the ESP.
    async fn install(&self, _staging: &std::path::Path, version: &str) -> Result<(), String> {
        let unit = format!("foil-install@{}.service", update::systemd_escape(version));
        let result = run_unit(&unit, std::time::Duration::from_secs(45 * 60)).await;
        crate::system::esp_names_changed();
        let result = result?;
        if result == "done" { Ok(()) } else { Err(format!("{unit}: job {result}")) }
    }

    /// `foil-var-epoch@<op>-<v>.service` (an image unit): instance escaped like the
    /// installer's (the unit unescapes with %I and maps "/" back to "-"); the
    /// result file is /run/foilbird/var-epoch/<op>-<v>.result with the raw version.
    async fn var_epoch(&self, op: &str, version: &str) -> update::KeyOutcome {
        let unit = format!("foil-var-epoch@{op}-{}.service", update::systemd_escape(version));
        let file = std::path::Path::new(VAR_EPOCH_RESULTS).join(format!("{op}-{version}.result"));
        // /run/foilbird is read-only for the agent; every unit run rewrites the file, and a job other than
        // "done" is a failure whatever the file says.
        match run_unit(&unit, std::time::Duration::from_secs(6 * 60)).await {
            Ok(job) => {
                let text = std::fs::read_to_string(&file).ok();
                update::key_outcome(&job, text.as_deref())
            }
            Err(e) => update::KeyOutcome { phase: pb::KeyOpPhase::Failed, detail: e },
        }
    }

    /// `foil-rollback@<version>.service` (image unit): checks itself that
    /// <version> is the booted, committed release and renames its UKI to a
    /// bad entry (+0), so systemd-boot boots the previous one.
    async fn abandon(&self, version: &str) -> Result<(), String> {
        let unit = format!("foil-rollback@{}.service", update::systemd_escape(version));
        let result = run_unit(&unit, std::time::Duration::from_secs(120)).await;
        crate::system::esp_names_changed();
        let result = result?;
        if result == "done" { Ok(()) } else { Err(format!("{unit}: job {result}")) }
    }

    async fn slots(&self) -> Vec<pb::Slot> {
        Vec::new()
    }
    async fn reboot(&self) -> Result<(), String> {
        let c = zbus::Connection::system().await.map_err(|e| e.to_string())?;
        c.call_method(Some("org.freedesktop.login1"), "/org/freedesktop/login1", Some("org.freedesktop.login1.Manager"), "Reboot", &(false,))
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl Agent {
    async fn profile(&self) -> pb::Profile {
        let has_k8s = {
            let s = self.state.lock().await;
            s.config.as_ref().is_some_and(|c| c.k8s.is_some())
                || self.paths.config_dir.join(config::K8S_JOIN).exists()
                || self.paths.config_dir.join(config::K8S_INIT).exists()
        };
        system::profile(&system::os_release(), has_k8s)
    }
}

impl Agent {
    async fn var_keys(&self) -> pb::VarKeys {
        let p = &self.stager.policy;
        let st = self.stager.state.lock().await;
        pb::VarKeys {
            committed_at_unix: p.committed_at(&p.booted).unwrap_or(0),
            booted_epoch: system::os_release().get("FOILBIRD_PCR_EPOCH").and_then(|e| e.parse().ok()).unwrap_or(0),
            enrolled: p.enrolled(),
            enroll: st.enroll.clone(),
            raise: st.raise.clone(),
        }
    }
}

impl Agent {
    /// The operator operation of this process (running or last), else what the ESP says: the booted release is committed,
    /// <id>_<N>.efi is gone and <id>_<N>+0.efi is there = abandoned by a rollback whose reboot did not happen (the same
    /// files Rollback resumes from; a counted name +0-k, the boot counter's own rollback, is not one).
    fn operation(&self) -> Option<pb::OperatorOperation> {
        if let Some(o) = self.ops.last() {
            return Some(o);
        }
        let p = &self.stager.policy;
        let abandoned = p.committed_at(&p.booted).is_some() && rollback_interrupted(&self.paths.esp_linux(), &p.image_id, &p.booted);
        abandoned.then(|| pb::OperatorOperation {
            kind: "rollback".into(),
            version: Some(pb::Version { image_version: p.booted.clone() }),
            phase: pb::OperationPhase::RebootPending as i32,
            detail: format!(
                "the booted release {} is abandoned on the ESP ({}_{}+0.efi) but the node did not reboot; the next boot starts the previous release; Rollback with expect_booted {} records it and reboots",
                p.booted, p.image_id, p.booted, p.booted
            ),
            started_unix: 0,
            finished_unix: 0,
        })
    }

    async fn boot_state(&self) -> pb::BootState {
        let mut b = system::boot_state(&self.paths.run_dir).await;
        b.rollback = self.rollback.lock().await.clone();
        b
    }

    async fn journal(&self, q: journal::Query, boot: i32, limit: u32) -> Result<pb::ReadJournalResponse, Status> {
        self.journal_with(q, boot, if limit == 0 { 200 } else { limit.min(2000) }, true).await
    }

    /// `limit` already bounded by the caller; `redact` = false only for the
    /// EMERGENCY dump.
    async fn journal_with(&self, mut q: journal::Query, boot: i32, limit: u32, redact: bool) -> Result<pb::ReadJournalResponse, Status> {
        if q.max_priority.is_some_and(|p| p > 7) {
            return Err(Status::invalid_argument("max_priority: 0..7"));
        }
        if boot > 0 {
            return Err(Status::invalid_argument("boot: 0 = current, -1 = previous, ..."));
        }
        q.limit = limit as usize;
        let known: Vec<String> = {
            let s = self.state.lock().await;
            s.config.as_ref().map(config::secret_values).unwrap_or_default()
        };
        let roots = self.paths.journal_roots.clone();
        let current = system::read_trim("/proc/sys/kernel/random/boot_id").replace('-', "");
        let res = tokio::task::spawn_blocking(move || {
            if boot == 0 {
                q.boot_id = Some(current.clone());
            } else {
                // boot list first (one extra pass), then the boot by offset
                let probe = journal::Query { kernel_only: true, unit: Some("-.none".into()), limit: 0, ..Default::default() };
                let boots = journal::query(&roots, &probe).boots;
                match journal::boot_by_offset(&boots, &current, boot) {
                    Some(b) => q.boot_id = Some(b),
                    None => return (journal::Result_ { entries: vec![], truncated: false, boots }, current),
                }
            }
            (journal::query(&roots, &q), current)
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        let (res, current) = res;
        let mut redactions = 0;
        let entries = res
            .entries
            .iter()
            .map(|e| {
                let raw = e.get("MESSAGE").unwrap_or("");
                let (message, n) = if redact { journal::redact(raw, &known) } else { (journal::clip(raw.to_string()), 0) };
                redactions += n;
                pb::JournalEntry {
                    realtime_usec: e.realtime_usec as i64,
                    priority: e.get("PRIORITY").and_then(|p| p.parse().ok()).unwrap_or(6),
                    unit: e.get("_SYSTEMD_UNIT").unwrap_or("").to_string(),
                    identifier: e.get("SYSLOG_IDENTIFIER").or(e.get("_COMM")).unwrap_or("").to_string(),
                    pid: e.get("_PID").and_then(|p| p.parse().ok()).unwrap_or(0),
                    message,
                }
            })
            .collect();
        let cur_idx = res.boots.iter().position(|b| b.0 == current).unwrap_or(res.boots.len().saturating_sub(1)) as i32;
        let boots = res
            .boots
            .iter()
            .enumerate()
            .filter(|(i, _)| *i as i32 <= cur_idx)
            .map(|(i, b)| pb::BootInfo { offset: i as i32 - cur_idx, boot_id: b.0.clone(), first_realtime_usec: b.1 as i64 })
            .collect();
        Ok(pb::ReadJournalResponse { entries, truncated: res.truncated, redactions, boots })
    }
}

const DUMP_DEFAULT_ENTRIES: u32 = 5000;
const DUMP_MAX_ENTRIES: u32 = 20000;
/// Under tonic's default 4 MiB decode limit with the per-entry overhead.
const DUMP_MAX_BYTES: usize = 3 * 1024 * 1024;

/// Keep the newest entries whose messages fit in `max` bytes; true if any were dropped.
pub fn bound_bytes(mut entries: Vec<pb::JournalEntry>, max: usize) -> (Vec<pb::JournalEntry>, bool) {
    let mut sum = 0usize;
    let mut keep = 0;
    for e in entries.iter().rev() {
        if sum + e.message.len() > max {
            break;
        }
        sum += e.message.len();
        keep += 1;
    }
    let cut = keep < entries.len();
    entries.drain(..entries.len() - keep);
    (entries, cut)
}

#[tonic::async_trait]
impl NodeAgent for Agent {
    async fn get_info(&self, req: Request<pb::GetInfoRequest>) -> Result<Response<pb::GetInfoResponse>, Status> {
        authz::caller(&req)?;
        let osr = system::os_release();
        let generation = self.state.lock().await.generation;
        Ok(Response::new(pb::GetInfoResponse {
            hostname: system::hostname(),
            machine_id: system::read_trim("/etc/machine-id"),
            boot_id: system::read_trim("/proc/sys/kernel/random/boot_id"),
            booted: Some(pb::Version { image_version: osr.get("IMAGE_VERSION").cloned().unwrap_or_default() }),
            os_id: osr.get("ID").cloned().unwrap_or_default(),
            kernel_release: system::kernel_release(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
            profile: self.profile().await as i32,
            mode: AgentMode::Bridge as i32,
            secure_boot: system::secure_boot(),
            tpm_present: system::tpm_present(),
            config_generation: generation,
            uptime_seconds: system::uptime_seconds(),
            var_protection: system::var_protection() as i32,
            api: crate::API.into(),
        }))
    }

    async fn get_health(&self, req: Request<pb::GetHealthRequest>) -> Result<Response<pb::GetHealthResponse>, Status> {
        authz::caller(&req)?;
        let checks = system::health(self.profile().await).await;
        Ok(Response::new(pb::GetHealthResponse {
            overall: system::overall(&checks) as i32,
            checks,
            boot: Some(self.boot_state().await),
        }))
    }

    async fn get_config(&self, req: Request<pb::GetConfigRequest>) -> Result<Response<pb::GetConfigResponse>, Status> {
        authz::caller(&req)?;
        let s = self.state.lock().await;
        Ok(Response::new(pb::GetConfigResponse {
            generation: s.generation,
            config: s.config.as_ref().map(config::redacted),
            source: s.source as i32,
        }))
    }

    async fn validate_config(
        &self,
        req: Request<pb::ValidateConfigRequest>,
    ) -> Result<Response<pb::ValidateConfigResponse>, Status> {
        authz::caller(&req)?;
        let c = req.into_inner().config.ok_or_else(|| Status::invalid_argument("config required"))?;
        let errors = config::validate(&c);
        Ok(Response::new(pb::ValidateConfigResponse { valid: errors.is_empty(), errors }))
    }

    async fn apply_config(&self, req: Request<pb::ApplyConfigRequest>) -> Result<Response<pb::ApplyConfigResponse>, Status> {
        authz::caller(&req)?;
        let r = req.into_inner();
        let c = r.config.ok_or_else(|| Status::invalid_argument("config required"))?;
        let errors = config::validate(&c);
        if !errors.is_empty() {
            let msg: Vec<_> = errors.iter().map(|e| format!("{}: {}", e.field, e.message)).collect();
            return Err(Status::invalid_argument(msg.join("; ")));
        }
        let mut s = self.state.lock().await;
        if r.expected_generation != s.generation {
            return Err(Status::failed_precondition(format!(
                "generation is {}, expected {}",
                s.generation, r.expected_generation
            )));
        }
        if let Some(e) = role_change(s.config.as_ref(), &c) {
            return Err(Status::failed_precondition(e));
        }
        let generation = s.generation + 1;
        // against the booted section: applying a change and then undoing it before a reboot needs none
        let reboot_required = s.booted_k8s != k8s_fingerprint(c.k8s.as_ref());
        // Render, then persist, then activate: a failed render or write leaves
        // the previous generation on disk and its files in /run (nothing was
        // activated yet), so the node keeps running and reboots into it.
        let restore = |what: &str, e: std::io::Error| {
            match s.config.as_ref() {
                Some(o) => {
                    if let Err(e2) = render_live(&self.paths, o, s.generation) {
                        tracing::error!("{what} failed, restoring generation {} in /run also failed: {e2}", s.generation);
                    }
                }
                None => tracing::warn!("{what} failed; no API config to restore in /run (bridge files stay partly overwritten until reboot)"),
            }
            tracing::error!(generation, "config {what} failed, generation {} kept: {e}", s.generation);
            Status::internal(format!("{what}: {e}"))
        };
        let time_changed = match render_live(&self.paths, &c, generation) {
            Ok(t) => t,
            Err(e) => return Err(restore("apply", e)),
        };
        if let Err(e) = config::save(&self.paths, generation, &c) {
            return Err(restore("persist", e));
        }
        activate(&self.paths, &c, time_changed, false);
        // consumers of /run/foilbird/config read the source there too (was left at "bridge")
        if let Err(e) = config::write_atomic(&self.paths.config_dir.join("source"), b"api\n", 0o644) {
            tracing::warn!("config source file: {e}");
        }
        if s.config.as_ref().map(|o| &o.update_channel) != Some(&c.update_channel) {
            self.stager.set_override(c.update_channel.as_ref());
        }
        s.generation = generation;
        s.config = Some(c);
        s.source = ConfigSource::Api;
        tracing::info!(generation, "config applied");
        Ok(Response::new(pb::ApplyConfigResponse { generation, reboot_required }))
    }

    async fn stage_update(&self, req: Request<pb::StageUpdateRequest>) -> Result<Response<pb::StageUpdateResponse>, Status> {
        authz::caller(&req)?;
        let v = req.into_inner().target.map(|v| v.image_version).unwrap_or_default();
        if let Some(op) = self.ops.running().await {
            return Err(Status::failed_precondition(format!("a {op} is running")));
        }
        if let Some(rb) = self.rollback.lock().await.as_ref() {
            if rb.from.as_ref().map(|f| f.image_version.as_str()) == Some(v.as_str()) {
                tracing::warn!(target: "audit", version = %v, "stage-update refused: rolled back on this node");
                return Err(Status::failed_precondition(format!(
                    "STAGE_ERROR_ROLLED_BACK: {v} was rolled back on this node ({}); stage a newer release",
                    rb.reason
                )));
            }
        }
        match self.stager.start(&v).await {
            Ok(operation_id) => Ok(Response::new(pb::StageUpdateResponse { operation_id })),
            Err(update::Refusal::Busy) => Err(Status::failed_precondition("an update is being staged")),
            Err(update::Refusal::Invalid(m)) => Err(Status::invalid_argument(m)),
            Err(update::Refusal::Policy(e, m)) => Err(Status::failed_precondition(format!("{}: {m}", e.as_str_name()))),
        }
    }

    async fn get_update_status(
        &self,
        req: Request<pb::GetUpdateStatusRequest>,
    ) -> Result<Response<pb::GetUpdateStatusResponse>, Status> {
        authz::caller(&req)?;
        let p = &self.stager.policy;
        let stage = self.stager.state.lock().await.stage.clone();
        Ok(Response::new(pb::GetUpdateStatusResponse {
            booted: Some(pb::Version { image_version: p.booted.clone() }),
            slots: self.stager.platform.slots().await,
            stage,
            boot: Some(self.boot_state().await),
            min_version: Some(pb::Version { image_version: p.floor() }),
            channel: Some(self.stager.current_channel().1),
            var_keys: Some(self.var_keys().await),
            operation: self.operation(),
        }))
    }

    async fn raise_min_version(
        &self,
        req: Request<pb::RaiseMinVersionRequest>,
    ) -> Result<Response<pb::RaiseMinVersionResponse>, Status> {
        let caller = authz::caller(&req)?;
        let want = req.into_inner().expect_booted.map(|v| v.image_version).unwrap_or_default();
        // rpc-cancel: the raise (its unit) runs to its end without this call; the same call meanwhile waits for it
        let stager = self.stager.clone();
        let (cn, roles, obo, v) = (caller.common_name.clone(), caller.roles(), caller.on_behalf_of.clone().unwrap_or_else(|| "-".into()), want.clone());
        let r = self
            .ops
            .run("raise-min-version", &want, async move {
                let before = stager.policy.floor();
                let r = stager.raise(&v).await.map_err(|e| {
                    let d = match e {
                        update::RaiseRefusal::NotBooted(d) | update::RaiseRefusal::NotCommitted(d) | update::RaiseRefusal::Busy(d) => d,
                    };
                    tracing::warn!(target: "audit", caller_cn = %cn, roles = %roles, on_behalf_of = %obo, expect_booted = %v, refused = %d, "raise-min-version");
                    (tonic::Code::FailedPrecondition, d)
                })?;
                let after = stager.policy.floor();
                tracing::warn!(
                    target: "audit",
                    caller_cn = %cn,
                    roles = %roles,
                    on_behalf_of = %obo,
                    version = %v,
                    phase = pb::KeyOpPhase::try_from(r.phase).map(|p| p.as_str_name()).unwrap_or("?"),
                    floor_before = %before,
                    floor_after = %after,
                    "raise-min-version"
                );
                if r.phase == pb::KeyOpPhase::Failed as i32 {
                    return Err((tonic::Code::Aborted, format!("raise failed: {}", r.detail)));
                }
                Ok(OpOk::Raise(pb::RaiseMinVersionResponse { min_version: Some(pb::Version { image_version: after }), raise: Some(r) }))
            })
            .await?;
        match r {
            OpOk::Raise(x) => Ok(Response::new(x)),
            _ => Err(Status::internal("raise-min-version: unexpected result")),
        }
    }

    async fn list_units(&self, req: Request<pb::ListUnitsRequest>) -> Result<Response<pb::ListUnitsResponse>, Status> {
        authz::caller(&req)?;
        let failed_only = req.into_inner().failed_only;
        type Row = (String, String, String, String, String, String, zbus::OwnedObjectPath, u32, String, zbus::OwnedObjectPath);
        let c = zbus::Connection::system().await.map_err(|e| Status::unavailable(e.to_string()))?;
        let rows: Vec<Row> = c
            .call_method(Some("org.freedesktop.systemd1"), "/org/freedesktop/systemd1", Some("org.freedesktop.systemd1.Manager"), "ListUnits", &())
            .await
            .map_err(|e| Status::unavailable(e.to_string()))?
            .body()
            .deserialize()
            .map_err(|e| Status::internal(e.to_string()))?;
        let mut units: Vec<pb::UnitStatus> = rows
            .into_iter()
            .filter(|r| !failed_only || r.3 == "failed")
            .map(|r| pb::UnitStatus { name: r.0, description: r.1, load_state: r.2, active_state: r.3, sub_state: r.4 })
            .collect();
        units.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Response::new(pb::ListUnitsResponse { units }))
    }

    async fn read_journal(&self, req: Request<pb::ReadJournalRequest>) -> Result<Response<pb::ReadJournalResponse>, Status> {
        authz::caller(&req)?;
        let r = req.into_inner();
        let unit = (!r.unit.is_empty()).then_some(r.unit);
        if unit.as_deref().is_some_and(|u| !journal::valid_unit(u)) {
            return Err(Status::invalid_argument("unit: name.type, e.g. kubelet.service"));
        }
        let q = journal::Query {
            unit,
            max_priority: r.max_priority,
            kernel_only: false,
            boot_id: None,
            since_usec: (r.since_unix.max(0) as u64).saturating_mul(1_000_000),
            until_usec: (r.until_unix.max(0) as u64).saturating_mul(1_000_000),
            limit: 0,
        };
        self.journal(q, r.boot, r.limit).await.map(Response::new)
    }

    async fn read_kernel_log(&self, req: Request<pb::ReadKernelLogRequest>) -> Result<Response<pb::ReadJournalResponse>, Status> {
        authz::caller(&req)?;
        let r = req.into_inner();
        let q = journal::Query { kernel_only: true, max_priority: r.max_priority, ..Default::default() };
        self.journal(q, r.boot, r.limit).await.map(Response::new)
    }

    async fn collect_diagnostics(
        &self,
        req: Request<pb::CollectDiagnosticsRequest>,
    ) -> Result<Response<pb::CollectDiagnosticsResponse>, Status> {
        let caller = authz::caller(&req)?;
        let r = req.into_inner();
        let limit = match r.max_entries {
            0 => DUMP_DEFAULT_ENTRIES,
            n => n.min(DUMP_MAX_ENTRIES),
        };
        let res = self.journal_with(journal::Query::default(), r.boot, limit, false).await;
        let res = match res {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "audit", caller_cn = %caller.common_name, roles = %caller.roles(), on_behalf_of = caller.on_behalf_of.as_deref().unwrap_or("-"), boot = r.boot, error = %e.message(), "emergency CollectDiagnostics refused");
                return Err(e);
            }
        };
        let (entries, cut) = bound_bytes(res.entries, DUMP_MAX_BYTES);
        let message_bytes: u64 = entries.iter().map(|e| e.message.len() as u64).sum();
        tracing::warn!(
            target: "audit",
            caller_cn = %caller.common_name,
            roles = %caller.roles(),
            on_behalf_of = caller.on_behalf_of.as_deref().unwrap_or("-"),
            boot = r.boot,
            entries = entries.len(),
            message_bytes,
            truncated = res.truncated || cut,
            "emergency CollectDiagnostics: unredacted journal returned"
        );
        Ok(Response::new(pb::CollectDiagnosticsResponse { entries, truncated: res.truncated || cut, message_bytes, boots: res.boots }))
    }

    async fn rollback(&self, req: Request<pb::RollbackRequest>) -> Result<Response<pb::RollbackResponse>, Status> {
        let caller = authz::caller(&req)?;
        let r = req.into_inner();
        let want = r.expect_booted.map(|v| v.image_version).unwrap_or_default();
        let mut reason = r.reason.replace(['\n', '\r'], " ");
        reason.truncate(200);
        let who = match &caller.on_behalf_of {
            Some(o) => format!("{} (on behalf of {o})", caller.common_name),
            None => caller.common_name.clone(),
        };
        let obo = caller.on_behalf_of.as_deref().unwrap_or("-");
        let refuse = |d: String| {
            tracing::warn!(target: "audit", caller_cn = %caller.common_name, roles = %caller.roles(), on_behalf_of = obo, expect_booted = %want, refused = %d, "rollback");
            Status::failed_precondition(d)
        };
        let p = &self.stager.policy;
        if want != p.booted {
            return Err(refuse(format!("booted version is {}, expected {want}", p.booted)));
        }
        if p.committed_at(&p.booted).is_none() {
            return Err(refuse(format!("{want} is not committed; before the commit the boot counter rolls back")));
        }
        {
            let st = self.stager.state.lock().await;
            if st.busy() {
                return Err(refuse("an update is being staged".into()));
            }
            // a staged release is the newest good entry; systemd-boot would boot it, not the previous one
            if let Some(v) = st.staged_version() {
                return Err(refuse(format!("release {v} is staged; systemd-boot would boot it instead of the previous release")));
            }
        }
        if let Err(e) = rollback::esp_rollback_layout(&self.paths.esp_linux(), &p.image_id, &p.booted) {
            return Err(refuse(e));
        }
        let Some((prev, uki)) = rollback::previous_release(&self.paths.esp_linux(), &p.image_id, &p.booted) else {
            return Err(refuse(format!("no previous release of {} older than {want} on the ESP", p.image_id)));
        };
        // T20b: an older release than the floor would not open /var after the reboot
        let floor = p.floor();
        if update::vercmp(&prev, &floor) == std::cmp::Ordering::Less {
            return Err(refuse(format!(
                "BELOW_MIN_VERSION: previous release {prev} is below the anti-rollback floor {floor}; once older epochs are wiped it would not open /var"
            )));
        }
        let check = {
            let (uki, prev) = (uki.clone(), prev.clone());
            tokio::task::spawn_blocking(move || std::fs::read(&uki).map_err(|e| e.to_string()).and_then(|d| rollback::check_uki(&d, &prev)))
                .await
                .map_err(|e| Status::internal(e.to_string()))?
        };
        if let Err(e) = check {
            return Err(refuse(format!("previous release {prev}: {}: {e}", uki.display())));
        }
        // the floor is FOILBIRD_MIN_VERSION of the booted release and may lag behind the wiped epochs;
        // the previous release must have a live /var key slot for its epoch (Rollback cannot enroll one)
        let guard = {
            let (uki, p, what) = (uki.clone(), p.clone(), format!("previous release {prev}"));
            tokio::task::spawn_blocking(move || {
                p.epoch_guard(&what, false, || std::fs::read(&uki).map_err(|e| e.to_string()).and_then(|d| rollback::uki_epoch(&d)))
            })
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        };
        let warning = match guard {
            update::EpochGuard::Pass => String::new(),
            update::EpochGuard::Refuse(d) => return Err(refuse(d)),
            update::EpochGuard::Unchecked(d) => {
                tracing::warn!(target: "audit", caller_cn = %caller.common_name, expect_booted = %want, to = %prev, warning = %d, "rollback: var-epoch guard");
                d
            }
        };
        let missing = rollback::missing_partitions(&self.paths.sys_block, &prev);
        if !missing.is_empty() {
            return Err(refuse(format!("previous release {prev}: partitions missing: {}", missing.join(", "))));
        }
        // The booted, committed entry is <id>_<N>.efi (no counter). <id>_<N>+0.efi without it: a rollback whose unit
        // finished while its call was gone (connection, agent restart); every check above passed again, so it is
        // completed without the unit (record, reboot). A counted name (+0-k: the boot counter's own rollback) or no
        // entry at all: refused, nothing is touched.
        let esp = self.paths.esp_linux();
        let resume = rollback_interrupted(&esp, &p.image_id, &want);
        if !resume && !esp.join(format!("{}_{want}.efi", p.image_id)).exists() {
            return Err(refuse(format!(
                "the booted entry {}_{want}.efi is not on the ESP and no {}_{want}+0.efi of an interrupted rollback: nothing to abandon",
                p.image_id, p.image_id
            )));
        }
        // From here on the operation runs to its end without this call (rpc-cancel): unit, record, reboot.
        let (stager, paths, cn, roles) = (self.stager.clone(), self.paths.clone(), caller.common_name.clone(), caller.roles());
        let (obo, v) = (obo.to_string(), want.clone());
        let r = self
            .ops
            .run("rollback", &want, async move {
                if resume {
                    tracing::warn!(target: "audit", caller_cn = %cn, expect_booted = %v, "rollback: the entry is already abandoned (interrupted rollback); recording and rebooting");
                } else {
                    let r = stager.platform.abandon(&v).await;
                    system::esp_names_changed();
                    if let Err(e) = r {
                        tracing::warn!(target: "audit", caller_cn = %cn, expect_booted = %v, error = %e, "rollback failed");
                        return Err((tonic::Code::Aborted, format!("rollback unit: {e}")));
                    }
                }
                let reason = if resume { format!("{reason} (completed after an interrupted rollback)") } else { reason };
                let boot_id = system::read_trim("/proc/sys/kernel/random/boot_id");
                rollback::record_operator(&paths, &v, &prev, &boot_id, unix_now().max(0) as u64, &who, &reason)
                    .map_err(|e| (tonic::Code::Internal, format!("record rollback: {e}")))?;
                tracing::warn!(target: "audit", caller_cn = %cn, roles = %roles, on_behalf_of = %obo, from = %v, to = %prev, reason = %reason, "rollback: rebooting into the previous release");
                stager.platform.reboot().await.map_err(|e| (tonic::Code::Internal, format!("reboot: {e}")))?;
                Ok(OpOk::Rollback(pb::RollbackResponse { from: Some(pb::Version { image_version: v }), to: Some(pb::Version { image_version: prev }), boot_id, warning }))
            })
            .await?;
        match r {
            OpOk::Rollback(x) => Ok(Response::new(x)),
            _ => Err(Status::internal("rollback: unexpected result")),
        }
    }

    async fn reboot(&self, req: Request<pb::RebootRequest>) -> Result<Response<pb::RebootResponse>, Status> {
        let caller = authz::caller(&req)?;
        let r = req.into_inner();
        if let Some(op) = self.ops.running().await {
            return Err(Status::failed_precondition(format!("a {op} is running")));
        }
        {
            let st = self.stager.state.lock().await;
            if st.busy() {
                return Err(Status::failed_precondition("an update is being staged"));
            }
            if let Some(want) = r.expect_staged.map(|v| v.image_version) {
                let staged = st.staged_version();
                if staged.as_deref() != Some(want.as_str()) {
                    return Err(Status::failed_precondition(format!(
                        "staged version is {}, expected {want}",
                        staged.as_deref().unwrap_or("none")
                    )));
                }
            }
        }
        let mut reason = r.reason;
        reason.truncate(200);
        tracing::warn!(target: "audit", caller_cn = %caller.common_name, roles = %caller.roles(), on_behalf_of = caller.on_behalf_of.as_deref().unwrap_or("-"), reason = %reason, "reboot");
        let boot_id = system::read_trim("/proc/sys/kernel/random/boot_id");
        if let Some(staged) = self.stager.state.lock().await.staged_version() {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            rollback::record_pending(&self.paths, &staged, &boot_id, now)
                .map_err(|e| Status::internal(format!("record pending boot: {e}")))?;
        }
        self.stager.platform.reboot().await.map_err(|e| Status::internal(format!("reboot: {e}")))?;
        Ok(Response::new(pb::RebootResponse { boot_id }))
    }
}

/// Best-effort D-Bus method call; failures are logged.
macro_rules! dbus_call {
    ($dest:expr, $path:expr, $iface:expr, $method:expr, $body:expr) => {{
        let r = async {
            let c = zbus::Connection::system().await?;
            c.call_method(Some($dest), $path, Some($iface), $method, $body).await?;
            Ok::<_, zbus::Error>(())
        }
        .await;
        if let Err(e) = r {
            tracing::warn!("{}.{}: {e}", $iface, $method);
        }
    }};
}

/// Render the files and activate them: early boot sets the host name by
/// syscall (no D-Bus yet); at run time hostnamed and networkd are asked over
/// D-Bus, so the API service needs no capabilities.
/// Render a configuration into /run (foilbird files, networkd, containerd hosts,
/// /run/foilbird/hosts, timesyncd drop-in); nothing is activated. True if the
/// timesyncd drop-in changed.
pub fn render_live(paths: &Paths, c: &pb::NodeConfig, generation: u64) -> std::io::Result<bool> {
    let files = config::render(c);
    let ifs = c.network.as_ref().map(|n| n.interfaces.clone()).unwrap_or_default();
    config::install(paths, &files, generation, &ifs)?;
    config::install_registries(paths, &c.registries)?;
    config::install_hosts(paths, &c.extra_host_entries)?;
    tracing::info!(registries = c.registries.len(), host_entries = c.extra_host_entries.len(), "containerd hosts and /run/foilbird/hosts rendered");
    let ntp: Vec<String> = c.time.as_ref().map(|t| t.servers.clone()).unwrap_or_default();
    let time_changed = config::install_time(paths, &ntp)?;
    if time_changed {
        tracing::info!(servers = %ntp.join(" "), "timesyncd drop-in rendered");
    }
    Ok(time_changed)
}

/// Make the rendered configuration take effect.
pub fn activate(paths: &Paths, c: &pb::NodeConfig, time_changed: bool, early_boot: bool) {
    if early_boot {
        if let Err(e) = config::set_hostname_syscall(paths, &c.hostname) {
            tracing::error!("sethostname: {e}");
        }
    } else if paths.live {
        // Activate after the RPC has answered: a new address may cut the
        // caller's connection.
        let name = c.hostname.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            dbus_call!("org.freedesktop.hostname1", "/org/freedesktop/hostname1", "org.freedesktop.hostname1", "SetStaticHostname", &(name.as_str(), false));
            dbus_call!("org.freedesktop.hostname1", "/org/freedesktop/hostname1", "org.freedesktop.hostname1", "SetHostname", &(name.as_str(), false));
            dbus_call!("org.freedesktop.network1", "/org/freedesktop/network1", "org.freedesktop.network1.Manager", "Reload", &());
            if time_changed {
                // early boot needs no restart: foil-config runs before timesyncd
                dbus_call!("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "RestartUnit", &("systemd-timesyncd.service", "replace"));
                tracing::info!("systemd-timesyncd restarted");
            }
            tracing::info!(hostname = %name, "configuration activated");
        });
    }
}

/// At boot (foil-config): render and set the host name.
pub async fn apply_live(paths: &Paths, c: &pb::NodeConfig, generation: u64, early_boot: bool) -> std::io::Result<()> {
    let time_changed = render_live(paths, c, generation)?;
    if early_boot {
        config::set_hostname_syscall(paths, &c.hostname)?;
    } else {
        activate(paths, c, time_changed, false);
    }
    Ok(())
}

/// The k8s section takes effect only at boot. kubeadm init/join run from foil-kubeadm-{init,join}.service,
/// whose ConditionPathExists on /run/foilbird/config/k8s.{init,join} is checked once per boot, and the kubelet flags are
/// rendered by foil-k8s-env.service before kubelet starts. So any change of the section, including the first time it
/// appears on a node that is already up (first Apply after a boot from the bridge or with no configuration), needs a
/// reboot; the agent does not start those units itself (as Talos: the first machine config is applied by a reboot).
/// An empty section counts as none.
pub fn k8s_reboot_required(old: Option<&pb::K8sConfig>, new: Option<&pb::K8sConfig>) -> bool {
    k8s_fingerprint(old) != k8s_fingerprint(new)
}

/// SHA-256 of a k8s section, "none" for no or an empty section. Secrets are inside the hash only (the file in /run
/// carries no token or key); labels are hashed in key order (a protobuf map has no stable encoding order).
/// The role is fixed for the life of an installation (alpha). Against the API config in force (a bridge boot has
/// none: its k8s counts as none, so the first ApplyConfig sets the role): changing CONTROL_PLANE <-> WORKER or
/// dropping k8s from a node with a role is refused; nothing is written, the generation stays. Pure, for tests.
pub fn role_change(old: Option<&pb::NodeConfig>, new: &pb::NodeConfig) -> Option<String> {
    let (o, n) = (config::role(old?), config::role(new));
    (o != pb::NodeRole::Unspecified && o != n).then(|| {
        format!(
            "role: {} -> {} needs a reinstall (alpha: the role of a node does not change)",
            o.as_str_name(),
            n.as_str_name()
        )
    })
}

pub fn k8s_fingerprint(k: Option<&pb::K8sConfig>) -> String {
    use prost::Message;
    use sha2::Digest;
    let Some(k) = k.filter(|k| **k != pb::K8sConfig::default()) else {
        return "none".into();
    };
    let mut k = k.clone();
    let labels: std::collections::BTreeMap<String, String> = std::mem::take(&mut k.node_labels).into_iter().collect();
    let mut h = sha2::Sha256::new();
    h.update(k.encode_to_vec());
    for (n, v) in &labels {
        h.update((n.len() as u64).to_le_bytes());
        h.update(n.as_bytes());
        h.update((v.len() as u64).to_le_bytes());
        h.update(v.as_bytes());
    }
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// /run/foilbird/booted-k8s, written once per boot by apply-boot from the configuration the boot runs with. Mode 0600:
/// an unsalted SHA-256 over the section with its token and key; only the agent (root) reads it.
pub const BOOTED_K8S: &str = "booted-k8s";

pub fn record_booted_k8s(paths: &Paths, k: Option<&pb::K8sConfig>) -> std::io::Result<()> {
    config::write_atomic(&paths.run_dir.join(BOOTED_K8S), format!("{}\n", k8s_fingerprint(k)).as_bytes(), 0o600)
}

/// The booted fingerprint for the server state: the record of this boot's apply-boot (an agent restarted after an
/// Apply still compares with the boot, not with that Apply); without a record, the persisted configuration's section.
pub fn booted_k8s(paths: &Paths, persisted: Option<&pb::NodeConfig>) -> String {
    match system::read_trim(paths.run_dir.join(BOOTED_K8S)) {
        f if f == "none" || f.starts_with("sha256:") => f,
        _ => k8s_fingerprint(persisted.and_then(|c| c.k8s.as_ref())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR 0016: Discovery does not depend on the agent's mode, configuration or /var. The handler holds nothing (a unit
    /// type: no mode, no state, no paths), so it answers the same in every AgentMode; called here without any Agent.
    #[tokio::test]
    async fn discovery_holds_no_mode_or_state() {
        use crate::discovery_pb::discovery_server::Discovery as _;
        assert_eq!(std::mem::size_of::<Discovery>(), 0);
        for mode in [AgentMode::Bridge, AgentMode::Operational, AgentMode::Registration] {
            let mut req = Request::new(crate::discovery_pb::GetApiVersionsRequest {});
            req.extensions_mut().insert(authz::Caller {
                method: format!("{}GetApiVersions", authz::DISCOVERY),
                level: pb::AccessLevel::Read,
                common_name: format!("mode {}", mode.as_str_name()),
                roles: vec![],
                on_behalf_of: None,
            });
            let r = Discovery.get_api_versions(req).await.unwrap().into_inner();
            assert_eq!(r.served_apis, vec![crate::API.to_string()], "{mode:?}");
            assert_eq!(r.agent_version, env!("CARGO_PKG_VERSION"), "{mode:?}");
        }
    }

    /// The role of an installation does not change through ApplyConfig.
    #[test]
    fn r2_role_change_refused() {
        let node = |r: pb::NodeRole, k8s: bool| pb::NodeConfig { role: r as i32, k8s: k8s.then(pb::K8sConfig::default), ..Default::default() };
        let (w, cp, none) = (node(pb::NodeRole::Worker, true), node(pb::NodeRole::ControlPlane, true), node(pb::NodeRole::Unspecified, false));
        // first role (no API config yet: bridge or nothing; or an API config without k8s)
        assert_eq!(role_change(None, &w), None);
        assert_eq!(role_change(None, &cp), None);
        assert_eq!(role_change(Some(&none), &w), None);
        assert_eq!(role_change(Some(&none), &none), None);
        // the same role
        assert_eq!(role_change(Some(&w), &w), None);
        assert_eq!(role_change(Some(&cp), &cp), None);
        // CP <-> WORKER, dropping k8s
        for (o, n) in [(&w, &cp), (&cp, &w), (&w, &none), (&cp, &none)] {
            let e = role_change(Some(o), n).expect("refused");
            assert!(e.contains("needs a reinstall"), "{e}");
        }
        assert!(role_change(Some(&w), &cp).unwrap().starts_with("role: NODE_ROLE_WORKER -> NODE_ROLE_CONTROL_PLANE"));
    }

    #[test]
    fn k8s_change_needs_reboot() {
        let join = pb::K8sConfig {
            api_server_endpoint: "192.0.2.10:6443".into(),
            bootstrap_token: Some(pb::SecretString { value: "abcdef.0123456789abcdef".into(), sha256: String::new() }),
            ca_cert_hashes: vec![format!("sha256:{}", "a".repeat(64))],
            ..Default::default()
        };
        let init = pb::K8sConfig {
            init: Some(pb::SecretString { value: "kind: InitConfiguration\n".into(), sha256: String::new() }),
            ..Default::default()
        };
        // first appearance on a running node (bridge or no config before): the units were already skipped this boot
        assert!(k8s_reboot_required(None, Some(&join)));
        assert!(k8s_reboot_required(None, Some(&init)));
        // changed: another token, labels (kubelet flags), role
        let mut j2 = join.clone();
        j2.bootstrap_token = Some(pb::SecretString { value: "bbbbbb.0123456789abcdef".into(), sha256: String::new() });
        assert!(k8s_reboot_required(Some(&join), Some(&j2)));
        let mut j3 = join.clone();
        j3.node_labels.insert("a".into(), "b".into());
        assert!(k8s_reboot_required(Some(&join), Some(&j3)));
        assert!(k8s_reboot_required(Some(&join), Some(&init)));
        assert!(k8s_reboot_required(Some(&join), None));
        // unchanged, or no k8s at all (an empty section is none)
        assert!(!k8s_reboot_required(Some(&join), Some(&join.clone())));
        assert!(!k8s_reboot_required(None, None));
        assert!(!k8s_reboot_required(None, Some(&pb::K8sConfig::default())));
        assert!(!k8s_reboot_required(Some(&pb::K8sConfig::default()), None));
        // label order does not matter
        let (mut l1, mut l2) = (join.clone(), join.clone());
        for (k, v) in [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")] {
            l1.node_labels.insert(k.into(), v.into());
        }
        for (k, v) in [("d", "4"), ("c", "3"), ("b", "2"), ("a", "1")] {
            l2.node_labels.insert(k.into(), v.into());
        }
        assert_eq!(k8s_fingerprint(Some(&l1)), k8s_fingerprint(Some(&l2)));
        // no secret value in the fingerprint
        let f = k8s_fingerprint(Some(&j2));
        assert!(f.starts_with("sha256:") && !f.contains("bbbbbb"), "{f}");
    }

    /// Booted fingerprint from this boot's record, else from the persisted configuration.
    #[test]
    fn booted_k8s_record_wins() {
        let root = std::env::temp_dir().join(format!("foil-booted-k8s-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let paths = Paths::with_root(root.clone());
        let a = pb::K8sConfig { api_server_endpoint: "192.0.2.1:6443".into(), ..Default::default() };
        let b = pb::K8sConfig { api_server_endpoint: "192.0.2.2:6443".into(), ..Default::default() };
        let persisted_b = pb::NodeConfig { k8s: Some(b.clone()), ..Default::default() };
        // no record (agent started outside apply-boot): the persisted section
        assert_eq!(booted_k8s(&paths, Some(&persisted_b)), k8s_fingerprint(Some(&b)));
        assert_eq!(booted_k8s(&paths, None), "none");
        // booted with A, B applied and persisted since, agent restarted: still A
        record_booted_k8s(&paths, Some(&a)).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(paths.run_dir.join(BOOTED_K8S)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "booted-k8s holds a hash over secrets: root only");
        }
        assert_eq!(booted_k8s(&paths, Some(&persisted_b)), k8s_fingerprint(Some(&a)));
        record_booted_k8s(&paths, None).unwrap();
        assert_eq!(booted_k8s(&paths, Some(&persisted_b)), "none");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn dump_bounds() {
        let e = |n: usize| pb::JournalEntry { message: "x".repeat(n), ..Default::default() };
        let (v, cut) = bound_bytes(vec![e(10), e(20), e(30)], 50);
        assert!(cut);
        assert_eq!(v.iter().map(|x| x.message.len()).collect::<Vec<_>>(), vec![20, 30]); // newest kept
        let (v, cut) = bound_bytes(vec![e(10), e(20)], 30);
        assert!(!cut);
        assert_eq!(v.len(), 2);
    }
}

/// Serve the API over mTLS until `shutdown` resolves. `tls_dir` holds
/// agent.tls-cert, agent.tls-key and agent.tls-ca (client CA) in PEM.
pub async fn run(
    paths: Paths,
    state: State,
    stager: Arc<update::Stager>,
    rollback: Option<pb::RollbackInfo>,
    listen: std::net::SocketAddr,
    tls_dir: &std::path::Path,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
    let rd = |n: &str| std::fs::read(tls_dir.join(n)).map_err(|e| format!("{n}: {e}"));
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(rd("agent.tls-cert")?, rd("agent.tls-key")?))
        .client_ca_root(Certificate::from_pem(rd("agent.tls-ca")?));
    if paths.live {
        // a pending update is done once its boot is confirmed
        let (p, booted) = (paths.clone(), stager.policy.booted.clone());
        tokio::spawn(async move {
            for _ in 0..180 {
                if rollback::pending_version(&p).is_none() {
                    return;
                }
                if system::boot_state(&p.run_dir).await.confirmation == pb::BootConfirmation::Confirmed as i32 {
                    rollback::confirm(&p, &booted);
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }
    if let Some(u) = state.config.as_ref().and_then(|c| c.update_channel.as_ref()) {
        stager.set_override(Some(u));
    }
    let agent = Agent { paths, state: Arc::new(Mutex::new(state)), stager, rollback: Arc::new(Mutex::new(rollback)), ops: Arc::default() };
    tracing::info!(%listen, "serving");
    Server::builder()
        .tls_config(tls)?
        // every response names the agent's API (compat): a client of another version can say so
        .layer(crate::compat::ApiHeaderLayer(crate::API))
        // authorization before any handler: no role or a role the RPC does not list -> denied; a path this agent
        // does not serve -> Unimplemented with its API (after the certificate checks)
        .layer(authz::AuthzLayer)
        .add_service(pb::node_agent_server::NodeAgentServer::new(agent))
        // Discovery (ADR 0016): no state, no configuration, no /var; answers in every mode the agent serves at all
        .add_service(crate::discovery_pb::discovery_server::DiscoveryServer::new(Discovery))
        .serve_with_shutdown(listen, shutdown)
        .await?;
    Ok(())
}

/// The release this agent reports in Discovery: the crate version only, never build features (Discovery answers any
/// client of the CA; lab features are not its business).
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Discovery (ADR 0016): stateless, so it answers whatever the agent's configuration, state or /var.
#[derive(Clone, Copy, Debug, Default)]
pub struct Discovery;

#[tonic::async_trait]
impl crate::discovery_pb::discovery_server::Discovery for Discovery {
    async fn get_api_versions(
        &self,
        req: Request<crate::discovery_pb::GetApiVersionsRequest>,
    ) -> Result<Response<crate::discovery_pb::GetApiVersionsResponse>, Status> {
        authz::caller(&req)?;
        Ok(Response::new(crate::discovery_pb::GetApiVersionsResponse { agent_version: AGENT_VERSION.into(), served_apis: vec![crate::API.into()] }))
    }
}
