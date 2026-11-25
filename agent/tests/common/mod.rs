// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use foil_agent::pb;
use foil_agent::update::{self, Platform};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Default)]
pub struct Mock {
    pub unconfirmed: AtomicBool,
    pub installs: Mutex<Vec<(PathBuf, String, Vec<String>)>>,
    pub reboots: AtomicUsize,
    /// var_epoch calls (op, version); outcome per op, default Done.
    pub key_ops: Mutex<Vec<(String, String)>>,
    pub key_fail: Mutex<Option<(String, String)>>, // (op, detail) -> Failed
    /// emulate the raise unit: write <dir>/min_version = this
    pub raise_writes: Mutex<Option<(PathBuf, String)>>,
    /// abandon (rollback unit) calls
    pub abandons: Mutex<Vec<String>>,
    /// emulate the rollback unit on this ESP dir: <image>_<v>.efi -> <image>_<v>+0.efi (image, dir)
    pub abandon_esp: Mutex<Option<(String, PathBuf)>>,
    /// a slow unit: abandon and var_epoch take this long
    pub unit_delay: Mutex<Option<std::time::Duration>>,
    /// reboot fails with this text
    pub reboot_fail: Mutex<Option<String>>,
    /// the next abandon panics (once): Before = before the unit touched anything, After = after the rename
    pub abandon_panic: Mutex<Option<PanicAt>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PanicAt {
    Before,
    After,
}

#[tonic::async_trait]
impl Platform for Mock {
    async fn boot_confirmed(&self) -> bool {
        !self.unconfirmed.load(Ordering::SeqCst)
    }
    async fn install(&self, staging: &Path, version: &str) -> Result<(), String> {
        let mut names: Vec<String> =
            std::fs::read_dir(staging).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        self.installs.lock().unwrap().push((staging.to_path_buf(), version.to_string(), names));
        Ok(())
    }
    async fn slots(&self) -> Vec<pb::Slot> {
        vec![]
    }
    async fn reboot(&self) -> Result<(), String> {
        if let Some(e) = self.reboot_fail.lock().unwrap().clone() {
            return Err(e);
        }
        self.reboots.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn var_epoch(&self, op: &str, version: &str) -> update::KeyOutcome {
        let d = *self.unit_delay.lock().unwrap();
        if let Some(d) = d {
            tokio::time::sleep(d).await;
        }
        self.key_ops.lock().unwrap().push((op.to_string(), version.to_string()));
        if let Some((o, d)) = self.key_fail.lock().unwrap().clone() {
            if o == op {
                return update::KeyOutcome { phase: pb::KeyOpPhase::Failed, detail: d };
            }
        }
        if op == "raise" {
            if let Some((dir, v)) = self.raise_writes.lock().unwrap().clone() {
                std::fs::write(dir.join("min_version"), format!("{v}\n")).unwrap();
            }
        }
        update::KeyOutcome { phase: pb::KeyOpPhase::Done, detail: format!("{op} {version} ok") }
    }
    async fn abandon(&self, version: &str) -> Result<(), String> {
        let d = *self.unit_delay.lock().unwrap();
        if let Some(d) = d {
            tokio::time::sleep(d).await;
        }
        // taken under the lock, panicked without it (no poisoned mutex for the rest of the test)
        let panic_at = self.abandon_panic.lock().unwrap().take();
        if panic_at == Some(PanicAt::Before) {
            panic!("mock abandon: panic before the unit");
        }
        self.abandons.lock().unwrap().push(version.to_string());
        if let Some((img, dir)) = self.abandon_esp.lock().unwrap().clone() {
            std::fs::rename(dir.join(format!("{img}_{version}.efi")), dir.join(format!("{img}_{version}+0.efi"))).map_err(|e| e.to_string())?;
        }
        if panic_at == Some(PanicAt::After) {
            panic!("mock abandon: panic after the unit");
        }
        Ok(())
    }
}

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("foil-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn stager(channel: PathBuf, staging: PathBuf, min: &str, mock: Arc<Mock>) -> Arc<update::Stager> {
    stager_with(channel, staging, min, mock, None)
}

pub fn stager_with(channel: PathBuf, staging: PathBuf, min: &str, mock: Arc<Mock>, foilbird: Option<PathBuf>) -> Arc<update::Stager> {
    let mock: Arc<dyn Platform> = mock;
    Arc::new(update::Stager {
        channel: Some(Arc::new(update::DirChannel(channel))),
        channel_override: Default::default(),
        platform: mock,
        policy: update::Policy {
            image_id: "foilbird".into(),
            booted: "1".into(),
            min_version: min.into(),
            foilbird_state: foilbird,
            keyring: Arc::new(std::fs::read(fixtures().join("release.pgp")).unwrap()),
            max_file: 1 << 20,
            booted_epoch: Some(1),
            var_luks2: false,
        },
        staging_root: staging,
        state: Default::default(),
    })
}

/// Wait until the operation leaves the busy phases; returns the status.
pub async fn settle(s: &update::Stager) -> pb::StageStatus {
    for _ in 0..200 {
        {
            let st = s.state.lock().await;
            if !st.busy() {
                return st.stage.clone().unwrap();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("stage did not settle: {:?}", s.state.lock().await.stage);
}
