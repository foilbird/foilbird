// SPDX-License-Identifier: Apache-2.0
//! StageUpdate against a directory channel and a mock platform (decision 0002;
//! acceptance tests T3, T10).
mod common;
use common::*;
use foil_agent::pb::{StageError, StagePhase};
use foil_agent::update::{RaiseRefusal, Refusal};
use std::sync::Arc;

fn err(s: &foil_agent::pb::StageStatus) -> StageError {
    StageError::try_from(s.error).unwrap()
}

#[tokio::test]
async fn stages_a_verified_release() {
    let root = tmp("stage-ok");
    let mock = Arc::new(Mock::default());
    let s = stager(fixtures().join("channel"), root.join("staging"), "0", mock.clone());
    let op = s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.operation_id, op);
    assert_eq!(st.phase, StagePhase::Staged as i32, "{st:?}");
    let inst = mock.installs.lock().unwrap().clone();
    assert_eq!(inst.len(), 1);
    assert_eq!(inst[0].1, "2");
    assert_eq!(inst[0].0, root.join("staging/2"));
    assert_eq!(inst[0].2.len(), 6, "4 parts + manifest + signature: {:?}", inst[0].2);
    assert_eq!(std::fs::read_link(root.join("staging/current")).unwrap(), std::path::PathBuf::from("2"));
    // decision 0002 rule 2: no new update before the staged one is committed
    assert!(matches!(s.start("4").await, Err(Refusal::Policy(StageError::NotCommitted, _))));
    assert_eq!(s.state.lock().await.staged_version().as_deref(), Some("2"), "refusal must not replace the staged status");
}

#[tokio::test]
async fn t10_foreign_signature_is_refused() {
    let root = tmp("stage-t10");
    let ch = root.join("channel");
    std::fs::create_dir_all(&ch).unwrap();
    for e in std::fs::read_dir(fixtures().join("channel")).unwrap().flatten() {
        std::fs::copy(e.path(), ch.join(e.file_name())).unwrap();
    }
    std::fs::copy(fixtures().join("SHA256SUMS.other.gpg"), ch.join("SHA256SUMS.gpg")).unwrap();
    let mock = Arc::new(Mock::default());
    let s = stager(ch, root.join("staging"), "0", mock.clone());
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.phase, StagePhase::Failed as i32);
    assert_eq!(err(&st), StageError::BadSignature, "{st:?}");
    assert!(mock.installs.lock().unwrap().is_empty(), "slot must not be touched");
    assert_eq!(std::fs::read_dir(root.join("staging")).unwrap().count(), 0, "staging cleaned");
}

/// An older release than the booted one is refused before any
/// download; the floor is checked first (below it Rollback is no answer).
#[tokio::test]
async fn older_than_booted_is_refused_before_download() {
    let root = tmp("stage-older");
    let mock = Arc::new(Mock::default());
    // booted "1" (common::stager)
    let s = stager(fixtures().join("channel"), root.join("staging"), "0", mock.clone());
    match s.start("0.9").await {
        Err(Refusal::Policy(StageError::OlderThanBooted, d)) => assert!(d.contains("use Rollback"), "{d}"),
        Ok(_) => panic!("accepted an older release"),
        Err(_) => panic!("refused, but not OlderThanBooted"),
    }
    assert!(s.state.lock().await.stage.is_none(), "nothing started");
    assert!(!root.join("staging").join("0.9.partial").exists(), "nothing downloaded");
    assert!(mock.installs.lock().unwrap().is_empty());
    assert!(mock.key_ops.lock().unwrap().is_empty());
    // below the floor: the floor answers, not "use Rollback"
    let s = stager(fixtures().join("channel"), root.join("staging2"), "1", mock.clone());
    assert!(matches!(s.start("0.9").await, Err(Refusal::Policy(StageError::BelowMinVersion, _))));
    // forward still works
    let s = stager(fixtures().join("channel"), root.join("staging3"), "0", mock.clone());
    s.start("2").await.ok().expect("accepted");
}

#[tokio::test]
async fn t3_below_min_version_is_refused() {
    let root = tmp("stage-t3");
    let mock = Arc::new(Mock::default());
    let s = stager(fixtures().join("channel"), root.join("staging"), "3", mock.clone());
    assert!(matches!(s.start("2").await, Err(Refusal::Policy(StageError::BelowMinVersion, _))));
    assert!(s.state.lock().await.stage.is_none(), "nothing started");
    assert!(mock.installs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn refuses_incomplete_tampered_unknown_and_uncommitted() {
    let root = tmp("stage-bad");
    let mock = Arc::new(Mock::default());
    let s = stager(fixtures().join("channel"), root.join("staging"), "0", mock.clone());
    for (v, want) in [("3", StageError::Incomplete), ("4", StageError::HashMismatch), ("9", StageError::NotInChannel)] {
        s.start(v).await.ok().expect("accepted");
        let st = settle(&s).await;
        assert_eq!(err(&st), want, "version {v}: {st:?}");
    }
    assert!(mock.installs.lock().unwrap().is_empty());
    assert!(matches!(s.start("../2").await, Err(Refusal::Invalid(_))));
    assert!(matches!(s.start("1").await, Err(Refusal::Invalid(_))), "booted version");
    mock.unconfirmed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(s.start("2").await, Err(Refusal::Policy(StageError::NotCommitted, _))));
}

#[tokio::test]
async fn enroll_runs_before_install() {
    let root = tmp("stage-enroll");
    let mock = Arc::new(Mock::default());
    let s = stager(fixtures().join("channel"), root.join("staging"), "0", mock.clone());
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.phase, StagePhase::Staged as i32, "{st:?}");
    assert_eq!(*mock.key_ops.lock().unwrap(), vec![("enroll".to_string(), "2".to_string())]);
    assert_eq!(mock.installs.lock().unwrap().len(), 1);
    let e = s.state.lock().await.enroll.clone().unwrap();
    assert_eq!(e.phase, foil_agent::pb::KeyOpPhase::Done as i32);
}

#[tokio::test]
async fn failed_enroll_installs_nothing() {
    let root = tmp("stage-enroll-fail");
    let mock = Arc::new(Mock::default());
    *mock.key_fail.lock().unwrap() = Some(("enroll".into(), "refused: foilbird-deb_2.efi does not match SHA256SUMS".into()));
    let s = stager(fixtures().join("channel"), root.join("staging"), "0", mock.clone());
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.phase, StagePhase::Failed as i32);
    assert_eq!(err(&st), StageError::Enroll, "{st:?}");
    assert!(st.detail.contains("does not match"), "{st:?}");
    assert!(mock.installs.lock().unwrap().is_empty(), "no slot without a key slot");
    assert!(std::fs::symlink_metadata(root.join("staging/current")).is_err(), "current removed");
    assert!(!root.join("staging/2").exists(), "staged copy removed");
}

#[tokio::test]
async fn raise_preconditions_and_floor() {
    let root = tmp("raise");
    let foilbird = root.join("foilbird");
    std::fs::create_dir_all(foilbird.join("committed")).unwrap();
    let mock = Arc::new(Mock::default());
    *mock.raise_writes.lock().unwrap() = Some((foilbird.clone(), "3".into()));
    let s = stager_with(fixtures().join("channel"), root.join("staging"), "0", mock.clone(), Some(foilbird.clone()));
    assert!(matches!(s.raise("2").await, Err(RaiseRefusal::NotBooted(_))));
    assert!(matches!(s.raise("1").await, Err(RaiseRefusal::NotCommitted(_))), "no commit marker for 1");
    assert!(mock.key_ops.lock().unwrap().is_empty(), "refusals start no unit");
    assert_eq!(s.policy.floor(), "0");
    std::fs::write(foilbird.join("committed/1"), "").unwrap();
    let r = s.raise("1").await.expect("raise");
    assert_eq!(r.phase, foil_agent::pb::KeyOpPhase::Done as i32);
    assert_eq!(*mock.key_ops.lock().unwrap(), vec![("raise".to_string(), "1".to_string())]);
    assert_eq!(s.policy.floor(), "3", "floor written by the unit, read by the agent");
    // the raised floor refuses an older release (T3)
    assert!(matches!(s.start("2").await, Err(Refusal::Policy(StageError::BelowMinVersion, _))));
}

/// With var-epochs on the node the staged UKI's epoch must be
/// enrolled or newer than the booted one; else refused before enroll and install.
/// The fixture UKI is not a PE image: its epoch is unknown.
#[tokio::test]
async fn epoch_guard_refuses_before_enroll() {
    let root = tmp("stage-epoch");
    let foilbird = root.join("foilbird");
    std::fs::create_dir_all(&foilbird).unwrap();
    std::fs::write(foilbird.join("var-epochs"), "1\n").unwrap();
    let mock = Arc::new(Mock::default());
    let s = stager_with(fixtures().join("channel"), root.join("staging"), "0", mock.clone(), Some(foilbird.clone()));
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.phase, StagePhase::Failed as i32, "{st:?}");
    assert_eq!(err(&st), StageError::EpochNotEnrolled, "{st:?}");
    assert!(st.detail.starts_with("EPOCH_NOT_ENROLLED"), "{st:?}");
    assert!(mock.key_ops.lock().unwrap().is_empty(), "enroll not started");
    assert!(mock.installs.lock().unwrap().is_empty(), "nothing installed");
    assert!(std::fs::symlink_metadata(root.join("staging/current")).is_err());
    assert!(!root.join("staging/2").exists() && !root.join("staging/2.partial").exists(), "staging cleaned");
    // no var-epochs (node encrypted before var-epoch is told apart by var_protection; here not LUKS2): staged as before
    std::fs::remove_file(foilbird.join("var-epochs")).unwrap();
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.phase, StagePhase::Staged as i32, "{st:?}");
    assert!(st.detail.is_empty(), "{st:?}");
}
