// SPDX-License-Identifier: Apache-2.0
//! Authorization and Rollback end to end: real server over mTLS on localhost (authorization
//! layer in front of the router), a test root instead of /.
//!  * T12 ext: every RPC x every role (and a certificate without a role or
//!    without clientAuth) against the table generated from the .proto;
//!  * T20 (logic): Rollback of a committed release -> unit started, operator
//!    record written, reboot; T20b: previous release below the floor ->
//!    BELOW_MIN_VERSION before anything is touched.
mod common;
#[path = "common/authz_calls.rs"]
mod authz_calls;
use foil_agent::authz;
use foil_agent::config::Paths;
use foil_agent::pb::{self, node_agent_client::NodeAgentClient};
use foil_agent::rollback;
use foil_agent::server::{self, State};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use std::sync::Arc;
use tonic::Code;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

struct Pki {
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, "test ca");
        let key = KeyPair::generate().unwrap();
        let ca = p.self_signed(&key).unwrap();
        Pki { ca_pem: ca.pem(), issuer: Issuer::new(p, key) }
    }
    fn leaf(&self, cn: &str, ous: &[&str], eku: Vec<ExtendedKeyUsagePurpose>) -> (String, String) {
        let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        for ou in ous {
            p.distinguished_name.push(DnType::OrganizationalUnitName, *ou);
        }
        p.extended_key_usages = eku;
        let key = KeyPair::generate().unwrap();
        let c = p.signed_by(&key, &self.issuer).unwrap();
        (c.pem(), key.serialize_pem())
    }
}

async fn client(pki: &Pki, port: u16, ous: &[&str], eku: Vec<ExtendedKeyUsagePurpose>) -> NodeAgentClient<Channel> {
    let (crt, key) = pki.leaf("probe", ous, eku);
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&pki.ca_pem))
        .identity(Identity::from_pem(crt, key))
        .domain_name("localhost");
    let ch = Channel::from_shared(format!("https://127.0.0.1:{port}")).unwrap().tls_config(tls).unwrap().connect().await.unwrap();
    NodeAgentClient::new(ch)
}

struct Srv {
    port: u16,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

async fn start(pki: &Pki, root: &std::path::Path, stager: Arc<foil_agent::update::Stager>) -> Srv {
    let tls = root.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let (scrt, skey) = pki.leaf("localhost", &[], vec![ExtendedKeyUsagePurpose::ServerAuth]);
    std::fs::write(tls.join("agent.tls-cert"), scrt).unwrap();
    std::fs::write(tls.join("agent.tls-key"), skey).unwrap();
    std::fs::write(tls.join("agent.tls-ca"), &pki.ca_pem).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let paths = Paths::with_root(root.to_path_buf());
    let state = State { generation: 0, config: None, source: pb::ConfigSource::None, booted_k8s: "none".into() };
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        server::run(paths, state, stager, None, format!("127.0.0.1:{port}").parse().unwrap(), &tls, async {
            let _ = rx.await;
        })
        .await
        .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Srv { port, stop, task }
}

#[tokio::test(flavor = "multi_thread")]
async fn t12_ext_matrix_from_proto() {
    let root = common::tmp("authz-matrix");
    let pki = Pki::new();
    let mock = Arc::new(common::Mock::default());
    let stager = common::stager(common::fixtures().join("channel"), root.join("staging"), "0", mock.clone());
    let srv = start(&pki, &root, stager).await;
    let table: Vec<_> = authz::table().collect();
    assert_eq!(table.len(), 14);
    let ca = || vec![ExtendedKeyUsagePurpose::ClientAuth];
    for role in ["reader", "diag", "updater", "configurer", "controller", "operator"] {
        let mut c = client(&pki, srv.port, &[role], ca()).await;
        let got = authz_calls::probe(&mut c).await;
        assert_eq!(got.len(), table.len());
        for (m, o) in got {
            let (_, _, allowed) = table.iter().find(|(p, _, _)| p.ends_with(&format!("/{m}"))).unwrap_or_else(|| panic!("{m} not in table"));
            let want = allowed.contains(&authz::role_from_ou(role).unwrap());
            assert!(o != authz_calls::Outcome::Error, "{role} {m}: transport error is not an authorization result");
            assert_eq!(matches!(o, authz_calls::Outcome::Allow(_)), want, "{role} {m}: {o:?}");
        }
    }
    // no known OU, no OU, no EKU extension at all (rustls accepts it; the layer does not), even with OU=operator:
    // PermissionDenied everywhere
    for (ous, eku) in [(vec!["workload"], ca()), (vec![], ca()), (vec!["operator"], vec![])] {
        let mut c = client(&pki, srv.port, &ous, eku).await;
        for (m, o) in authz_calls::probe(&mut c).await {
            assert_eq!(o, authz_calls::Outcome::Deny(Code::PermissionDenied), "{ous:?} {m}");
        }
    }
    // EKU without clientAuth (serverAuth only): refused already by rustls in the handshake
    let mut c = client(&pki, srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ServerAuth]).await;
    for (m, o) in authz_calls::probe(&mut c).await {
        assert_eq!(o, authz_calls::Outcome::Error, "serverAuth-only {m}: {o:?}");
    }
    // the on-behalf-of metadata never adds a role
    let mut c = client(&pki, srv.port, &["diag"], ca()).await;
    let mut req = tonic::Request::new(pb::RebootRequest { reason: "x".into(), expect_staged: None });
    req.metadata_mut().insert("x-foilbird-on-behalf-of", "operator".parse().unwrap());
    assert_eq!(c.reboot(req).await.unwrap_err().code(), Code::PermissionDenied);
    // nothing destructive happened
    assert_eq!(mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(mock.abandons.lock().unwrap().is_empty());
    let _ = srv.stop.send(());
    srv.task.await.unwrap();
}

/// Minimal signed-looking PE32+ UKI (the agent's structural check).
fn uki(version: &str) -> Vec<u8> {
    let secs: [(&str, Vec<u8>); 4] = [
        (".osrel", format!("ID=foilbird\nIMAGE_VERSION={version}\nFOILBIRD_PCR_EPOCH=1\n").into_bytes()),
        (".cmdline", b"usrhash=00 ro".to_vec()),
        (".linux", vec![1; 16]),
        (".initrd", vec![2; 16]),
    ];
    let (pe, opt_size) = (0x80usize, 240usize);
    let mut b = vec![0u8; pe + 24 + opt_size + 40 * secs.len()];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
    b[pe..pe + 4].copy_from_slice(b"PE\0\0");
    b[pe + 6..pe + 8].copy_from_slice(&(secs.len() as u16).to_le_bytes());
    b[pe + 20..pe + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt = pe + 24;
    b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    b[opt + 148..opt + 152].copy_from_slice(&8u32.to_le_bytes());
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

#[tokio::test(flavor = "multi_thread")]
async fn t20_rollback_logic() {
    let root = common::tmp("authz-rollback");
    let pki = Pki::new();
    let paths = Paths::with_root(root.clone());
    let foilbird = paths.foilbird_state.clone();
    std::fs::create_dir_all(foilbird.join("committed")).unwrap();
    let esp = paths.esp_linux();
    std::fs::create_dir_all(&esp).unwrap();
    // booted "1" (common::stager), committed; previous "0.9" on the ESP and on disk
    // the booted, committed entry: no counter (bless removed it)
    std::fs::write(esp.join("foilbird_1.efi"), uki("1")).unwrap();
    std::fs::write(esp.join("foilbird_0.9+3.efi"), uki("0.9")).unwrap();
    std::fs::write(esp.join(rollback::RECOVERY_UKI), b"MZ").unwrap();
    for (d, n) in [("vda2", "usr_0.9"), ("vda3", "usr-verity_0.9"), ("vda4", "usr-verity-sig_0.9")] {
        std::fs::create_dir_all(paths.sys_block.join(d)).unwrap();
        std::fs::write(paths.sys_block.join(d).join("uevent"), format!("DEVTYPE=partition\nPARTNAME={n}\n")).unwrap();
    }
    let mock = Arc::new(common::Mock::default());
    let stager = common::stager_with(common::fixtures().join("channel"), root.join("staging"), "0", mock.clone(), Some(foilbird.clone()));
    let srv = start(&pki, &root, stager.clone()).await;
    let mut c = client(&pki, srv.port, &["controller"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    let rb = |v: &str| pb::RollbackRequest { expect_booted: Some(pb::Version { image_version: v.into() }), reason: "t20".into() };

    // not committed yet -> refused, nothing started
    let e = c.rollback(rb("1")).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert!(e.message().contains("not committed"), "{}", e.message());
    std::fs::write(foilbird.join("committed/1"), b"").unwrap();
    // wrong expect_booted
    assert_eq!(c.rollback(rb("2")).await.unwrap_err().code(), Code::FailedPrecondition);

    // T20b: floor above the previous release -> BELOW_MIN_VERSION, slot untouched
    std::fs::write(foilbird.join("min_version"), "1\n").unwrap();
    let e = c.rollback(rb("1")).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert!(e.message().contains("BELOW_MIN_VERSION"), "{}", e.message());
    assert!(mock.abandons.lock().unwrap().is_empty());
    assert_eq!(mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 0);
    std::fs::remove_file(foilbird.join("min_version")).unwrap();

    // previous UKI damaged -> refused
    let good = std::fs::read(esp.join("foilbird_0.9+3.efi")).unwrap();
    std::fs::write(esp.join("foilbird_0.9+3.efi"), &good[..good.len() / 2]).unwrap();
    let e = c.rollback(rb("1")).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{e:?}");
    std::fs::write(esp.join("foilbird_0.9+3.efi"), &good).unwrap();

    let refused = |e: tonic::Status, what: &str| {
        assert_eq!(e.code(), Code::FailedPrecondition, "{what}: {e:?}");
        assert!(e.message().contains(what), "{what}: {}", e.message());
    };
    // no recovery UKI -> refused
    std::fs::remove_file(esp.join(rollback::RECOVERY_UKI)).unwrap();
    refused(c.rollback(rb("1")).await.unwrap_err(), "no recovery UKI");
    std::fs::write(esp.join(rollback::RECOVERY_UKI), b"MZ").unwrap();
    // a newer good release on the ESP -> refused; a bad one (abandoned earlier) is ignored below
    std::fs::write(esp.join("foilbird_2+3-0.efi"), uki("2")).unwrap();
    refused(c.rollback(rb("1")).await.unwrap_err(), "foilbird_2+3-0.efi");
    std::fs::rename(esp.join("foilbird_2+3-0.efi"), esp.join("foilbird_2+0.efi")).unwrap();
    // a staged release -> refused
    stager.state.lock().await.stage = Some(pb::StageStatus {
        operation_id: "op".into(),
        target: Some(pb::Version { image_version: "3".into() }),
        phase: pb::StagePhase::Staged as i32,
        error: pb::StageError::None as i32,
        detail: String::new(),
    });
    refused(c.rollback(rb("1")).await.unwrap_err(), "release 3 is staged");
    stager.state.lock().await.stage = None;
    // the previous release's epoch (1) has no /var key slot -> refused; with it -> allowed
    std::fs::write(foilbird.join("var-epochs"), "2\n").unwrap();
    refused(c.rollback(rb("1")).await.unwrap_err(), "EPOCH_NOT_ENROLLED: previous release 0.9 has epoch 1");
    std::fs::write(foilbird.join("var-epochs"), "1 2\n").unwrap();
    assert!(mock.abandons.lock().unwrap().is_empty(), "no unit started by a refusal");

    // T20: committed, previous present -> unit, record, reboot
    let r = c.rollback(rb("1")).await.unwrap().into_inner();
    assert_eq!(r.to.unwrap().image_version, "0.9");
    assert!(r.warning.is_empty(), "{}", r.warning);
    assert_eq!(*mock.abandons.lock().unwrap(), vec!["1".to_string()]);
    assert_eq!(mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 1);
    // next start on 0.9 (another boot): reported as OPERATOR
    let info = rollback::evaluate(&paths, "foilbird", "0.9", "next-boot", 1000).expect("rollback reported");
    assert_eq!(info.reason_code, pb::RollbackReason::Operator as i32);
    assert!(info.reason.contains("operator rollback by probe"), "{}", info.reason);

    // the reader may not roll back
    let mut rd = client(&pki, srv.port, &["reader"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    assert_eq!(rd.rollback(rb("1")).await.unwrap_err().code(), Code::PermissionDenied);
    let _ = srv.stop.send(());
    srv.task.await.unwrap();
}

/// rpc-cancel: a node ready for an operator rollback 1 -> 0.9 (as t20), and a server on it.
struct RbNode {
    paths: Paths,
    esp: std::path::PathBuf,
    mock: Arc<common::Mock>,
    srv: Srv,
    pki: Pki,
}

async fn rb_node(tag: &str, booted_entry: Option<&str>) -> RbNode {
    let root = common::tmp(tag);
    let pki = Pki::new();
    let paths = Paths::with_root(root.clone());
    let foilbird = paths.foilbird_state.clone();
    std::fs::create_dir_all(foilbird.join("committed")).unwrap();
    std::fs::write(foilbird.join("committed/1"), b"").unwrap();
    std::fs::write(foilbird.join("var-epochs"), "1\n").unwrap();
    let esp = paths.esp_linux();
    std::fs::create_dir_all(&esp).unwrap();
    if let Some(n) = booted_entry {
        std::fs::write(esp.join(n), uki("1")).unwrap();
    }
    std::fs::write(esp.join("foilbird_0.9+3.efi"), uki("0.9")).unwrap();
    std::fs::write(esp.join(rollback::RECOVERY_UKI), b"MZ").unwrap();
    for (d, n) in [("vda2", "usr_0.9"), ("vda3", "usr-verity_0.9"), ("vda4", "usr-verity-sig_0.9")] {
        std::fs::create_dir_all(paths.sys_block.join(d)).unwrap();
        std::fs::write(paths.sys_block.join(d).join("uevent"), format!("DEVTYPE=partition\nPARTNAME={n}\n")).unwrap();
    }
    let mock = Arc::new(common::Mock::default());
    *mock.abandon_esp.lock().unwrap() = Some(("foilbird".into(), esp.clone()));
    let stager = common::stager_with(common::fixtures().join("channel"), root.join("staging"), "0", mock.clone(), Some(foilbird));
    let srv = start(&pki, &root, stager).await;
    RbNode { paths, esp, mock, srv, pki }
}

fn rb(v: &str, why: &str) -> pb::RollbackRequest {
    pb::RollbackRequest { expect_booted: Some(pb::Version { image_version: v.into() }), reason: why.into() }
}

async fn operation(n: &RbNode) -> Option<pb::OperatorOperation> {
    let mut c = client(&n.pki, n.srv.port, &["reader"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    c.get_update_status(pb::GetUpdateStatusRequest {}).await.unwrap().into_inner().operation
}

/// The caller's connection drops while the rollback unit runs: the operation still records the rollback and reboots;
/// GetUpdateStatus shows it running (mid-operation, the caller gone) and a repeat of the same Rollback then joins it,
/// then done; the next boot reports an operator rollback.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_cancel_rollback_completes_without_its_caller() {
    let n = rb_node("rc-drop", Some("foilbird_1.efi")).await;
    *n.mock.unit_delay.lock().unwrap() = Some(std::time::Duration::from_millis(1500));
    let mut c = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    assert!(tokio::time::timeout(std::time::Duration::from_millis(300), c.rollback(rb("1", "drop"))).await.is_err(), "the call must still run");
    drop(c);
    let o = operation(&n).await.expect("operation shown");
    assert_eq!((o.kind.as_str(), o.phase), ("rollback", pb::OperationPhase::Running as i32), "{o:?}");
    // mid-operation, its caller gone: the same Rollback joins it and gets its answer; the unit runs once
    let mut again = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    let joined = again.rollback(rb("1", "repeat while running")).await.expect("joins the running rollback").into_inner();
    assert_eq!(joined.to.unwrap().image_version, "0.9");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(*n.mock.abandons.lock().unwrap(), vec!["1".to_string()]);
    assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 1, "rebooted although the caller was gone");
    assert!(n.esp.join("foilbird_1+0.efi").is_file());
    let o = operation(&n).await.unwrap();
    assert_eq!(o.phase, pb::OperationPhase::Done as i32, "{o:?}");
    let info = rollback::evaluate(&n.paths, "foilbird", "0.9", "next-boot", 1000).expect("rollback reported");
    assert_eq!(info.reason_code, pb::RollbackReason::Operator as i32, "{info:?}");
    let _ = n.srv.stop.send(());
}

/// The same call while the rollback runs waits for it and gets the same answer; the unit runs once. Another
/// operation meanwhile is refused.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_cancel_repeat_joins_the_running_rollback() {
    let n = rb_node("rc-join", Some("foilbird_1.efi")).await;
    *n.mock.unit_delay.lock().unwrap() = Some(std::time::Duration::from_millis(1000));
    let (mut a, mut b) = (
        client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await,
        client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await,
    );
    let first = tokio::spawn(async move { a.rollback(rb("1", "first")).await });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut r = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    let e = r.raise_min_version(pb::RaiseMinVersionRequest { expect_booted: Some(pb::Version { image_version: "1".into() }) }).await.unwrap_err();
    assert!(e.code() == Code::FailedPrecondition && e.message().contains("a rollback of 1 is running"), "{e:?}");
    let second = b.rollback(rb("1", "second")).await.unwrap().into_inner();
    let first = first.await.unwrap().unwrap().into_inner();
    assert_eq!(first.to, second.to);
    assert_eq!(first.boot_id, second.boot_id);
    assert_eq!(n.mock.abandons.lock().unwrap().len(), 1, "one unit for both calls");
    assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 1);
    let _ = n.srv.stop.send(());
}

/// The unit had finished but the agent never recorded it (call gone, agent restarted; in the release build also a panic:
/// panic = "abort", systemd restarts the agent): <N>+0.efi without <N>.efi. A new agent shows REBOOT_PENDING and
/// completes the rollback without the unit (record, reboot); a counted name (the boot counter's own rollback) is not
/// touched.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_cancel_rollback_resumes_after_an_agent_restart() {
    let n = rb_node("rc-resume", Some("foilbird_1+0.efi")).await;
    // a fresh agent: nothing of its own yet, the ESP says REBOOT_PENDING
    let o = operation(&n).await.expect("REBOOT_PENDING from the ESP");
    assert_eq!((o.kind.as_str(), o.phase), ("rollback", pb::OperationPhase::RebootPending as i32), "{o:?}");
    let mut c = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    let r = c.rollback(rb("1", "again")).await.unwrap().into_inner();
    assert_eq!(r.to.unwrap().image_version, "0.9");
    assert!(n.mock.abandons.lock().unwrap().is_empty(), "the unit is not started again");
    assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 1);
    let info = rollback::evaluate(&n.paths, "foilbird", "0.9", "next-boot", 1000).expect("rollback reported");
    assert!(info.reason.contains("completed after an interrupted rollback"), "{info:?}");
    assert_eq!(operation(&n).await.unwrap().phase, pb::OperationPhase::Done as i32);
    let _ = n.srv.stop.send(());

    // committed, a counted +0-k name and no <N>.efi: not REBOOT_PENDING (operation() reads the same files as resume,
    // not tries_left, which is 0 for +0-k as well)
    let n = rb_node("rc-counted", Some("foilbird_1+0-3.efi")).await;
    assert_eq!(operation(&n).await, None, "a counted name is not an interrupted rollback");
    let mut c = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    let e = c.rollback(rb("1", "counted")).await.unwrap_err();
    assert!(e.code() == Code::FailedPrecondition && e.message().contains("nothing to abandon"), "{e:?}");
    assert!(n.mock.abandons.lock().unwrap().is_empty());
    assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(n.esp.join("foilbird_1+0-3.efi").is_file(), "untouched");
    let _ = n.srv.stop.send(());
}

/// The reboot fails after the unit and the record: REBOOT_PENDING is shown; the same call again (the entry is now +0)
/// completes it without the unit.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_cancel_reboot_pending_is_shown_and_completed_by_a_repeat() {
    let n = rb_node("rc-reboot", Some("foilbird_1.efi")).await;
    *n.mock.reboot_fail.lock().unwrap() = Some("logind: no".into());
    let mut c = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    let e = c.rollback(rb("1", "first")).await.unwrap_err();
    assert!(e.message().starts_with("reboot: "), "{e:?}");
    let o = operation(&n).await.unwrap();
    assert_eq!(o.phase, pb::OperationPhase::RebootPending as i32, "{o:?}");
    *n.mock.reboot_fail.lock().unwrap() = None;
    c.rollback(rb("1", "again")).await.unwrap();
    assert_eq!(n.mock.abandons.lock().unwrap().len(), 1, "the unit ran once");
    assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(operation(&n).await.unwrap().phase, pb::OperationPhase::Done as i32);
    let _ = n.srv.stop.send(());
}

/// RaiseMinVersion: the caller drops while the unit runs; the raise ends Done (not Running for good) and a repeat is
/// allowed.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_cancel_raise_completes_and_is_not_stuck_running() {
    let n = rb_node("rc-raise", Some("foilbird_1.efi")).await;
    *n.mock.unit_delay.lock().unwrap() = Some(std::time::Duration::from_millis(1000));
    let raise = || pb::RaiseMinVersionRequest { expect_booted: Some(pb::Version { image_version: "1".into() }) };
    let mut c = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    assert!(tokio::time::timeout(std::time::Duration::from_millis(200), c.raise_min_version(raise())).await.is_err());
    drop(c);
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let mut rd = client(&n.pki, n.srv.port, &["reader"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    let us = rd.get_update_status(pb::GetUpdateStatusRequest {}).await.unwrap().into_inner();
    let k = us.var_keys.unwrap().raise.unwrap();
    assert_eq!(k.phase, pb::KeyOpPhase::Done as i32, "{k:?}");
    assert_eq!(us.operation.unwrap().phase, pb::OperationPhase::Done as i32);
    *n.mock.unit_delay.lock().unwrap() = None;
    let mut c = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
    c.raise_min_version(raise()).await.expect("a repeat is allowed");
    let _ = n.srv.stop.send(());
}

/// The rollback task panics (mock abandon), before the unit touched anything or after its rename: the call fails, the
/// slot is free (StageUpdate and Reboot are not refused as "running"), GetUpdateStatus shows FAILED "operation task
/// panicked", and the same Rollback again completes without harm: the usual path when the unit did not run, the resume
/// path (<N>+0.efi, no <N>.efi) when it did; the unit never runs twice.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_cancel_panicked_rollback_frees_the_slot() {
    for (tag, at) in [("rc-panic-before", common::PanicAt::Before), ("rc-panic-after", common::PanicAt::After)] {
        let n = rb_node(tag, Some("foilbird_1.efi")).await;
        *n.mock.abandon_panic.lock().unwrap() = Some(at);
        let mut c = client(&n.pki, n.srv.port, &["operator"], vec![ExtendedKeyUsagePurpose::ClientAuth]).await;
        let e = c.rollback(rb("1", "panic")).await.unwrap_err();
        assert!(e.code() == Code::Internal && e.message().contains("operation task panicked"), "{at:?}: {e:?}");
        let o = operation(&n).await.expect("operation shown");
        assert_eq!((o.kind.as_str(), o.phase), ("rollback", pb::OperationPhase::Failed as i32), "{at:?}: {o:?}");
        assert!(o.detail.contains("operation task panicked") && o.finished_unix > 0, "{at:?}: {o:?}");
        assert_eq!(n.esp.join("foilbird_1+0.efi").is_file(), at == common::PanicAt::After, "{at:?}");
        assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 0, "{at:?}");

        // the slot is free: StageUpdate reaches its own checks (0 is below the booted release), Reboot runs
        let e = c.stage_update(pb::StageUpdateRequest { target: Some(pb::Version { image_version: "0".into() }) }).await.unwrap_err();
        assert!(!e.message().contains("is running") && e.message().contains("older than the booted"), "{at:?}: {e:?}");
        c.reboot(pb::RebootRequest { reason: "after a panicked rollback".into(), expect_staged: None }).await.expect("reboot accepted");
        assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 1, "{at:?}");

        // the same Rollback again: completes, the unit ran at most once in all
        let r = c.rollback(rb("1", "again")).await.unwrap().into_inner();
        assert_eq!(r.to.unwrap().image_version, "0.9", "{at:?}");
        assert_eq!(n.mock.abandons.lock().unwrap().len(), 1, "{at:?}: one unit run");
        assert_eq!(n.mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 2, "{at:?}");
        assert!(n.esp.join("foilbird_1+0.efi").is_file() && !n.esp.join("foilbird_1.efi").exists(), "{at:?}");
        assert_eq!(operation(&n).await.unwrap().phase, pb::OperationPhase::Done as i32, "{at:?}");
        let info = rollback::evaluate(&n.paths, "foilbird", "0.9", "next-boot", 1000).expect("rollback reported");
        assert_eq!(info.reason.contains("completed after an interrupted rollback"), at == common::PanicAt::After, "{at:?}: {info:?}");
        let _ = n.srv.stop.send(());
    }
}
