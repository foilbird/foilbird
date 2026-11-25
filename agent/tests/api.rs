// SPDX-License-Identifier: Apache-2.0
//! End-to-end API test: real server over mTLS on localhost, a test root
//! instead of /, certificates from a throw-away CA.
mod common;
use foil_agent::config::Paths;
use foil_agent::pb::{self, interface, node_agent_client::NodeAgentClient};
use foil_agent::server::{self, State};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use std::path::{Path, PathBuf};
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
    fn leaf(&self, san: &str, ou: Option<&str>, eku: ExtendedKeyUsagePurpose) -> (String, String) {
        let mut p = CertificateParams::new(vec![san.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, san);
        if let Some(ou) = ou {
            p.distinguished_name.push(DnType::OrganizationalUnitName, ou);
        }
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate().unwrap();
        let c = p.signed_by(&key, &self.issuer).unwrap();
        (c.pem(), key.serialize_pem())
    }
}

async fn client(pki: &Pki, port: u16, ou: Option<&str>) -> Result<NodeAgentClient<Channel>, tonic::transport::Error> {
    let (crt, key) = pki.leaf("client", ou, ExtendedKeyUsagePurpose::ClientAuth);
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&pki.ca_pem))
        .identity(Identity::from_pem(crt, key))
        .domain_name("localhost");
    let ch = Channel::from_shared(format!("https://127.0.0.1:{port}")).unwrap().tls_config(tls)?.connect().await?;
    Ok(NodeAgentClient::new(ch))
}

fn sample() -> pb::NodeConfig {
    pb::NodeConfig {
        schema: 1,
        hostname: "node-01".into(),
        network: Some(pb::NetworkConfig {
            interfaces: vec![pb::Interface {
                r#match: Some(interface::Match::Name("enp1s0".into())),
                dhcp4: true,
                ..Default::default()
            }],
        }),
        role: pb::NodeRole::Worker as i32,
        k8s: Some(pb::K8sConfig {
            api_server_endpoint: "192.0.2.1:6443".into(),
            bootstrap_token: Some(pb::SecretString { value: "abcdef.0123456789abcdef".into(), sha256: String::new() }),
            ca_cert_hashes: vec![format!("sha256:{}", "0".repeat(64))],
            node_labels: Default::default(),
            node_taints: vec![],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn tmp_root() -> PathBuf {
    let d = std::env::temp_dir().join(format!("foil-agent-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread")]
async fn api_over_mtls() {
    let root = tmp_root();
    let pki = Pki::new();
    let tls = root.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let (scrt, skey) = pki.leaf("localhost", None, ExtendedKeyUsagePurpose::ServerAuth);
    std::fs::write(tls.join("agent.tls-cert"), scrt).unwrap();
    std::fs::write(tls.join("agent.tls-key"), skey).unwrap();
    std::fs::write(tls.join("agent.tls-ca"), &pki.ca_pem).unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let paths = Paths::with_root(root.clone());
    let state = State { generation: 0, config: None, source: pb::ConfigSource::None, booted_k8s: "none".into() };
    let mock = std::sync::Arc::new(common::Mock::default());
    let stager = common::stager(common::fixtures().join("channel"), root.join("staging"), "0", mock.clone());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn({
        let tls = tls.clone();
        async move {
            server::run(paths, state, stager, None, format!("127.0.0.1:{port}").parse().unwrap(), &tls, async {
                let _ = rx.await;
            })
            .await
            .unwrap()
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // read with the controller role
    let mut c = client(&pki, port, Some("controller")).await.unwrap();
    let info = c.get_info(pb::GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.config_generation, 0);
    assert!(!info.agent_version.is_empty());

    // reader: READ only (no DIAG, no OPERATE/DESTRUCTIVE)
    let mut rd = client(&pki, port, Some("reader")).await.unwrap();
    assert!(rd.get_info(pb::GetInfoRequest {}).await.is_ok());
    assert!(rd.get_update_status(pb::GetUpdateStatusRequest {}).await.is_ok());
    for e in [
        rd.read_journal(pb::ReadJournalRequest::default()).await.unwrap_err(),
        rd.stage_update(pb::StageUpdateRequest { target: Some(pb::Version { image_version: "2".into() }) }).await.unwrap_err(),
        rd.reboot(pb::RebootRequest::default()).await.unwrap_err(),
        rd.apply_config(pb::ApplyConfigRequest { config: Some(sample()), expected_generation: 0 }).await.unwrap_err(),
    ] {
        assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");
    }

    // certificate without a role: connection is fine, every RPC denied
    let mut nobody = client(&pki, port, Some("workload")).await.unwrap();
    let e = nobody.get_info(pb::GetInfoRequest {}).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);

    // certificate from a foreign CA: TLS handshake or first call fails
    let other = Pki::new();
    let foreign = match client(&other, port, Some("operator")).await {
        Err(_) => true,
        Ok(mut f) => f.get_info(pb::GetInfoRequest {}).await.is_err(),
    };
    assert!(foreign, "foreign CA must be rejected");

    // invalid configuration
    let mut bad = sample();
    bad.hostname = "Bad Host".into();
    let v = c.validate_config(pb::ValidateConfigRequest { config: Some(bad.clone()) }).await.unwrap().into_inner();
    assert!(!v.valid && v.errors.iter().any(|e| e.field == "hostname"));
    let e = c.apply_config(pb::ApplyConfigRequest { config: Some(bad), expected_generation: 0 }).await.unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);

    // 7b: update_channel over plain http is not expressible; a scheme in the endpoint is rejected
    let mut http = sample();
    http.update_channel = Some(pb::UpdateChannel { endpoint: "http://192.0.2.1:8080".into(), prefix: "/".into(), ca_pem: pki.ca_pem.clone() });
    let e = c.apply_config(pb::ApplyConfigRequest { config: Some(http), expected_generation: 0 }).await.unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    assert!(e.message().contains("update_channel.endpoint"), "{}", e.message());
    let us = c.get_update_status(pb::GetUpdateStatusRequest {}).await.unwrap().into_inner();
    assert_eq!(us.channel.unwrap().origin, pb::ChannelOrigin::Image as i32, "rejected config leaves the image channel");

    // apply generation 1
    let r = c
        .apply_config(pb::ApplyConfigRequest { config: Some(sample()), expected_generation: 0 })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.generation, 1);
    // the first k8s section on a running node takes effect only after a reboot
    assert!(r.reboot_required, "first Apply with k8s.join must ask for a reboot");
    let cfg = root.join("run/foilbird/config");
    assert_eq!(std::fs::read_to_string(cfg.join("node.hostname")).unwrap(), "node-01\n");
    assert_eq!(std::fs::read_to_string(cfg.join("generation")).unwrap(), "1\n");
    assert_eq!(std::fs::read_to_string(cfg.join("source")).unwrap(), "api\n");
    let join = std::fs::read_to_string(cfg.join("k8s.join")).unwrap();
    assert!(join.contains("kind: JoinConfiguration") && join.contains("abcdef.0123456789abcdef"));
    assert_eq!(mode(&cfg.join("k8s.join")), 0o600);
    assert!(std::fs::read_to_string(root.join("run/systemd/network/50-foil-0.network")).unwrap().contains("DHCP=ipv4"));
    assert_eq!(mode(&root.join("var/lib/foil-agent/config.pb")), 0o600);

    // stale generation
    let e = c.apply_config(pb::ApplyConfigRequest { config: Some(sample()), expected_generation: 0 }).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);

    // GetConfig: secret redacted
    let g = c.get_config(pb::GetConfigRequest {}).await.unwrap().into_inner();
    assert_eq!(g.generation, 1);
    assert_eq!(g.source, pb::ConfigSource::Api as i32);
    let t = g.config.unwrap().k8s.unwrap().bootstrap_token.unwrap();
    assert!(t.value.is_empty() && t.sha256.len() == 64);

    // StageUpdate -> STAGED; Reboot guarded by expect_staged
    let v = |s: &str| Some(pb::Version { image_version: s.into() });
    let op = c.stage_update(pb::StageUpdateRequest { target: v("2") }).await.unwrap().into_inner().operation_id;
    let mut phase = 0;
    for _ in 0..100 {
        let s = c.get_update_status(pb::GetUpdateStatusRequest {}).await.unwrap().into_inner();
        let st = s.stage.unwrap();
        assert_eq!(st.operation_id, op);
        phase = st.phase;
        if phase == pb::StagePhase::Staged as i32 || phase == pb::StagePhase::Failed as i32 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(phase, pb::StagePhase::Staged as i32);
    let e = c.stage_update(pb::StageUpdateRequest { target: v("0") }).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{e:?}");
    let e = c.reboot(pb::RebootRequest { reason: "test".into(), expect_staged: v("9") }).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert_eq!(mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 0);
    c.reboot(pb::RebootRequest { reason: "test".into(), expect_staged: v("2") }).await.unwrap();
    assert_eq!(mock.reboots.load(std::sync::atomic::Ordering::SeqCst), 1);

    let _ = tx.send(());
    srv.await.unwrap();
    let _ = std::fs::remove_dir_all(&root);
}
