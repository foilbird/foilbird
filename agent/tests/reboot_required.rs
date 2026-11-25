// SPDX-License-Identifier: Apache-2.0
//! ApplyConfig.reboot_required compares the k8s section with
//! the one the node booted with, not with the last applied generation. Booted
//! with generation 2 (k8s A): 3 = B -> true; 4 = A again -> false; 5 = A with
//! other labels -> true. Real server over mTLS on localhost, test root.
mod common;
use foil_agent::config::Paths;
use foil_agent::pb::{self, node_agent_client::NodeAgentClient};
use foil_agent::server::{self, State};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

fn leaf(issuer: &Issuer<'static, KeyPair>, san: &str, ou: Option<&str>, eku: ExtendedKeyUsagePurpose) -> (String, String) {
    let mut p = CertificateParams::new(vec![san.to_string()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, san);
    if let Some(ou) = ou {
        p.distinguished_name.push(DnType::OrganizationalUnitName, ou);
    }
    p.extended_key_usages = vec![eku];
    let key = KeyPair::generate().unwrap();
    let c = p.signed_by(&key, issuer).unwrap();
    (c.pem(), key.serialize_pem())
}

const CP_INIT: &str = "apiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\nbootstrapTokens:\n- token: \"abcdef.0123456789abcdef\"\n  ttl: 2h\n---\napiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n  - {name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}\n  - {name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}\n  extraVolumes:\n  - {name: audit-policy, hostPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, mountPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, readOnly: true, pathType: File}\n  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}\n---\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nshutdownGracePeriod: 60s\nshutdownGracePeriodCriticalPods: 20s\n";

fn node(endpoint: &str, labels: &[(&str, &str)]) -> pb::NodeConfig {
    pb::NodeConfig {
        schema: 1,
        hostname: "node-01".into(),
        network: Some(pb::NetworkConfig {
            interfaces: vec![pb::Interface { r#match: Some(pb::interface::Match::Name("enp1s0".into())), dhcp4: true, ..Default::default() }],
        }),
        role: pb::NodeRole::Worker as i32,
        k8s: Some(pb::K8sConfig {
            api_server_endpoint: endpoint.into(),
            bootstrap_token: Some(pb::SecretString { value: "abcdef.0123456789abcdef".into(), sha256: String::new() }),
            ca_cert_hashes: vec![format!("sha256:{}", "0".repeat(64))],
            node_labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn r10_reboot_required_against_the_booted_section() {
    let root = common::tmp("reboot-required");
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, "test ca");
    let key = KeyPair::generate().unwrap();
    let ca_pem = p.self_signed(&key).unwrap().pem();
    let ca_key_pem = key.serialize_pem();
    let issuer = Issuer::new(p, key);
    let tls = root.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let (scrt, skey) = leaf(&issuer, "localhost", None, ExtendedKeyUsagePurpose::ServerAuth);
    std::fs::write(tls.join("agent.tls-cert"), scrt).unwrap();
    std::fs::write(tls.join("agent.tls-key"), skey).unwrap();
    std::fs::write(tls.join("agent.tls-ca"), &ca_pem).unwrap();

    // booted with generation 2 = A: apply-boot recorded A in /run/foilbird/booted-k8s
    let a = node("192.0.2.1:6443", &[("zone", "a"), ("rack", "1")]);
    let paths = Paths::with_root(root.clone());
    server::record_booted_k8s(&paths, a.k8s.as_ref()).unwrap();
    let booted_k8s = server::booted_k8s(&paths, Some(&a));
    assert_eq!(booted_k8s, server::k8s_fingerprint(a.k8s.as_ref()));
    let state = State { generation: 2, config: Some(a.clone()), source: pb::ConfigSource::Api, booted_k8s };

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mock = std::sync::Arc::new(common::Mock::default());
    let stager = common::stager(common::fixtures().join("channel"), root.join("staging"), "0", mock);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn({
        let (paths, tls) = (paths.clone(), tls.clone());
        async move {
            server::run(paths, state, stager, None, format!("127.0.0.1:{port}").parse().unwrap(), &tls, async {
                let _ = rx.await;
            })
            .await
            .unwrap()
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (ccrt, ckey) = leaf(&issuer, "client", Some("controller"), ExtendedKeyUsagePurpose::ClientAuth);
    let ctls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_pem)).identity(Identity::from_pem(ccrt, ckey)).domain_name("localhost");
    let ch = Channel::from_shared(format!("https://127.0.0.1:{port}")).unwrap().tls_config(ctls).unwrap().connect().await.unwrap();
    let mut c = NodeAgentClient::new(ch);
    let mut try_apply = async |cfg: &pb::NodeConfig, expected: u64| {
        c.apply_config(pb::ApplyConfigRequest { config: Some(cfg.clone()), expected_generation: expected }).await.map(|r| r.into_inner())
    };
    macro_rules! apply {
        ($cfg:expr, $exp:expr) => {{
            let r = try_apply($cfg, $exp).await.unwrap();
            assert_eq!(r.generation, $exp + 1);
            r.reboot_required
        }};
    }

    let b = node("192.0.2.2:6443", &[("zone", "a"), ("rack", "1")]);
    assert!(apply!(&b, 2), "gen 3: k8s section changed from the booted one");
    assert!(!apply!(&a, 3), "gen 4 = gen 2: back to the booted section, no reboot");
    // the same section, labels given in another order: no reboot
    let a_reordered = node("192.0.2.1:6443", &[("rack", "1"), ("zone", "a")]);
    assert!(!apply!(&a_reordered, 4), "labels in another order are the same section");
    let a_labels = node("192.0.2.1:6443", &[("zone", "b"), ("rack", "1")]);
    assert!(apply!(&a_labels, 5), "gen 6: labels changed (kubelet flags)");
    // dropping k8s from a node with a role, or changing the role, needs a reinstall: refused, nothing written
    let pb0 = std::fs::read(paths.state_dir.join("config.pb")).unwrap();
    let mut no_k8s = a.clone();
    no_k8s.k8s = None;
    no_k8s.role = pb::NodeRole::Unspecified as i32;
    let e = try_apply(&no_k8s, 6).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::FailedPrecondition, "{e:?}");
    assert!(e.message().contains("WORKER -> NODE_ROLE_UNSPECIFIED") && e.message().contains("needs a reinstall"), "{}", e.message());
    let mut to_cp = a.clone();
    to_cp.role = pb::NodeRole::ControlPlane as i32;
    let k = to_cp.k8s.as_mut().unwrap();
    k.api_server_endpoint.clear();
    k.bootstrap_token = None;
    k.ca_cert_hashes.clear();
    k.init = Some(pb::SecretString { value: CP_INIT.into(), sha256: String::new() });
    k.cluster_ca_crt = ca_pem.clone();
    k.cluster_ca_key = Some(pb::SecretString { value: ca_key_pem.clone(), sha256: String::new() });
    let e = try_apply(&to_cp, 6).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::FailedPrecondition, "a valid control plane config on a worker: {e:?}");
    assert!(e.message().contains("WORKER -> NODE_ROLE_CONTROL_PLANE"), "{}", e.message());
    assert_eq!(std::fs::read(paths.state_dir.join("config.pb")).unwrap(), pb0, "config.pb unchanged after the refusals");
    // non-k8s change on top of the booted section: no reboot; the generation did not move (6 -> 7)
    let mut a_host = a.clone();
    a_host.hostname = "node-02".into();
    assert!(!apply!(&a_host, 6), "gen 7: only the hostname differs from the booted generation");

    // agent restarted within the same boot after gen 3 = B was persisted: still compared with the boot (A)
    assert_eq!(server::booted_k8s(&paths, Some(&b)), server::k8s_fingerprint(a.k8s.as_ref()));

    let _ = tx.send(());
    let _ = srv.await;
    let _ = std::fs::remove_dir_all(&root);
}
