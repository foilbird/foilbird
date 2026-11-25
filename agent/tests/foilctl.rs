// SPDX-License-Identifier: Apache-2.0
//! foilctl whose stdout reader went away (`foilctl ... info | head -1`) ends
//! quietly - killed by SIGPIPE (shell status 141) or exit 0 - with no panic and
//! no core dump. Real agent over mTLS on localhost, certificates from a
//! throw-away CA, the foilctl binary of this build.
mod common;
use foil_agent::config::Paths;
use foil_agent::pb;
use foil_agent::server::{self, State};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

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

fn foilctl_info(port: u16, tls_dir: &std::path::Path, close_stdout: bool) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_foilctl"));
    c.args(["--addr", &format!("https://127.0.0.1:{port}"), "--tls-dir", tls_dir.to_str().unwrap(), "--server-name", "localhost", "info"]);
    let mut ch = c.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    if close_stdout {
        drop(ch.stdout.take());
    }
    ch.wait_with_output().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn r7_closed_stdout_is_not_a_panic() {
    let root = common::tmp("foilctl-epipe");
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, "test ca");
    let key = KeyPair::generate().unwrap();
    let ca_pem = p.self_signed(&key).unwrap().pem();
    let issuer = Issuer::new(p, key);

    let tls = root.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let (scrt, skey) = leaf(&issuer, "localhost", None, ExtendedKeyUsagePurpose::ServerAuth);
    std::fs::write(tls.join("agent.tls-cert"), scrt).unwrap();
    std::fs::write(tls.join("agent.tls-key"), skey).unwrap();
    std::fs::write(tls.join("agent.tls-ca"), &ca_pem).unwrap();
    let cli = root.join("cli");
    std::fs::create_dir_all(&cli).unwrap();
    let (ccrt, ckey) = leaf(&issuer, "client", Some("reader"), ExtendedKeyUsagePurpose::ClientAuth);
    std::fs::write(cli.join("client.crt"), ccrt).unwrap();
    std::fs::write(cli.join("client.key"), ckey).unwrap();
    std::fs::write(cli.join("ca.crt"), &ca_pem).unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let paths = Paths::with_root(root.clone());
    let state = State { generation: 0, config: None, source: pb::ConfigSource::None, booted_k8s: "none".into() };
    let mock = std::sync::Arc::new(common::Mock::default());
    let stager = common::stager(common::fixtures().join("channel"), root.join("staging"), "0", mock);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(async move {
        server::run(paths, state, stager, None, format!("127.0.0.1:{port}").parse().unwrap(), &tls, async {
            let _ = rx.await;
        })
        .await
        .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // control: the same call with a reader prints the answer and exits 0
    let c = cli.clone();
    let ok = tokio::task::spawn_blocking(move || foilctl_info(port, &c, false)).await.unwrap();
    assert!(ok.status.success(), "{:?} {}", ok.status, String::from_utf8_lossy(&ok.stderr));
    assert!(String::from_utf8_lossy(&ok.stdout).contains("GetInfoResponse"));
    // the reader is gone before foilctl prints
    let out = tokio::task::spawn_blocking(move || foilctl_info(port, &cli, true)).await.unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() || out.status.signal() == Some(libc::SIGPIPE), "status {:?}, stderr: {err}", out.status);
    assert!(!out.status.core_dumped(), "{:?}", out.status);
    assert!(!err.contains("panicked"), "{err}");

    let _ = tx.send(());
    let _ = srv.await;
    let _ = std::fs::remove_dir_all(&root);
}

/// `foilctl apply` with k8s flags and no `--role` (or an unknown one) fails in the client, before any TLS file is
/// read or a connection is made (here: no TLS directory, nothing listening).
#[test]
fn r2_apply_needs_role_with_k8s_flags() {
    let run = |extra: &[&str]| {
        let mut a = vec!["--addr", "https://127.0.0.1:1", "--tls-dir", "/nonexistent-foil-tls", "--hostname", "n1", "--k8s-endpoint", "192.0.2.1:6443"];
        a.extend_from_slice(extra);
        a.push("apply");
        let o = Command::new(env!("CARGO_BIN_EXE_foilctl")).args(&a).output().unwrap();
        (o.status.success(), String::from_utf8_lossy(&o.stderr).to_string())
    };
    let (ok, err) = run(&[]);
    assert!(!ok && err.contains("--role worker|control-plane is required"), "{err}");
    let (ok, err) = run(&["--role", "master"]);
    assert!(!ok && err.contains("--role master: expected worker or control-plane"), "{err}");
    // with a role the client goes on: the next error is the missing TLS material, not the role
    let (ok, err) = run(&["--role", "worker"]);
    assert!(!ok && err.contains("ca.crt") && !err.contains("--role"), "{err}");
}
