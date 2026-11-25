// SPDX-License-Identifier: Apache-2.0
//! Agent and foilctl of different API versions (proto packages) say so.
//! The agent reports its API in GetInfo.api and in the header x-foilbird-api of
//! every response; a path of another package is Unimplemented naming the
//! agent's API; foilctl turns that into "the agent speaks X, foilctl speaks Y".
//! Real agent over mTLS on localhost, plus two stand-ins for an agent of
//! another API: one that reports it (header) and one that does not (an agent
//! before the version report: plain Unimplemented).
mod common;
use foil_agent::compat::{self, ApiHeaderLayer};
use foil_agent::config::Paths;
use foil_agent::pb::{self, node_agent_client::NodeAgentClient};
use foil_agent::server::{self, State};
use foil_agent::API;
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use std::path::{Path, PathBuf};
use std::process::Command;
use tonic::Code;
use tonic::codegen::http;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig};

struct Pki {
    root: PathBuf,
    ca: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Pki {
    fn new(name: &str) -> Pki {
        let root = common::tmp(name);
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, "test ca");
        let key = KeyPair::generate().unwrap();
        let ca = p.self_signed(&key).unwrap().pem();
        Pki { root, ca, issuer: Issuer::new(p, key) }
    }
    fn leaf(&self, san: &str, ou: Option<&str>, eku: ExtendedKeyUsagePurpose) -> (String, String) {
        let mut p = CertificateParams::new(vec![san.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, san);
        if let Some(ou) = ou {
            p.distinguished_name.push(DnType::OrganizationalUnitName, ou);
        }
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate().unwrap();
        (p.signed_by(&key, &self.issuer).unwrap().pem(), key.serialize_pem())
    }
    /// agent.tls-* for the server
    fn server_dir(&self) -> PathBuf {
        let d = self.root.join("tls");
        std::fs::create_dir_all(&d).unwrap();
        let (c, k) = self.leaf("localhost", None, ExtendedKeyUsagePurpose::ServerAuth);
        std::fs::write(d.join("agent.tls-cert"), c).unwrap();
        std::fs::write(d.join("agent.tls-key"), k).unwrap();
        std::fs::write(d.join("agent.tls-ca"), &self.ca).unwrap();
        d
    }
    /// client.crt/key + ca.crt for foilctl, role `ou` ("" = a certificate of the CA without a role)
    fn client_dir(&self, ou: &str) -> PathBuf {
        let d = self.root.join(format!("cli-{}", if ou.is_empty() { "norole" } else { ou }));
        std::fs::create_dir_all(&d).unwrap();
        let (c, k) = self.leaf("client", (!ou.is_empty()).then_some(ou), ExtendedKeyUsagePurpose::ClientAuth);
        std::fs::write(d.join("client.crt"), c).unwrap();
        std::fs::write(d.join("client.key"), k).unwrap();
        std::fs::write(d.join("ca.crt"), &self.ca).unwrap();
        d
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn channel(port: u16, cli: &Path) -> Channel {
    let rd = |n: &str| std::fs::read(cli.join(n)).unwrap();
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(rd("ca.crt")))
        .identity(Identity::from_pem(rd("client.crt"), rd("client.key")))
        .domain_name("localhost");
    Channel::from_shared(format!("https://127.0.0.1:{port}")).unwrap().tls_config(tls).unwrap().connect().await.unwrap()
}

fn foilctl(port: u16, cli: &Path, cmd: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_foilctl"))
        .args(["--addr", &format!("https://127.0.0.1:{port}"), "--tls-dir", cli.to_str().unwrap(), "--server-name", "localhost", cmd])
        .output()
        .unwrap()
}

/// Stand-in for an agent of another API: serves only `<api>.NodeAgent`, every call Unimplemented.
#[derive(Clone)]
struct Other(&'static str);

impl tonic::server::NamedService for Other {
    const NAME: &'static str = "foilbird.agent.v0.NodeAgent";
}

impl tower_service::Service<http::Request<tonic::body::Body>> for Other {
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: http::Request<tonic::body::Body>) -> Self::Future {
        std::future::ready(Ok(tonic::Status::unimplemented(format!("stand-in for {}", self.0)).into_http()))
    }
}

/// Serve the stand-in on `port`; with `report`, every response carries x-foilbird-api: foilbird.agent.v0.
fn serve_other(tls_dir: &Path, port: u16, report: bool) -> tokio::sync::oneshot::Sender<()> {
    let rd = |n: &str| std::fs::read(tls_dir.join(n)).unwrap();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(rd("agent.tls-cert"), rd("agent.tls-key")))
        .client_ca_root(Certificate::from_pem(rd("agent.tls-ca")));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let stop = async {
        let _ = rx.await;
    };
    let mut b = Server::builder().tls_config(tls).unwrap();
    if report {
        let f = b.layer(ApiHeaderLayer("foilbird.agent.v0")).add_service(Other("foilbird.agent.v0")).serve_with_shutdown(addr, stop);
        tokio::spawn(async move { f.await.unwrap() });
    } else {
        let f = b.add_service(Other("foilbird.agent.v0")).serve_with_shutdown(addr, stop);
        tokio::spawn(async move { f.await.unwrap() });
    }
    tx
}

#[tokio::test(flavor = "multi_thread")]
async fn r1_agent_reports_its_api() {
    let pki = Pki::new("api-compat-agent");
    let tls = pki.server_dir();
    let (reader, op) = (pki.client_dir("reader"), pki.client_dir("operator"));
    let port = free_port();
    let paths = Paths::with_root(pki.root.clone());
    let state = State { generation: 0, config: None, source: pb::ConfigSource::None, booted_k8s: "none".into() };
    let stager = common::stager(common::fixtures().join("channel"), pki.root.join("staging"), "0", Default::default());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(async move {
        server::run(paths, state, stager, None, format!("127.0.0.1:{port}").parse().unwrap(), &tls, async {
            let _ = rx.await;
        })
        .await
        .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let ch = channel(port, &reader).await;

    // Discovery (ADR 0016): any client of the CA, also one without a role; the agent's own version, no features; served
    // APIs = the agent's; the agent runs without a configuration and without /var (a temporary root)
    for ou in ["", "reader", "operator"] {
        let d = compat::discover(channel(port, &pki.client_dir(ou)).await).await.unwrap().expect("the agent serves Discovery");
        assert_eq!(d.agent_version, env!("CARGO_PKG_VERSION"), "role {ou:?}");
        assert!(!d.agent_version.contains("lab") && !d.agent_version.contains("esp"), "{}", d.agent_version);
        assert_eq!(d.served_apis, vec![API.to_string()], "role {ou:?}");
        assert!(compat::served(&d, API).is_ok());
        assert!(compat::served(&d, "foilbird.agent.v9").unwrap_err().contains(&format!("the agent speaks API {API}, foilctl speaks API foilbird.agent.v9")));
    }
    // a role-less certificate gets Discovery only
    let mut c = NodeAgentClient::new(channel(port, &pki.client_dir("")).await);
    assert_eq!(c.get_info(pb::GetInfoRequest {}).await.unwrap_err().code(), Code::PermissionDenied);

    // the one mode the agent serves in (ADR 0016): BRIDGE
    let r = compat::get_info(ch.clone(), API).await.unwrap();
    assert_eq!(r.get_ref().mode, pb::AgentMode::Bridge as i32);

    // own package: GetInfo.api and the header name the agent's API
    let r = compat::get_info(ch.clone(), API).await.unwrap();
    assert_eq!(compat::api_of(r.metadata()).as_deref(), Some(API));
    assert_eq!(r.into_inner().api, API);

    // another package: Unimplemented naming the agent's API (body and header), and foilctl's explanation
    let e = compat::get_info(ch.clone(), "foilbird.agent.v9").await.unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented, "{e:?}");
    assert!(e.message().contains(&format!("agent API {API}")), "{}", e.message());
    assert_eq!(compat::api_of(e.metadata()).as_deref(), Some(API));
    let m = compat::explain(&ch, &e, "foilbird.agent.v9").await.unwrap();
    assert!(m.contains(&format!("the agent speaks API {API}, foilctl speaks API foilbird.agent.v9")), "{m}");

    // a denied call carries the header too; it is not a version problem
    let mut c = NodeAgentClient::new(ch.clone());
    let e = c.reboot(pb::RebootRequest::default()).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    assert_eq!(compat::api_of(e.metadata()).as_deref(), Some(API));
    assert!(compat::explain(&ch, &e, API).await.is_none());
    // the operator's call works and is unchanged
    let mut c = NodeAgentClient::new(channel(port, &op).await);
    let r = c.get_update_status(pb::GetUpdateStatusRequest {}).await.unwrap();
    assert_eq!(compat::api_of(r.metadata()).as_deref(), Some(API));

    // foilctl of the same API: prints the API with the info
    let (p, r2) = (port, reader.clone());
    let out = tokio::task::spawn_blocking(move || foilctl(p, &r2, "info")).await.unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("api: \"{API}\"")), "{}", String::from_utf8_lossy(&out.stdout));

    let _ = tx.send(());
    let _ = srv.await;
    let _ = std::fs::remove_dir_all(&pki.root);
}

#[tokio::test(flavor = "multi_thread")]
async fn r1_foilctl_names_both_versions() {
    let pki = Pki::new("api-compat-other");
    let tls = pki.server_dir();
    let reader = pki.client_dir("reader");

    // agent of another API that reports it
    let port = free_port();
    let stop = serve_other(&tls, port, true);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let r = reader.clone();
    let out = tokio::task::spawn_blocking(move || foilctl(port, &r, "info")).await.unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success());
    assert!(err.contains(&format!("API version mismatch: the agent speaks API foilbird.agent.v0, foilctl speaks API {API}")), "{err}");
    let _ = stop.send(());

    // agent of another API that does not report it (before the version report): plain Unimplemented, no header
    let port = free_port();
    let stop = serve_other(&tls, port, false);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let r = reader.clone();
    let out = tokio::task::spawn_blocking(move || foilctl(port, &r, "health")).await.unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success());
    assert!(err.contains(&format!("API version mismatch: the agent does not serve API {API} and does not report its own")), "{err}");
    assert!(err.contains(&format!("foilctl speaks API {API}")), "{err}");
    assert!(err.contains("Unimplemented"), "{err}");
    let _ = stop.send(());
    let _ = std::fs::remove_dir_all(&pki.root);
}

/// Stand-in agent with Discovery that serves another API only (foilbird.agent.v0), release 9.9.9.
#[derive(Clone, Copy)]
struct OtherDiscovery;

#[tonic::async_trait]
impl foil_agent::discovery_pb::discovery_server::Discovery for OtherDiscovery {
    async fn get_api_versions(
        &self,
        _: tonic::Request<foil_agent::discovery_pb::GetApiVersionsRequest>,
    ) -> Result<tonic::Response<foil_agent::discovery_pb::GetApiVersionsResponse>, tonic::Status> {
        Ok(tonic::Response::new(foil_agent::discovery_pb::GetApiVersionsResponse { agent_version: "9.9.9".into(), served_apis: vec!["foilbird.agent.v0".into()] }))
    }
}

/// An agent whose Discovery does not list foilctl's API: refused from Discovery, before any NodeAgent call.
#[tokio::test(flavor = "multi_thread")]
async fn discovery_without_own_api_is_refused_first() {
    let pki = Pki::new("api-compat-discovery");
    let tls = pki.server_dir();
    let reader = pki.client_dir("reader");
    let rd = |n: &str| std::fs::read(tls.join(n)).unwrap();
    let stls = ServerTlsConfig::new()
        .identity(Identity::from_pem(rd("agent.tls-cert"), rd("agent.tls-key")))
        .client_ca_root(Certificate::from_pem(rd("agent.tls-ca")));
    let port = free_port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let f = Server::builder()
        .tls_config(stls)
        .unwrap()
        .add_service(foil_agent::discovery_pb::discovery_server::DiscoveryServer::new(OtherDiscovery))
        .add_service(Other("foilbird.agent.v0"))
        .serve_with_shutdown(format!("127.0.0.1:{port}").parse().unwrap(), async {
            let _ = rx.await;
        });
    tokio::spawn(async move { f.await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let r = reader.clone();
    let out = tokio::task::spawn_blocking(move || foilctl(port, &r, "info")).await.unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success());
    assert!(err.contains(&format!("API version mismatch: the agent speaks API foilbird.agent.v0, foilctl speaks API {API}")), "{err}");
    // from Discovery (it names the agent's release), not from a failed NodeAgent call (that would say Unimplemented)
    assert!(err.contains("(agent 9.9.9)") && !err.contains("Unimplemented"), "{err}");
    let _ = tx.send(());
    let _ = std::fs::remove_dir_all(&pki.root);
}

/// Discovery does not depend on the configuration or /var (ADR 0016): an agent without a configuration whose root has
/// no /var at all, and one whose /var is read-only, both answer GetApiVersions.
#[tokio::test(flavor = "multi_thread")]
async fn discovery_without_config_or_writable_var() {
    use std::os::unix::fs::PermissionsExt;
    let pki = Pki::new("api-compat-novar");
    let tls = pki.server_dir();
    let norole = pki.client_dir("");
    let missing = pki.root.join("root-without-var");
    let ro = pki.root.join("root-ro-var");
    std::fs::create_dir_all(ro.join("var/lib")).unwrap();
    std::fs::set_permissions(ro.join("var"), std::fs::Permissions::from_mode(0o555)).unwrap();
    for root in [missing, ro.clone()] {
        let port = free_port();
        let paths = Paths::with_root(root.clone());
        let state = State { generation: 0, config: None, source: pb::ConfigSource::None, booted_k8s: "none".into() };
        let stager = common::stager(common::fixtures().join("channel"), pki.root.join(format!("staging-{port}")), "0", Default::default());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let t = tls.clone();
        let srv = tokio::spawn(async move {
            server::run(paths, state, stager, None, format!("127.0.0.1:{port}").parse().unwrap(), &t, async {
                let _ = rx.await;
            })
            .await
            .unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let d = compat::discover(channel(port, &norole).await).await.unwrap().expect("Discovery answers");
        assert_eq!(d.served_apis, vec![API.to_string()], "{}", root.display());
        assert_eq!(d.agent_version, env!("CARGO_PKG_VERSION"));
        let _ = tx.send(());
        let _ = srv.await;
    }
    std::fs::set_permissions(ro.join("var"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_dir_all(&pki.root);
}
