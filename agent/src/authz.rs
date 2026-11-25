// SPDX-License-Identifier: Apache-2.0
//! Authorization of every RPC before its handler.
//!
//! A tower layer in front of the gRPC router looks up the request path in the
//! table generated from the .proto (`(foilbird.agent.v1alpha1.access)` and
//! `(foilbird.agent.v1alpha1.roles)`, build.rs) and the caller's roles in the client
//! certificate: Subject OU = role name (reader, diag, updater, configurer,
//! controller, operator). A certificate with several OUs may call the union
//! of their RPCs. Denied by default: an unknown path, a certificate without
//! the clientAuth extended key usage or without a known OU, or roles that the
//! RPC does not list. A path this agent does not serve (another API version,
//! a newer RPC) is `Unimplemented` naming the agent's API, but only for a
//! caller that passed the certificate checks. Handlers never check access; they read the [`Caller`]
//! (CN, roles, "on behalf of") from the request extensions for the audit log.
//!
//! `x-foilbird-on-behalf-of` (metadata from a gateway: the human or ticket it acts
//! for) is only recorded in the audit log; it never changes the roles.

use crate::pb::{AccessLevel, Role};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::Status;
use tonic::codegen::http;

mod table {
    include!(concat!(env!("OUT_DIR"), "/access.rs"));
}

pub const ON_BEHALF_OF: &str = "x-foilbird-on-behalf-of";

/// The API this agent serves: the package of the service in the .proto (build.rs).
pub const API: &str = table::API;
/// Path prefix of the unversioned Discovery service (ADR 0016), e.g. `/foilbird.agent.Discovery/`.
pub const DISCOVERY: &str = table::DISCOVERY;
/// The Discovery RPCs: any client of the agent's CA may call them, whatever its role (see [`decide`]).
pub const DISCOVERY_METHODS: &[&str] = &["GetApiVersions"];

/// Is `method` an RPC of the Discovery service?
pub fn is_discovery(method: &str) -> bool {
    method.strip_prefix(DISCOVERY).is_some_and(|m| DISCOVERY_METHODS.contains(&m))
}

/// Every RPC of the API: (path, access level, roles allowed).
pub fn table() -> impl Iterator<Item = (&'static str, AccessLevel, Vec<Role>)> {
    table::ACCESS.iter().map(|(m, l, r)| {
        (*m, AccessLevel::try_from(*l).unwrap_or(AccessLevel::Unspecified), r.iter().filter_map(|x| Role::try_from(*x).ok()).collect())
    })
}

pub fn level(method: &str) -> Option<AccessLevel> {
    table::ACCESS.iter().find(|(m, _, _)| *m == method).and_then(|(_, l, _)| AccessLevel::try_from(*l).ok())
}

pub fn allowed_roles(method: &str) -> Option<Vec<Role>> {
    table::ACCESS
        .iter()
        .find(|(m, _, _)| *m == method)
        .map(|(_, _, r)| r.iter().filter_map(|x| Role::try_from(*x).ok()).collect())
}

/// OU value -> role: the enum name without ROLE_, lower case.
pub fn role_from_ou(ou: &str) -> Option<Role> {
    match Role::from_str_name(&format!("ROLE_{}", ou.to_ascii_uppercase())) {
        Some(Role::Unspecified) | None => None,
        r => r,
    }
}

pub fn role_name(r: Role) -> String {
    r.as_str_name().trim_start_matches("ROLE_").to_ascii_lowercase()
}

fn names(rs: &[Role]) -> String {
    rs.iter().map(|r| role_name(*r)).collect::<Vec<_>>().join(",")
}

/// What the client certificate says about the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertFacts {
    pub common_name: String,
    pub roles: Vec<Role>,
    pub client_auth: bool,
}

pub fn cert_facts(der: &[u8]) -> Option<CertFacts> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok())
        .map(|c| c.chars().filter(|c| !c.is_control()).take(128).collect())
        .unwrap_or_else(|| "?".into());
    let mut roles = Vec::new();
    for ou in cert.subject().iter_organizational_unit() {
        if let Some(r) = ou.as_str().ok().and_then(role_from_ou) {
            if !roles.contains(&r) {
                roles.push(r);
            }
        }
    }
    // Required explicitly: rustls accepts a client certificate without the EKU extension.
    let client_auth = matches!(cert.extended_key_usage(), Ok(Some(e)) if e.value.client_auth);
    Some(CertFacts { common_name: cn, roles, client_auth })
}

/// The authorized caller, put into the request extensions for the handler.
#[derive(Clone, Debug)]
pub struct Caller {
    pub method: String,
    pub level: AccessLevel,
    pub common_name: String,
    pub roles: Vec<Role>,
    pub on_behalf_of: Option<String>,
}

impl Caller {
    pub fn roles(&self) -> String {
        names(&self.roles)
    }
}

/// Printable ASCII, at most 128 characters; anything else is replaced, never trusted.
pub fn sanitize_on_behalf(v: &[u8]) -> String {
    match std::str::from_utf8(v) {
        Ok(s) if !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| (0x20..0x7f).contains(&b)) => s.to_string(),
        _ => "<invalid>".into(),
    }
}

/// A caller with several roles may call the union of their RPCs.
pub fn permits(allowed: &[Role], roles: &[Role]) -> bool {
    roles.iter().any(|r| allowed.contains(r))
}

/// The decision, independent of transport (unit tests, the T12 ext matrix).
pub fn decide(method: &str, leaf_der: Option<&[u8]>, on_behalf_of: Option<String>) -> Result<Caller, Status> {
    let known = level(method).zip(allowed_roles(method));
    let der = leaf_der.ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let f = cert_facts(der).ok_or_else(|| Status::permission_denied("unreadable client certificate"))?;
    if !f.client_auth {
        return Err(Status::permission_denied("client certificate lacks the clientAuth extended key usage"));
    }
    // Discovery (ADR 0016): a client must learn the API versions before it can speak one; any certificate of the CA
    // with clientAuth, no role needed (the TLS layer has already checked the chain)
    if is_discovery(method) {
        return Ok(Caller { method: method.to_string(), level: AccessLevel::Read, common_name: f.common_name, roles: f.roles, on_behalf_of });
    }
    if f.roles.is_empty() {
        return Err(Status::permission_denied("no role in certificate"));
    }
    // a client of another API version gets the agent's version, not a bare "unknown"
    let Some((level, allowed)) = known else {
        return Err(Status::unimplemented(format!("{method}: not served by this agent (agent API {API})")));
    };
    if !permits(&allowed, &f.roles) {
        return Err(Status::permission_denied(format!(
            "{method} ({}) is not allowed for role {}; allowed: {}",
            level.as_str_name(),
            names(&f.roles),
            names(&allowed)
        )));
    }
    Ok(Caller { method: method.to_string(), level, common_name: f.common_name, roles: f.roles, on_behalf_of })
}

/// Tower layer: `Server::builder().layer(AuthzLayer)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthzLayer;

impl<S> tower_layer::Layer<S> for AuthzLayer {
    type Service = Authz<S>;
    fn layer(&self, inner: S) -> Authz<S> {
        Authz { inner }
    }
}

#[derive(Clone, Debug)]
pub struct Authz<S> {
    inner: S,
}

type BoxFut<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;

impl<S, B, RB> tower_service::Service<http::Request<B>> for Authz<S>
where
    S: tower_service::Service<http::Request<B>, Response = http::Response<RB>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    RB: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
        let method = req.uri().path().to_string();
        let leaf: Option<Vec<u8>> = req
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|i| i.peer_certs())
            .and_then(|c| c.first().map(|l| l.as_ref().to_vec()));
        let obo = req.headers().get(ON_BEHALF_OF).map(|v| sanitize_on_behalf(v.as_bytes()));
        match decide(&method, leaf.as_deref(), obo.clone()) {
            Ok(caller) => {
                if caller.level == AccessLevel::Read {
                    tracing::info!(method = %method, cn = %caller.common_name, roles = %caller.roles(), on_behalf_of = obo.as_deref().unwrap_or("-"), "call");
                } else {
                    tracing::warn!(target: "audit", method = %method, level = caller.level.as_str_name(), cn = %caller.common_name, roles = %caller.roles(), on_behalf_of = obo.as_deref().unwrap_or("-"), "call");
                }
                req.extensions_mut().insert(caller);
                // the clone that was polled ready serves this call
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                Box::pin(async move { inner.call(req).await })
            }
            Err(st) => {
                let cn = leaf.as_deref().and_then(cert_facts).map(|f| f.common_name).unwrap_or_else(|| "-".into());
                tracing::warn!(target: "audit", method = %method, cn = %cn, on_behalf_of = obo.as_deref().unwrap_or("-"), denied = %st.message(), "denied");
                let resp = st.into_http::<RB>();
                Box::pin(async move { Ok(resp) })
            }
        }
    }
}

/// The caller of a handler (set by the layer). Missing = the layer is not in
/// front of the service: refuse rather than serve unauthorized.
pub fn caller<T>(req: &tonic::Request<T>) -> Result<Caller, Status> {
    req.extensions().get::<Caller>().cloned().ok_or_else(|| Status::internal("request was not authorized"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(cn: &str, ous: &[&str], client_auth: bool) -> Vec<u8> {
        let k = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        for ou in ous {
            p.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, *ou);
        }
        if client_auth {
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        }
        p.self_signed(&k).unwrap().der().to_vec()
    }

    const SVC: &str = "/foilbird.agent.v1alpha1.NodeAgent/";

    /// Discovery (ADR 0016): any certificate of the CA with clientAuth, with or without a role; never without clientAuth;
    /// an unknown Discovery method is not allowed; NodeAgent without a role stays denied
    #[test]
    fn discovery_any_client_of_the_ca() {
        let m = format!("{DISCOVERY}GetApiVersions");
        assert_eq!(DISCOVERY, "/foilbird.agent.Discovery/");
        let no_role = cert("x", &[], true);
        assert_eq!(decide(&m, Some(&no_role), None).unwrap().level, AccessLevel::Read);
        for ou in ["reader", "diag", "updater", "configurer", "controller", "operator"] {
            assert!(decide(&m, Some(&cert("x", &[ou], true)), None).is_ok(), "{ou}");
        }
        assert_eq!(decide(&m, Some(&cert("x", &[], false)), None).unwrap_err().code(), tonic::Code::PermissionDenied);
        assert_eq!(decide(&m, None, None).unwrap_err().code(), tonic::Code::Unauthenticated);
        assert!(!is_discovery(&format!("{DISCOVERY}Other")));
        assert_eq!(decide(&format!("{DISCOVERY}Other"), Some(&no_role), None).unwrap_err().code(), tonic::Code::PermissionDenied);
        assert_eq!(decide(&format!("{SVC}GetInfo"), Some(&no_role), None).unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn table_from_proto() {
        let t: Vec<_> = table().collect();
        assert_eq!(t.len(), 14);
        for (m, l, r) in &t {
            assert_ne!(*l, AccessLevel::Unspecified, "{m}");
            assert!(r.contains(&Role::Operator), "{m}");
        }
        assert_eq!(allowed_roles(&format!("{SVC}CollectDiagnostics")), Some(vec![Role::Operator]));
        assert_eq!(allowed_roles(&format!("{SVC}RaiseMinVersion")), Some(vec![Role::Operator]));
        assert_eq!(level(&format!("{SVC}Rollback")), Some(AccessLevel::Destructive));
    }

    #[test]
    fn ou_names() {
        assert_eq!(role_from_ou("reader"), Some(Role::Reader));
        assert_eq!(role_from_ou("configurer"), Some(Role::Configurer));
        assert_eq!(role_from_ou("workload"), None);
        assert_eq!(role_from_ou("unspecified"), None);
        assert_eq!(role_name(Role::Updater), "updater");
    }

    #[test]
    fn deny_by_default() {
        let m = format!("{SVC}GetInfo");
        assert_eq!(decide(&m, None, None).unwrap_err().code(), tonic::Code::Unauthenticated);
        let wl = cert("workload", &["workload"], true);
        assert_eq!(decide(&m, Some(&wl), None).unwrap_err().code(), tonic::Code::PermissionDenied);
        let no_eku = cert("x", &["operator"], false);
        let e = decide(&m, Some(&no_eku), None).unwrap_err();
        assert!(e.message().contains("clientAuth"), "{}", e.message());
        let op = cert("op", &["operator"], true);
        // unknown path: still authenticated first, then Unimplemented with the agent's API
        for m in [format!("{SVC}Nope"), "/other.Svc/GetInfo".into(), "/foilbird.agent.v9.NodeAgent/GetInfo".into()] {
            let e = decide(&m, Some(&op), None).unwrap_err();
            assert_eq!(e.code(), tonic::Code::Unimplemented, "{m}");
            assert!(e.message().contains(&format!("agent API {API}")), "{}", e.message());
            assert_eq!(decide(&m, None, None).unwrap_err().code(), tonic::Code::Unauthenticated, "{m}");
            assert_eq!(decide(&m, Some(&wl), None).unwrap_err().code(), tonic::Code::PermissionDenied, "{m}");
        }
    }

    #[test]
    fn api_is_the_proto_package() {
        assert_eq!(format!("{API}.NodeAgent"), crate::pb::node_agent_server::SERVICE_NAME);
        assert!(table().all(|(m, _, _)| m.starts_with(&format!("/{API}.NodeAgent/"))));
    }

    #[test]
    fn matrix_matches_table() {
        // every RPC x every role: allowed exactly when the .proto lists the role
        let all = [Role::Reader, Role::Diag, Role::Updater, Role::Configurer, Role::Controller, Role::Operator];
        for (m, _, allowed) in table() {
            for r in all {
                let c = cert("t", &[&role_name(r)], true);
                assert_eq!(decide(m, Some(&c), None).is_ok(), allowed.contains(&r), "{m} {r:?}");
            }
        }
        // RaiseMinVersion is not the controller's; EMERGENCY only the operator's
        let ctl = cert("ctl", &["controller"], true);
        assert!(decide(&format!("{SVC}RaiseMinVersion"), Some(&ctl), None).is_err());
        assert!(decide(&format!("{SVC}CollectDiagnostics"), Some(&ctl), None).is_err());
        assert!(decide(&format!("{SVC}Rollback"), Some(&ctl), None).is_ok());
    }

    #[test]
    fn union_of_roles_and_audit_fields() {
        // rcgen keeps one OU per certificate, so the union is checked on the role sets
        // (a two-OU certificate made with openssl is checked against a running agent as well)
        let stage = allowed_roles(&format!("{SVC}StageUpdate")).unwrap();
        let apply = allowed_roles(&format!("{SVC}ApplyConfig")).unwrap();
        let journal = allowed_roles(&format!("{SVC}ReadJournal")).unwrap();
        let both = [Role::Reader, Role::Updater];
        assert!(permits(&stage, &both) && !permits(&apply, &both) && !permits(&journal, &both));
        assert!(!permits(&stage, &[Role::Reader]));
        let c = cert("gw-1", &["updater"], true);
        let ok = decide(&format!("{SVC}StageUpdate"), Some(&c), Some("alice".into())).unwrap();
        assert_eq!(ok.common_name, "gw-1");
        assert_eq!(ok.roles(), "updater");
        assert_eq!(ok.on_behalf_of.as_deref(), Some("alice"));
    }

    #[test]
    fn on_behalf_is_sanitized() {
        assert_eq!(sanitize_on_behalf(b"ticket-42 alice"), "ticket-42 alice");
        assert_eq!(sanitize_on_behalf(b"a\nb"), "<invalid>");
        assert_eq!(sanitize_on_behalf(&[b'x'; 200]), "<invalid>");
        assert_eq!(sanitize_on_behalf(b""), "<invalid>");
    }
}
