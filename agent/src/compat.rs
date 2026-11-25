// SPDX-License-Identifier: Apache-2.0
//! API version compatibility between the agent and its clients.
//!
//! The API version is the package of the gRPC service (`foilbird.agent.v1alpha1`): it is
//! part of every RPC path, so an agent and a client of different versions do
//! not see each other's RPCs at all. Without help the client then reports a
//! bare `Unimplemented` (or, from agents before this change, `PermissionDenied
//! ...: unknown method`), which reads like a broken or vanished node.
//!
//! - The agent puts its API into the response header `x-foilbird-api` of every
//!   response, errors included ([`ApiHeaderLayer`]), and into `GetInfo.api`.
//! - An authenticated call to a path the agent does not serve is
//!   `Unimplemented` naming the agent's API (authz).
//! - foilctl turns such an error into "the agent speaks X, foilctl speaks Y"
//!   ([`explain`]): from the header, or, for an agent that predates the
//!   header, by probing `GetInfo` under the packages of earlier releases.
//! - Before any call foilctl asks the unversioned Discovery service (ADR 0016,
//!   [`discover`]) which packages the agent serves; one without foilctl's is the
//!   same "speaks X, foilctl speaks Y" ([`served`]) before anything is sent. An
//!   agent without Discovery (older) takes the path above.

use crate::pb;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::codegen::http;
use tonic::{Code, Status};

/// Response header carrying the agent's API (proto package).
pub const API_HEADER: &str = "x-foilbird-api";

/// API packages of earlier releases, probed when an agent does not report its
/// API. `foilbird.agent.v1alpha1` is the package of every agent before the version report.
pub const PREVIOUS_APIS: &[&str] = &["foilbird.agent.v1alpha1"];

/// Tower layer: `Server::builder().layer(ApiHeaderLayer(API))`.
#[derive(Clone, Copy, Debug)]
pub struct ApiHeaderLayer(pub &'static str);

impl<S> tower_layer::Layer<S> for ApiHeaderLayer {
    type Service = ApiHeader<S>;
    fn layer(&self, inner: S) -> ApiHeader<S> {
        ApiHeader { inner, api: http::HeaderValue::from_static(self.0) }
    }
}

#[derive(Clone, Debug)]
pub struct ApiHeader<S> {
    inner: S,
    api: http::HeaderValue,
}

type BoxFut<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;

impl<S, B, RB> tower_service::Service<http::Request<B>> for ApiHeader<S>
where
    S: tower_service::Service<http::Request<B>, Response = http::Response<RB>>,
    S::Future: Send + 'static,
    RB: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let (f, api) = (self.inner.call(req), self.api.clone());
        Box::pin(async move {
            let mut r = f.await?;
            r.headers_mut().insert(API_HEADER, api);
            Ok(r)
        })
    }
}

/// The API an agent reported in a response or error (header `x-foilbird-api`).
pub fn api_of(md: &tonic::metadata::MetadataMap) -> Option<String> {
    md.get(API_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// Does this error say that the agent does not serve the called path?
/// `Unimplemented`, or `PermissionDenied "<path>: unknown method"` from agents
/// before the version report.
pub fn is_unknown_method(st: &Status) -> bool {
    st.code() == Code::Unimplemented || (st.code() == Code::PermissionDenied && st.message().ends_with(": unknown method"))
}

/// The error text for a client of API `own` when the agent (API `agent`, if
/// known) did not serve the call.
pub fn mismatch(agent: Option<&str>, own: &str, st: &Status) -> String {
    let said = format!("{:?}: {}", st.code(), st.message());
    match agent {
        Some(a) if a != own => format!(
            "API version mismatch: the agent speaks API {a}, foilctl speaks API {own}; use the foilctl of the agent's release (agent said {said})"
        ),
        Some(a) => format!("the agent speaks the same API {a} as foilctl but does not implement this call (agent said {said})"),
        None => format!(
            "API version mismatch: the agent does not serve API {own} and does not report its own (none of {} answers); \
             foilctl speaks API {own} (agent said {said})",
            PREVIOUS_APIS.join(", ")
        ),
    }
}

/// Discovery (ADR 0016): the agent's release and served API packages; `None` for an agent without Discovery (it
/// predates it: Unimplemented, or PermissionDenied "unknown method" from agents before the version report). Any
/// other error (TLS, transport, a refused certificate) is returned as it is.
pub async fn discover(ch: tonic::transport::Channel) -> Result<Option<crate::discovery_pb::GetApiVersionsResponse>, Status> {
    let mut c = crate::discovery_pb::discovery_client::DiscoveryClient::new(ch);
    match c.get_api_versions(crate::discovery_pb::GetApiVersionsRequest {}).await {
        Ok(r) => Ok(Some(r.into_inner())),
        Err(e) if is_unknown_method(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Does the agent of this Discovery answer serve API `own`? Else the mismatch text.
pub fn served(d: &crate::discovery_pb::GetApiVersionsResponse, own: &str) -> Result<(), String> {
    if d.served_apis.iter().any(|a| a == own) {
        return Ok(());
    }
    let apis = if d.served_apis.is_empty() { "(none)".to_string() } else { d.served_apis.join(", ") };
    Err(format!(
        "API version mismatch: the agent speaks API {apis}, foilctl speaks API {own}; use the foilctl of the agent's release (agent {})",
        if d.agent_version.is_empty() { "?" } else { &d.agent_version }
    ))
}

/// GetInfo under the API package `api` (a raw call: the generated client only
/// knows its own package).
pub async fn get_info(ch: tonic::transport::Channel, api: &str) -> Result<tonic::Response<pb::GetInfoResponse>, Status> {
    let mut g = tonic::client::Grpc::new(ch);
    g.ready().await.map_err(|e| Status::unavailable(format!("not ready: {e}")))?;
    let path: http::uri::PathAndQuery =
        format!("/{api}.NodeAgent/GetInfo").parse().map_err(|_| Status::invalid_argument(format!("bad API package {api}")))?;
    g.unary(tonic::Request::new(pb::GetInfoRequest {}), path, tonic_prost::ProstCodec::default()).await
}

/// For an error of a call made with API `own`: the explanation when the agent
/// does not serve that path, else None (the error stands as it is).
pub async fn explain(ch: &tonic::transport::Channel, st: &Status, own: &str) -> Option<String> {
    if !is_unknown_method(st) {
        return None;
    }
    let mut agent = api_of(st.metadata());
    if agent.is_none() {
        for p in PREVIOUS_APIS.iter().filter(|p| **p != own) {
            match get_info(ch.clone(), p).await {
                Ok(r) => {
                    agent = Some(api_of(r.metadata()).unwrap_or_else(|| p.to_string()));
                    break;
                }
                Err(e) if !is_unknown_method(&e) => {
                    agent = api_of(e.metadata()).or_else(|| Some(p.to_string()));
                    break;
                }
                Err(_) => {}
            }
        }
    }
    Some(mismatch(agent.as_deref(), own, st))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_api(mut st: Status, api: &str) -> Status {
        st.metadata_mut().insert(API_HEADER, api.parse().unwrap());
        st
    }

    #[test]
    fn unknown_method_shapes() {
        assert!(is_unknown_method(&Status::unimplemented("")));
        // agents before the version report (authz denied an unknown path)
        assert!(is_unknown_method(&Status::permission_denied("/foilbird.agent.v1alpha1.NodeAgent/GetInfo: unknown method")));
        assert!(!is_unknown_method(&Status::permission_denied("no role in certificate")));
        assert!(!is_unknown_method(&Status::unavailable("connection refused")));
    }

    #[test]
    fn mismatch_names_both_versions() {
        let st = with_api(Status::unimplemented("/foilbird.agent.v9.NodeAgent/GetInfo: not served"), "foilbird.agent.v1alpha1");
        let m = mismatch(api_of(st.metadata()).as_deref(), "foilbird.agent.v9", &st);
        assert!(m.contains("the agent speaks API foilbird.agent.v1alpha1, foilctl speaks API foilbird.agent.v9"), "{m}");
        let m = mismatch(None, "foilbird.agent.v1alpha1", &Status::permission_denied("x: unknown method"));
        assert!(m.contains("does not report its own") && m.contains("foilctl speaks API foilbird.agent.v1alpha1"), "{m}");
        let m = mismatch(Some("foilbird.agent.v1alpha1"), "foilbird.agent.v1alpha1", &Status::unimplemented("x"));
        assert!(m.contains("same API foilbird.agent.v1alpha1"), "{m}");
    }
}
