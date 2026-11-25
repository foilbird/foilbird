// SPDX-License-Identifier: Apache-2.0
//! Every RPC of the API called once with arguments that the handler refuses
//! or that only read (T12 ext matrix). Authorization runs before the handler,
//! so PermissionDenied/Unauthenticated = denied, any other code returned by the
//! server = allowed, and a call that never reached the server (TLS handshake
//! refused, connection reset: a tonic transport error) = Error, never counted as
//! allowed or denied (a dead connection must not make a matrix pass). The
//! refused arguments keep an allowed DESTRUCTIVE call from doing anything:
//! Reboot/Rollback/RaiseMinVersion with a version that is not staged/booted,
//! ApplyConfig/ValidateConfig without a config, StageUpdate with an invalid
//! version, the journal RPCs and CollectDiagnostics with boot = 1 (invalid).
//! Shared by tests/authz.rs and examples/authz_probe.rs.
use foil_agent::pb::{self, node_agent_client::NodeAgentClient};
use tonic::Code;

/// What one call showed about authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The server answered with this code past the authorization layer.
    Allow(Code),
    /// PermissionDenied or Unauthenticated from the server.
    Deny(Code),
    /// The call never reached the server (transport error, e.g. the TLS
    /// handshake refused the client certificate): nothing about authorization.
    Error,
}

impl Outcome {
    #[allow(dead_code)] // used by examples/authz_probe.rs, not by tests/authz.rs
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Allow(_) => "ALLOW",
            Outcome::Deny(_) => "DENY",
            Outcome::Error => "ERROR",
        }
    }
}

/// A status produced by the client side from a transport failure: tonic keeps
/// the tonic::transport::Error as the source ("transport error", code Unknown).
/// A server-sent status (even Unavailable from a handler) has no such source.
pub fn is_transport(e: &tonic::Status) -> bool {
    std::error::Error::source(e).is_some_and(|s| s.downcast_ref::<tonic::transport::Error>().is_some())
        || (e.code() == Code::Unknown && e.message() == "transport error")
}

fn code<T>(r: Result<tonic::Response<T>, tonic::Status>) -> Outcome {
    match r {
        Ok(_) => Outcome::Allow(Code::Ok),
        Err(e) if is_transport(&e) => Outcome::Error,
        Err(e) if denied(e.code()) => Outcome::Deny(e.code()),
        Err(e) => Outcome::Allow(e.code()),
    }
}

pub const NOT_A_VERSION: &str = "probe-not-this-version";

pub async fn probe<T>(c: &mut NodeAgentClient<T>) -> Vec<(&'static str, Outcome)>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
{
    let v = || Some(pb::Version { image_version: NOT_A_VERSION.into() });
    vec![
        ("GetInfo", code(c.get_info(pb::GetInfoRequest {}).await)),
        ("GetHealth", code(c.get_health(pb::GetHealthRequest {}).await)),
        ("GetConfig", code(c.get_config(pb::GetConfigRequest {}).await)),
        ("ValidateConfig", code(c.validate_config(pb::ValidateConfigRequest { config: None }).await)),
        ("ApplyConfig", code(c.apply_config(pb::ApplyConfigRequest { config: None, expected_generation: 0 }).await)),
        ("StageUpdate", code(c.stage_update(pb::StageUpdateRequest { target: Some(pb::Version { image_version: "../bad".into() }) }).await)),
        ("GetUpdateStatus", code(c.get_update_status(pb::GetUpdateStatusRequest {}).await)),
        ("ListUnits", code(c.list_units(pb::ListUnitsRequest { failed_only: true }).await)),
        ("ReadJournal", code(c.read_journal(pb::ReadJournalRequest { boot: 1, limit: 1, ..Default::default() }).await)),
        ("ReadKernelLog", code(c.read_kernel_log(pb::ReadKernelLogRequest { boot: 1, limit: 1, ..Default::default() }).await)),
        ("CollectDiagnostics", code(c.collect_diagnostics(pb::CollectDiagnosticsRequest { boot: 1, max_entries: 1 }).await)),
        ("RaiseMinVersion", code(c.raise_min_version(pb::RaiseMinVersionRequest { expect_booted: v() }).await)),
        ("Reboot", code(c.reboot(pb::RebootRequest { reason: "authz probe".into(), expect_staged: v() }).await)),
        ("Rollback", code(c.rollback(pb::RollbackRequest { expect_booted: v(), reason: "authz probe".into() }).await)),
    ]
}

pub fn denied(c: Code) -> bool {
    matches!(c, Code::PermissionDenied | Code::Unauthenticated)
}
