// SPDX-License-Identifier: Apache-2.0
//! foil-agent library: API types, configuration, system facts, gRPC service.

pub mod authz;
pub mod compat;
pub mod config;
pub mod journal;
pub mod logfmt;
pub mod rollback;
pub mod server;
pub mod system;
pub mod update;

/// The API this agent serves (the proto package, e.g. `foilbird.agent.v1alpha1`); see [`compat`].
pub const API: &str = authz::API;

pub mod pb {
    tonic::include_proto!("foilbird.agent.v1alpha1");
}

/// The unversioned Discovery service (ADR 0016): which API packages an agent serves.
pub mod discovery_pb {
    tonic::include_proto!("foilbird.agent");
}
