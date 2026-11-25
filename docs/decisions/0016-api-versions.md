# 0016. API versions of the node agent and how a client finds them

- Status: accepted (2026-11-22)
- Scope: the gRPC API of the node agent (`api/proto`), `foilctl` and every other client; not the configuration document
  (its own `schema`, see below)

## Context

The API version is the protobuf package of the agent's service (`<prefix>.agent.v<N>`). It is part of every RPC path,
so an agent and a client of different versions do not see each other's calls. Before this decision a client learned the
agent's version only after a call failed (`Unimplemented` with the response header `x-foilbird-api`, or, for older agents,
by probing `GetInfo` under the packages of earlier releases).

## Decision

1. **Discovery, without a version.** One small service in the unversioned package `<prefix>.agent`:
   `Discovery.GetApiVersions` returns `agent_version` (the agent's release, no build features) and `served_apis` (the
   full names of every API package the agent serves). It imports nothing versioned and carries no method options, so a
   new API version never touches it.
2. **Frozen.** From the first public release on, Discovery is frozen for good: the names, numbers, types and labels of
   its fields and the shape of the service (one service, one RPC, its request and response) never change and nothing is
   removed; fields may only be added. `api/tools/check_proto.py` checks this against
   `api/proto/<prefix>/agent/discovery.fields`. The package name follows the project prefix: before the first public
   release it may change once, in the commit that renames the prefix; `check_proto.py` only requires it to be the API
   package without its version.
3. **Who may call it.** Any client whose certificate the agent's CA signed, with the clientAuth extended key usage,
   whatever its role: a client must learn the versions before it can speak one. Every other RPC keeps its access level
   and roles.
4. **Every mode.** Discovery does not depend on the agent's mode, configuration or `/var`. It has no state: it does
   not read the configuration or `/var` and answers whenever the agent
   listens at all, also without a configuration and with `/var` missing or read-only (tests in
   `agent/tests/api_compat.rs`). The v1-alpha agent listens in one mode only: `GetInfo.mode` is `AGENT_MODE_BRIDGE`;
   `AGENT_MODE_REGISTRATION` and `AGENT_MODE_OPERATIONAL` are declared in the API but no agent runs in them yet; when
   they come, the same server serves Discovery in them. The recovery image has no agent.
5. **Clients.** `foilctl` asks Discovery first. An agent that does not list `foilctl`'s package is refused before any call
   with "API version mismatch: the agent speaks API X, foilctl speaks API Y". An agent without Discovery (older) is called
   as before; its `Unimplemented` is explained from `x-foilbird-api` or by probing earlier packages. The header `x-foilbird-api`
   stays in every response.
6. **No compatibility promise during alpha.** While the API is `v<N>alpha<M>`, an agent serves one version and
   `foilctl` and the agent are used at the same release; a mismatch is a clear error, not a fallback.
7. **From beta on.** With `v<N>beta<M>` and `v<N>`, an agent serves the new version N and the previous one N-1 for the
   time of a migration (both in `served_apis`). A version is removed only after it was marked deprecated and the removal
   was announced in the release notes.
8. **The configuration document is versioned on its own.** `NodeConfig.schema` (ADR 0005) is the version of the
   configuration an agent accepts and is independent of the RPC version: a new API version does not imply a new schema,
   and a new schema does not need a new API package.
9. **No capabilities.** Optional features are not announced in Discovery now; field number 3 and the name
   `capabilities` are reserved for that.

## Consequences

- A client never has to guess from an error which API an agent speaks.
- Adding an API version is a change of the versioned package only; Discovery and its clients keep working.
- `check_proto.py` fails on any change of Discovery's frozen surface (fixtures in `api/tools/test_check_proto.sh`).
