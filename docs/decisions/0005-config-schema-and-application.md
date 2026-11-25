# 0005. Node configuration: schema compatibility across releases; application modes deferred

- Status: accepted (2026-11-21, owner); rule 1 binds every agent with a schema above 1; items 2–4 are not implemented
  in v1-alpha (see "Deferred")
- Scope: agent (`NodeConfig`, `ApplyConfig`, `/var/lib/foil-agent`), update and rollback

## Problem

The agent keeps the applied configuration on the persistent `/var` in `/var/lib/foil-agent/config.pb` (protobuf
`NodeConfig`) and `generation`, written atomically (render, then persist, then activate; `agent/src/config.rs` `save`).
The file is shared by both A/B slots. The agent accepts exactly its own schema (`SCHEMA = 1`, `schema != SCHEMA` is
refused, `config.rs`).

When a later release introduces schema 2 and writes it to the same file, a rollback to a release with schema 1 boots an
agent that refuses the stored configuration: the node comes up without its configuration (network, join, labels), the
boot check fails, and the node can run out of good entries and end in recovery. A rollback must never be broken by
something the newer release wrote (the rule "N+1 does not migrate state irreversibly").

In v1-alpha there is one schema, so nothing breaks yet; the rule has to be fixed before the first schema change.

## Decision

1. **`config.pb` belongs to schema 1 forever.** An agent whose `SCHEMA` is above 1:
   - reads `config.pb` (schema 1) when it has nothing newer and accepts it (`schema <= SCHEMA`; new fields are optional);
   - writes its own configurations to a separate file named after its schema (for example `config.v2.pb` with its own
     generation), using the same atomic write;
   - **never rewrites, renames or removes `config.pb` or `generation`.**
2. After a rollback the older agent finds the configuration it committed itself. Changes applied under the newer release
   are not visible to it; that is intended: the node boots with the configuration committed under the release it runs
   (the API rule: configuration is committed per release). Its `generation` may be lower than the one the controller saw last; the controller re-reads it through
   `GetConfig` (an `ApplyConfig` with a stale `expected_generation` is refused, as today).
3. A schema is raised only together with a release; the controller does not send schema K to a node until the fleet floor
   (`min_version`) has reached a release that understands K.

## Deferred (accepted, not implemented in v1-alpha)

| # | Item | Why later | Effect on v1-alpha | Comes back when |
|---|---|---|---|---|
| Z1 | `ApplyConfigRequest.mode` `NO_REBOOT` / `STAGED` / `TRY` + bounded `try_timeout_seconds`; `TRY` reverts on failed local health checks, not only on a timer (Talos `try` is timer-only, step 2 T7) | needs a new state machine in the agent and its own tests (T17) | `ApplyConfig` applies immediately and reports `reboot_required`; a configuration that cuts the node off its management network is not reverted automatically; the way back is a reinstall | before the rollout controller (0008) uses `ApplyConfig` on a fleet. Compatible: new field, value 0 = today's behaviour |
| Z2 | `dry_run` and a typed diff (field paths; secrets only as sha256) | additive, no consumer in alpha (no gateway) | `ValidateConfig` checks a configuration without a diff | with the gateway or Z1. Compatible: new fields |
| Z3 | pending/committed of the whole `NodeConfig` bound to a release | the rule above covers the only risk (rollback after a schema change) without code in alpha | none while there is one schema | together with the first schema 2. Compatible by rule 1 |

The explicit node role (`NodeConfig.role`, WORKER / CONTROL_PLANE) is not deferred: it was merged before v1-alpha
within schema 1, as a new optional field. A `config.pb` written before the field (schema 1, `k8s` set,
role `UNSPECIFIED`) is loaded at boot with the role inferred in memory (`k8s.init` set = `CONTROL_PLANE`, otherwise
`WORKER`, with a warning in the journal); **the file is not rewritten** (rule 1). `GetConfig` returns the inferred role;
the next `ApplyConfig` must carry the role explicitly. Semantics: `profiles/k8s-worker/README.md`, "Node role".

## Test (with the first schema 2)

Apply a configuration under schema 2, roll back to the schema-1 release: the node boots with its schema-1 configuration,
`config.pb` is byte-identical to before the update, boot check passes (extends T14, decision 0004).
