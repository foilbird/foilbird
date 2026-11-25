# 0013. Decisions accepted for v1 but not implemented in v1-alpha

- Status: accepted (2026-11-21, owner)
- Scope: register of design decisions taken after studying reference systems (Talos first; Flatcar, Garden Linux,
  Kairos, Bottlerocket, FLUO by topic) that v1-alpha deliberately does not implement

## Why a register

The design study produced decisions that change the agent API or the disk layout. Implementing them all would take
longer than the whole alpha milestone. Only the changes that could not be made compatibly after publication were made
before v1-alpha:

| Done before v1-alpha | Merged |
|---|---|
| API package `foilbird.agent.v1alpha1` and profile `PROFILE_K8S`, renamed together with the project prefix | yes, in v1-alpha |
| explicit node role `NodeConfig.role` (WORKER / CONTROL_PLANE), validated in `ValidateConfig` / `ApplyConfig`; required only with `k8s`; fixed for an installation (semantics: `profiles/k8s-worker/README.md`, "Node role"; ADR 0005) | yes, in v1-alpha |
| explicit API version mismatch error between agent and `foilctl` (`foilctl` names both versions) | yes, in v1-alpha |
| reserved, unused 256 MiB `state` partition before `/var` on fresh installations (`docs/updates.md`) | yes, in v1-alpha |

This record is updated to the facts when those changes are merged. Everything in the register below is **accepted as
the direction for v1** and **not implemented in v1-alpha**. For each: why it waits, what it means for an alpha user, and
when it comes back.

Decision numbers 0006, 0008, 0009, 0011 are reserved for the full records of these topics: 0006 `state` partition,
0008 rollout controller, 0009 node PKI and registration, 0011 break-glass; 0015 is not used. Decision 0010 (threat model
limits and `/var` recovery) is proposed.

"Compatible" = can be added after alpha without reinstalling nodes and without breaking clients of the alpha API.

## Register

| # | Decision | Why deferred | Effect on v1-alpha | Comes back when |
|---|---|---|---|---|
| Z1 | `ApplyConfig` modes `NO_REBOOT` / `STAGED` / `TRY`; `TRY` reverts on failed local health checks | new state machine and tests | configuration is applied at once; a configuration that cuts the node off is not reverted automatically (reinstall) | before a fleet controller uses `ApplyConfig`; compatible (0005) |
| Z2 | `dry_run` and a typed diff of `ApplyConfig` | additive, no consumer yet | `ValidateConfig` without a diff | with the gateway or Z1; compatible (0005) |
| Z3 | configuration pending/committed per release; `schema <=` | one schema in alpha, risk covered by rule 1 of 0005 | none | with the first schema 2; compatible (0005) |
| Z4 | small encrypted `state` partition for configuration, installation identity, certificates, epochs and the anti-rollback floor, so that `/var` can be wiped without re-registration | new subsystem (unlock together with `/var`, migration from `/var/lib/foil-agent` and `/var/lib/foilbird`) | all state is on `/var`; losing `/var` loses configuration and node identity; a reserved, unused partition is done in v1-alpha (table above) | v1, decision 0006; compatible only if the reservation is merged, otherwise reinstall |
| Z5 | `Watch` RPC (server-streaming, READ) and a monotonic `resource_version` on status snapshots | needed by a rollout controller, none in alpha | clients poll `GetUpdateStatus` / `GetHealth` | with the rollout controller; compatible (new RPC and field) |
| Z6 | separate CAs: nodes / clients / emergency; `EMERGENCY` only for certificates of the emergency CA | the client CA belongs to the deployment; one EMERGENCY RPC in alpha | one client CA (`agent.tls-ca`); **any certificate it issues with `OU=operator` may call every RPC, including EMERGENCY** | decision 0009; compatible (second CA credential, absent = EMERGENCY for nobody) |
| Z7 | `(sensitive)` option on `.proto` fields for gateways and `foilctl` | consumer (gateway) not in alpha | secrets are hidden by `SecretString` only | with the gateway; compatible |
| Z8 | implementation of decision 0004: kubelet skew checked on the node, no skipped minor, kubelet configuration `pending → verifying → committed / reverted / unverified` | one Kubernetes minor per alpha, no minor change to guard | **a Kubernetes minor upgrade is not supported in alpha**; patch releases only | before the second minor stream; compatible (new `StageError` values, new files) |
| Z9 | release metadata with an expiry (`expires`) | channel format extension; tied to release keys (0012) | **against an older signed release served by a hostile channel only the floor `min_version` protects** | before the first production release (0012); compatible (extra signed file) |
| Z10 | `/var` recovery: distinguish TPM reset from failure, recreate `/var` on a worker, recovery key for other profiles | depends on Z4 | a TPM reset or lost `/var` key means reinstall; recovery-key slot does not exist | decision 0010, after Z4 |
| Z11 | rollout controller outside the cluster (state machine, drain failure ⇒ no reboot, concurrency slot until soak) | does not change the node API; separate component | updates are driven one node at a time with `foilctl` by the operator | decision 0008; first as a sequential `foilctl` command |
| Z12 | registration: TPM AK/EK, credential activation, server-set role, 24 h node certificates, quarantine by EK | a separate registration stage, own API package | node TLS material and configuration come from systemd credentials prepared by the operator | decision 0009; compatible (own package `…registration.v1alpha1`, `AgentMode.REGISTRATION` exists) |
| Z13 | anti-rollback floor in a TPM NV counter, copy on `state` | together with Z4 | floor = max(`/var/lib/foilbird/min_version`, floor of the image) plus `/var` key epochs; root on the node can lower the file, but not the image floor or the epochs | with Z4 |
| Z14 | etcd of a control plane on its own volume outside A/B | the control plane design record is not written | **control plane in alpha is a single node; etcd is on `/var`; losing `/var` loses the cluster state; backups are the operator's job** | control plane design record |

Not part of this register (no API or disk change), stated so the documentation does not over-claim:
- break-glass (0011, reserved): **`kubectl debug node/` and pods with `hostPID` / `hostPath: /` are not blocked** by
  the OS; the cluster's admission policy decides;
- `/etc` is writable at runtime by root (it is a tmpfs, empty after reboot); read-only `/etc` is not implemented.

## Rule

An item leaves the register only with its own accepted decision and its test from the test plan; "done by commit" does
not count.
