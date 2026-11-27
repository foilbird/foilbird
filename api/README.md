# Node agent API

`proto/foilbird/agent/v1alpha1/` — gRPC API of the node agent (`service NodeAgent`), protobuf package
`foilbird.agent.v1alpha1`. Transport: gRPC over mutual TLS.

## Rules
- Typed operations only. No RPC or field carries a command, script, argument vector, file
  system path, binary or URL; no untyped containers; `bytes` only by allowlist.
  Enforced by `tools/check_proto.py` (acceptance test T8; `tools/test_check_proto.sh`
  also checks a negative fixture).

  > **v1-alpha limitation** (fix planned for v1-alpha4): the control plane's `k8s.init` (`K8sConfig.init`) is a kubeadm
  > `InitConfiguration` and `ClusterConfiguration` document passed to `kubeadm init` as given. The agent checks only
  > what the image requires of it: `kubeadm.k8s.io/v1beta4`, the image's kube-apiserver audit policy with the audit log
  > on `/var`, the kubelet shutdown settings and the bootstrap token ttl. Everything else in it is not restricted, among
  > it `extraArgs`, `extraVolumes` (host paths) and `imageRepository`. A client whose role may call `ApplyConfig` (not
  > only `operator`) can therefore make a node that has no role yet a control plane running static pods and host mounts
  > of its choice: on such a node that is equivalent to root. The boundary is who is issued a certificate of such a
  > role. The role of a configured node cannot change and `kubeadm init` runs once. T8 checks field names and types; it
  > cannot see inside this text.
- Network locations are typed parts, never URLs: `endpoint` (`host[:port]`) + `prefix`
  (path, `[A-Za-z0-9._~/-]`, no `..`) + `ca_pem`. The scheme is fixed by the field (always
  https for `UpdateChannel`, `RegistryMirror`), so plain http, user info, query and fragment
  cannot be expressed; T8 forbids `url`/`uri` field names, and a new location field follows
  the same pattern instead of an exception in the checker.
- Every RPC has exactly one `(foilbird.agent.v1alpha1.access)` level: `READ`, `DIAG`, `OPERATE`,
  `DESTRUCTIVE`, `EMERGENCY`. The gateway publishes MCP tools by level and never
  publishes `EMERGENCY`; `tools/check_proto.py --mcp` is the reference filter (CI checks
  that no `EMERGENCY` RPC is in its output).
- `EMERGENCY` (`CollectDiagnostics`): the unredacted journal for an operator in an
  emergency — read only, no paths, bounded (entries and bytes, truncation reported),
  audited on the node. Controller and reader certificates are refused (T12).
- `DIAG` (`ReadJournal`, `ReadKernelLog`) is read-only like `READ` but returns free
  text from the node. The agent redacts secrets (private keys, bootstrap tokens, JWTs,
  bearer/basic credentials, `password=`/`token=`-style values, the configured join
  token) and bounds sizes; a separate level lets the gateway decide who may see logs
  and at what rate, independently of structured state. `ListUnits` is structured and
  stays `READ`.
- Configuration: `ValidateConfig` → `ApplyConfig` with `expected_generation`; strict
  validation, no templates. Secrets (`SecretString`) are write-only; `GetConfig` returns
  their SHA-256 only.
- Updates: trust comes only from the `SHA256SUMS` signature by the release key built
  into the image — never from the channel URL or its scheme. The image's channel is the
  default; `NodeConfig.update_channel` (ApplyConfig, `DESTRUCTIVE`) may replace the
  server (https + its CA only), never the key. An unusable override fails `StageUpdate`
  rather than falling back to the image channel.
- `GetUpdateStatus.operation` (field 8, `OperatorOperation`, `OperationPhase` with `OPERATION_PHASE_UNSPECIFIED = 0`) was
  added in alpha: the running or last Rollback/RaiseMinVersion (agent/README.md, "Operator operations and dropped calls").
- API version = the protobuf package; it is part of every RPC path, so an agent and a
  client of different versions do not see each other's RPCs. The agent reports its
  version in `GetInfo.api` and in the response header `x-foilbird-api` of every response,
  errors included. An authenticated call to a path the agent does not serve is
  `Unimplemented` naming the agent's version (unauthenticated callers get the usual
  `Unauthenticated`/`PermissionDenied`). foilctl reports such a call as "API version
  mismatch: the agent speaks API X, foilctl speaks API Y"; for an agent that does not
  report its version it probes `GetInfo` under the packages of earlier releases.
- `proto/foilbird/agent/discovery.proto` — `Discovery.GetApiVersions` in the unversioned package `foilbird.agent` (ADR 0016):
  the agent's release and the API packages it serves; any client of the agent's CA may call it, whatever its role.
  `foilctl` asks it first and refuses an agent that does not serve its package before any call. Frozen: its surface is
  `discovery.fields`, checked by `tools/check_proto.py`.
- Boot confirmation is local (decision 0003): the agent confirms the boot when its health
  checks pass and re-arms the boot counter. There is no RPC to confirm a boot from outside.

## Rendered configuration: `/run/foilbird/config/<name>`
The agent (or, until it is deployed, the temporary credentials bridge) writes the applied
configuration as files, one per name, mode 0600 for secrets and 0644 otherwise. Consumers
read only these files.

| File | From | Format |
|---|---|---|
| `node.hostname` | `NodeConfig.hostname` | host name, one line |
| `node.network` | `NodeConfig.network.interfaces[0]` | systemd-networkd `.network`, same as the bridge. The agent also installs every interface as `/run/systemd/network/50-foil-<index>.network`; with one interface (the PoC case) both are identical |
| `k8s.join` | `NodeConfig.k8s` | kubeadm `JoinConfiguration` YAML (`kubeadm.k8s.io/v1beta4`): `discovery.bootstrapToken.{apiServerEndpoint,token,caCertHashes}`, `nodeRegistration.name` = hostname. Mode 0600. |
| `k8s.init` | `K8sConfig.init` | control plane v0 (`NodeConfig.role` = `NODE_ROLE_CONTROL_PLANE`; the join fields are for `NODE_ROLE_WORKER`): kubeadm `InitConfiguration` + `ClusterConfiguration` (`kubeadm.k8s.io/v1beta4`) as given by the operator. Mode 0600. |
| `k8s.ca.crt`, `k8s.ca.key` | `K8sConfig.cluster_ca_crt`, `cluster_ca_key` | the operator's cluster CA (with `init` only); the key 0600. `foil-kubeadm-init.service` copies them to `/etc/kubernetes/pki` before `kubeadm init`. `GetConfig` returns `init`, the key and the token only as SHA-256 |
| `k8s.node-labels` | `K8sConfig.node_labels` | `key=value` joined by `,`, sorted by key |
| `k8s.node-taints` | `K8sConfig.node_taints` | `key=value:Effect` joined by `,` (`NoSchedule`, `PreferNoSchedule`, `NoExecute`) |
| `generation` | | applied generation number, one line |

Outside `/run/foilbird/config` (other consumers):

| File | From | Format |
|---|---|---|
| `/run/foilbird/containerd/certs.d/<registry>/hosts.toml` | `NodeConfig.registries` | containerd hosts.toml. Without mirrors: `server` = the registry (`https://registry-1.docker.io` for `docker.io`) and `ca`. With mirrors the registry is never contacted (no silent fallback): mirrors 0..n-2 as `[host."https://<endpoint><prefix>"]` in order, the last mirror as `server`; each with `capabilities = ["pull", "resolve"]`, `override_path = true` when a prefix is set, `ca`. CA files `ca.crt`, `mirror-<n>.crt` re-encoded from the parsed certificates. The tree is replaced as a whole; absent without registries. The k8s-worker containerd `config_path` includes it |
| `/run/foilbird/hosts` | `NodeConfig.extra_host_entries` | hosts(5): localhost lines, then `<ip> <names…>`; always written. `/etc/hosts` in the image links to it |

Labels and taints are not put into `k8s.join`; the `k8s-worker` profile passes them to
kubelet itself.
