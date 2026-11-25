# Architecture

What a Foilbird node is made of and how it is managed. The overview diagram is in the
[README](../README.md#architecture). What each security property rests on, and its limits, is in
[threat-model.md](threat-model.md); this document states how the parts fit and links to the document that owns each
part. What v1-alpha has and has not verified is listed only in the [release notes](release-notes/v1-alpha.md).

## Parts

| Part | What it is | Owned by |
|---|---|---|
| image | Debian 13 binary packages, unmodified, built with mkosi; no shell, interpreter, network client or package manager beyond the image policy | [decision 0001](decisions/0001-base-distribution.md), [image-policy.md](image-policy.md), `images/debian/` |
| boot chain | UEFI Secure Boot with the deployment's keys → systemd-boot → signed UKI; the kernel command line inside the UKI carries `usrhash=` | [decision 0012](decisions/0012-release-signing-and-keys.md), [install.md](install.md) |
| `/usr` | erofs on dm-verity with a signed root hash, read-only; two slots, A and B | [updates.md](updates.md) |
| root and `/etc` | tmpfs: nothing written there survives a reboot; no system or configuration extensions | [decision 0007](decisions/0007-no-system-extensions.md) |
| `/var` | ext4 on LUKS2, one TPM2 key slot (PCR 7 and a signed PCR 11 policy), key epochs and an anti-rollback floor | [disk-encryption.md](disk-encryption.md) |
| node agent | `foil-agent` (Rust): the only management interface; client `foilctl` | `agent/README.md` |
| API | gRPC over mutual TLS, typed operations only, one access level per RPC | `api/README.md`, [decision 0016](decisions/0016-api-versions.md) |
| profiles | `k8s-worker` (v1-alpha); `container-host` (named in the API, not built in v1-alpha) | `profiles/k8s-worker/README.md`, [decision 0014](decisions/0014-product-scope.md) |

## Disk layout

ESP, `/usr` slot A (data, verity hash, verity signature), `/usr` slot B, a reserved `state` partition and `/var`.
The installation image carries the ESP and slot A; slot B, `state` and `/var` are created once, on the first boot of a
fresh installation, and never on a node that already has `/var`. Sizes and labels: [updates.md](updates.md), "Layout".

## Management path

1. A client connects to the agent over mutual TLS. Its certificate must chain to the agent's client CA; the role is the
   certificate's OU (`reader`, `controller`, `operator`).
2. Every RPC has exactly one access level (`READ`, `DIAG`, `OPERATE`, `DESTRUCTIVE`, `EMERGENCY`); the role decides
   which levels it may call. Denied and allowed calls are audited on the node.
3. No RPC carries a command, a script, a file path, a binary or a URL; network locations are typed parts. The agent
   uses privileged mechanisms of the node internally (systemd, the update tooling); none of them is reachable as such
   through the API.
4. Configuration is one typed `NodeConfig`: `ValidateConfig`, then `ApplyConfig` with the expected generation
   ([decision 0005](decisions/0005-config-schema-and-application.md)). The applied configuration is rendered into
   `/run`, so it is rebuilt from `/var` on every boot.

The access levels, the role table and the rules for new fields are in `api/README.md` and `agent/README.md`,
"Authorization".

## Update path

1. The operator stages a release (`StageUpdate`). The agent fetches the channel's `SHA256SUMS`, checks its signature
   with the release key built into the image (never trusting the channel's address) and writes the release into the
   free slot with `systemd-sysupdate` ([decision 0002](decisions/0002-update-staging.md)).
2. A release below the anti-rollback floor is refused; the floor is the higher of the one built into the image and the
   one on `/var` ([disk-encryption.md](disk-encryption.md)).
3. The new UKI boots with a try counter. The agent confirms the boot only when its health checks pass; until then every
   failed or hung boot spends a try, and after the last one systemd-boot boots the previous release
   ([boot-assessment.md](boot-assessment.md), [decision 0003](decisions/0003-boot-loop-recovery.md)). There is no RPC to
   confirm a boot from outside.
4. `Rollback` boots the previous release on the operator's request; `RaiseMinVersion` raises the floor and wipes the
   key slots of older epochs, so an older release can no longer open `/var`.

## Profiles

- **`k8s-worker`, roles**: containerd and kubelet, rootful, as Kubernetes expects. One image serves both roles of
  `NodeConfig.role`: `NODE_ROLE_WORKER` (kubeadm join) and `NODE_ROLE_CONTROL_PLANE` (kubeadm init, control plane v0,
  stacked etcd in `/var/lib/etcd`). The role is set at installation; the role does not change without a reinstall
  (`profiles/k8s-worker/README.md`, "Node role (`NodeConfig.role`)"; [install.md](install.md), "Reinstalling"). Pods are
  bounded by the cluster's admission policy, not by the OS ([decision
  0010](decisions/0010-root-on-the-node-and-var-recovery.md)).
- **`k8s-worker`, `gpu` variant** (`images/debian/tools/build-all.sh --variant gpu`): the NVIDIA open kernel modules
  610.57.04, built by DKMS at image build time and signed with the image's db key, and `nvidia-ctk` with CDI (GPU
  variant only). **Experimental**: built, not run on a GPU in v1-alpha ([release notes](release-notes/v1-alpha.md), "GPU
  support: experimental, hardware check deferred").
- **`container-host`** (not in v1-alpha): rootless Podman with Quadlet by default, rootless Docker allowed, workloads
  declared through the agent and checked against a policy. Its security contract is
  [decision 0014](decisions/0014-product-scope.md), item 4; it gets its own design record before it is built.

## Interfaces that are not in v1-alpha

- **MCP.** The agent API is the primary interface; an MCP adapter derived from the `.proto` is the target for automation
  and LLM clients, never a path to a shell ([decision 0014](decisions/0014-product-scope.md), item 6). v1-alpha has no
  MCP adapter.
- Plan and apply by plan id, dry run, `TRY` with a local revert, node registration, a rollout controller and
  break-glass access are deferred ([decision 0013](decisions/0013-deferred-in-v1alpha.md)).
