# v1-alpha release notes

v1-alpha is the first public state of the project: **source code and build recipes only**. The release is a source
tag and nothing else: the project publishes no binary and no built image, none with NVIDIA components either, and no
signing key. You build images yourself, with your own keys ([install](../install.md)). The node agent API may still
change incompatibly.

This file is the one list of what v1-alpha does not do or has not verified. Other documents link here instead of
repeating it.

## Where it was verified

**Everything was verified in virtual machines; nothing on bare metal.**

| What | Where | Result |
|---|---|---|
| The release cycle without GPU: fresh install of a control plane and a worker, Kubernetes join, reboots (shutdown within 65 s), A/B update, operator rollback, automatic rollback of a broken release (boot counting), anti-rollback floor, the same cycle a second time on the same image | QEMU/KVM, OVMF with Secure Boot, swtpm (software TPM 2.0), user-mode networking and a point-to-point link between the two guests, container images from local mirrors | passed, both cycles, 2026-11-24: every boot with Secure Boot and the TPM on, no failed unit, longest shutdown 46 s; run on the release candidate; this release differs from it only in documentation and source comments (verified by comparing the exported trees) |
| Test harness (`tests/`), seven scenarios: install, configuration, no shell, interpreter or login in `/usr`, A/B update, operator rollback, automatic rollback of a broken release, PCR epoch raise and anti-rollback floor | QEMU/KVM, OVMF Secure Boot, swtpm, in CI (a hosted runner, `debian:trixie` container) on images built in the same job without NVIDIA user space, with TEST keys | 30 of 30 checks passed, none skipped, 2026-11-25; run on the release candidate; this release differs from it only in documentation and source comments (verified by comparing the exported trees) |
| **Last run on GPU hardware** | **an earlier pre-release** (2026-11-20): two virtual machines (QEMU/KVM, OVMF Secure Boot), one control plane and one GPU worker with an **NVIDIA A100 80GB PCIe passed through**, driver **580.196.07**: install, join, device plugin and CDI, an inference workload under load, reboots, A/B update and rollback of both nodes | passed for that pre-release; **not repeated for v1-alpha** (below) |

"Verified" means the checks of the run passed on those machines, with Secure Boot and the TPM on. It does not mean
hardware validation: no physical server, firmware, TPM chip, NIC or disk controller has been tested.

## GPU support: experimental, hardware check deferred

- v1-alpha pins NVIDIA open kernel modules and user space **610.57.04** from NVIDIA's `debian13` repository
  (`images/debian/apt-pin.conf`, `images/debian/apt-pin.lock`). This version has been **built only**: the build verifies NVIDIA's signed
  repository chain and signs all 5 kernel modules with the image key. **It has not been run on a GPU.**
- The last GPU run (table above) used driver 580.196.07 from a pre-release. Its result does not carry over to 610.57.04
  or to the v1-alpha image.
- **Deferred check**, needed before GPU support stops being experimental: on GPU hardware with the v1-alpha image,
  boot under Secure Boot with `lockdown=integrity module.sig_enforce=1`, all NVIDIA modules accepted, `nvidia-smi`,
  CUDA driver init, the device plugin and CDI in a pod, then reboot, A/B update and rollback of the GPU node under a GPU
  workload. No date is set; the result will be added to [docs/compatibility/NVIDIA.md](../compatibility/NVIDIA.md) as
  a new row.
- Not covered at all: NCCL, multi-GPU, MIG, GPU sharing, other GPU models.

## NVIDIA components are never published

NVIDIA's licence terms restrict redistribution of its driver and user space; v1-alpha therefore publishes **no built
artifact that contains NVIDIA components**: no image, no `/usr` partition, no kernel module (`.ko`), no user-space
library, no NVIDIA package cache. Images with NVIDIA components are built by each deployment from NVIDIA's repository
([images/debian/README.md](../../images/debian/README.md), "Third-party apt inputs").

## Known limitations

**Installation and hardware**
- A product image takes the agent's TLS material only from systemd credentials. In a virtual machine they are passed as
  SMBIOS type 11 strings ([install](../install.md)). **On a physical machine v1-alpha has no supported way to pass them**:
  automatic registration (TPM attestation) is not implemented (decision 0013, Z12).
- The credentials passed this way are readable by root on the hypervisor and by root on the node (decision 0010).
- A node needs a usable, unique SMBIOS system UUID: the machine-id is derived from it on every boot
  ([docs/image-policy.md](../image-policy.md)).

**API and compatibility**
- The node agent API (`foilbird.agent.v1alpha1`) may change incompatibly in any later alpha. Agent and `foilctl` must
  come from the same release; a client finds the API versions an agent serves through `Discovery.GetApiVersions`, and a
  mismatch is reported as an API version error (decision 0016).
- Moving from v1-alpha to a later release may require reinstalling nodes. A later release's new partitions apply to
  fresh installations only ([docs/updates.md](../updates.md)).

**Keys and trust**
- The project publishes no signed images. All keys used by CI and the test harness are ephemeral and marked `TEST`; they
  are not a root of trust. Build images with your own keys (decision 0012).
- Integrity of published sources: commit, SHA-256, SBOM and build provenance. No project release key exists yet.
- Secure Boot keys are enrolled on first boot in setup mode (trust on first use).
- Protection against an older, correctly signed release served by a hostile update channel is only the anti-rollback
  floor (`min_version`); release metadata has no expiry yet.
- One client CA: any certificate it issues with the operator role can call every RPC, including EMERGENCY ones.

**Configuration**
- `ApplyConfig` applies at once; there is no dry run, diff, staged or try mode. A configuration that cuts the node off its
  management network is not reverted automatically; recovery is a reinstall.
- The node role (`NodeConfig.role`: worker or control plane) is explicit and required together with Kubernetes
  settings. **The role is fixed for an installation: changing it, or removing the Kubernetes settings, means
  reinstalling the node** (`ApplyConfig` refuses with `FAILED_PRECONDITION`). `foilctl apply` needs `--role` with any
  `--k8s-*` flag.
- A control plane's `k8s.init` must turn on kube-apiserver audit with the image's policy; the operator cannot change the
  audit policy ([profiles/k8s-worker/README.md](../../profiles/k8s-worker/README.md)).
- Node TLS material and the first configuration come from systemd credentials prepared by the operator.

**Disk and state**
- All node state (configuration, identity, key epochs, floor) is on `/var`. Losing `/var` or resetting the TPM means
  reinstalling the node; there is no recovery key (decision 0010). A 256 MiB `state` partition is reserved on fresh
  installations and not used yet.

**Kubernetes**
- One Kubernetes minor per release stream (1.34); minor upgrades are not supported in alpha (decision 0004 is not
  implemented).
- Control plane: single node; etcd on `/var`; losing `/var` loses the cluster state; backups are the operator's job.
- `kubectl debug node/` and pods with `hostPID` / `hostPath: /` are not blocked by the OS; use your cluster's admission
  policy. Such a pod is root on the node (decision 0010).
- Updates are driven node by node by the operator; there is no rollout controller.

**Host**
- No system or configuration extensions (by design, decision 0007).
- `/etc` is writable by root at runtime (tmpfs, empty after every reboot); a read-only `/etc` is not implemented.

The register of decisions accepted for v1 but not implemented is [decision 0013](../decisions/0013-deferred-in-v1alpha.md).
