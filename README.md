# Foilbird

An immutable, API-managed operating system for Kubernetes nodes, assembled from unmodified binary packages of Debian 13.

**Status: v1-alpha.** The project publishes source code and build recipes only, no built images. What has
been tested was tested in QEMU/KVM virtual machines, never on bare metal; the pinned GPU driver has not run on a GPU, and
GPU support is **experimental**. Read the
[release notes](docs/release-notes/v1-alpha.md) for what is and is not verified before you build anything. Nothing
here is ready for production use.

## Design in one paragraph

The image is built with [mkosi](https://github.com/systemd/mkosi) from Debian 13 packages. It boots a signed Unified
Kernel Image (UKI) under UEFI Secure Boot with the **deployment's own keys** (the project ships no keys); `/usr` is a
read-only erofs file system on signed dm-verity; the root file system is a tmpfs, so nothing written to `/etc` survives
a reboot; `/var` is LUKS2, bound to the TPM. Updates are A/B with boot counting and automatic rollback
(`systemd-sysupdate`, signed `SHA256SUMS` of the update channel). There is no shell, no SSH, no console login and no
package manager on the node. It is managed through a typed gRPC API over mutual TLS by a node agent written in Rust
(`foil-agent`, client `foilctl`).

## Architecture

![Foilbird architecture](docs/images/architecture.svg#gh-light-mode-only)
![Foilbird architecture](docs/images/architecture-dark.svg#gh-dark-mode-only)

Legend (dashed = roadmap):
- `foil-agent`: typed API, no exec, one access level per RPC, audit ([api/README.md](api/README.md)).
- `control-plane v0` (kubeadm init, stacked etcd), `worker` (kubeadm join): one build; the role (`NodeConfig.role`) is
  set at installation and changed only by a reinstall ([profiles/k8s-worker/README.md](profiles/k8s-worker/README.md),
  "Node role (`NodeConfig.role`)").
- `gpu: NVIDIA 610, experimental`: NVIDIA open modules 610.57.04 signed with the image's db key, nvidia-ctk / CDI;
  built, not run on a GPU in v1-alpha ([release notes](docs/release-notes/v1-alpha.md), "GPU support: experimental,
  hardware check deferred").
- `container (roadmap)`: the `container-host` profile, rootless Podman or Docker; not in v1-alpha
  ([decision 0014](docs/decisions/0014-product-scope.md), items 4 and 5).
- `MCP adapter (roadmap)`: not in v1-alpha; the LLM agent connects through it; MCP is an adapter derived from the API,
  never a path to a shell ([decision 0014](docs/decisions/0014-product-scope.md), item 6).

What holds and what checks it:
- Clients reach a node only through the agent over mutual TLS; the role is the client certificate's OU
  ([api/README.md](api/README.md); T12; `RaiseMinVersion` operator only, harness scenario `70-epoch`).
- No RPC carries a command, script, path or URL (T8); the image has nothing to log in with or to run a script with (T5).

  > **v1-alpha limitation** (fix planned for v1-alpha4): a control plane's `k8s.init` is passed to `kubeadm init` as
  > given, so on a node without a role `ApplyConfig` with it is equivalent to root
  > ([api/README.md](api/README.md#rules), "Rules").
- `/usr` is erofs on signed dm-verity, booted from a signed UKI under Secure Boot; `/var` is LUKS2 bound to the TPM, and
  a release below the anti-rollback floor does not open it (T3, T20b; [decision
  0010](docs/decisions/0010-root-on-the-node-and-var-recovery.md)).
- Updates are A/B from a signed `SHA256SUMS` (T10); a release that fails the boot gate is left by the node itself (T7).
- `container-host` is outside v1-alpha: rootless runtime, a container escape does not give persistence and root control
  of the node, within the limits of [decision 0014](docs/decisions/0014-product-scope.md), item 4.

Details: [docs/architecture.md](docs/architecture.md); what each security claim rests on:
[docs/threat-model.md](docs/threat-model.md).

## Documents

| Document | Contents |
|---|---|
| [docs/release-notes/v1-alpha.md](docs/release-notes/v1-alpha.md) | what v1-alpha is, what was verified where, known limitations, the deferred GPU check |
| [docs/architecture.md](docs/architecture.md) | components, boot chain, disk layout, management and update paths, profiles |
| [docs/threat-model.md](docs/threat-model.md) | each security claim with the decision and the test it rests on |
| [docs/install.md](docs/install.md) | build an image with your keys and install a node in a virtual machine |
| [docs/decisions/0010-root-on-the-node-and-var-recovery.md](docs/decisions/0010-root-on-the-node-and-var-recovery.md) | threat model and its limits: what root on a running node can and cannot do |
| [docs/decisions/](docs/decisions/) | architecture decision records |
| [SECURITY.md](SECURITY.md) | how to report a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | licence, DCO sign-off, ground rules |

## Layout

| Path | Contents |
|---|---|
| `images/debian/` | base image (Debian 13): UKI, signed verity `/usr`, initrd without a shell, recovery entry, build script |
| `profiles/k8s-worker/` | Kubernetes node profile (containerd, kubelet, kubeadm, NVIDIA driver and container toolkit in the GPU variant) |
| `agent/` | node agent and `foilctl` (Rust), systemd units, reproducible release build |
| `api/` | the agent's gRPC contract (`.proto`) and its rules |
| `deploy/` | Kubernetes manifests used with the image (device plugin) |
| `tests/` | test harness: boots an image in QEMU with OVMF Secure Boot and a software TPM |
| `docs/` | design documents, decision records, compatibility matrix, compliance register |

## Upstream

Debian 13 (trixie) is the base (decision 0001): kernel security fixes reach `trixie-security` within days of
linux-stable. The NVIDIA open kernel modules are built from NVIDIA's repository at image build time (DKMS in the build
stage only) and signed with the deployment's Secure Boot key; the node has no compiler and no DKMS. NVIDIA's licence
terms restrict redistribution of its driver and user space; v1-alpha therefore publishes no artifact that contains them
(`docs/compliance/`). Building the GPU profile downloads NVIDIA's packages from NVIDIA; whoever builds it accepts NVIDIA's
licence terms ([NVIDIA Driver License](https://www.nvidia.com/en-us/drivers/nvidia-license/)).

## License

Apache License 2.0, see [LICENSE](LICENSE). Contributions require a DCO sign-off, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Trademarks

Foilbird is not affiliated with Debian. Debian is a registered trademark owned by Software in the Public Interest, Inc.

Linux® is the registered trademark of Linus Torvalds in the U.S. and other countries.

Kubernetes® is a registered trademark of The Linux Foundation in the United States and/or other countries.

NVIDIA and the NVIDIA logo are trademarks and/or registered trademarks of NVIDIA Corporation in the U.S. and other countries.
