# NVIDIA compatibility matrix

A row is a **verified combination**, not a driver number. "Verified" means: image built from the listed sources,
booted under Secure Boot with `lockdown=integrity module.sig_enforce=1`, all NVIDIA kernel modules accepted, and the
listed checks passed on the listed GPU. No load tests unless stated.

| Base | Kernel | NVIDIA kernel modules | NVIDIA user space | CUDA (driver API) | Module signature | GPU | Checks | Date | Status |
|---|---|---|---|---|---|---|---|---|---|
| Debian 13 | 6.12.117+deb13-amd64 | open 610.57.04, DKMS in build stage | 610.57.04 (NVIDIA repo `debian13`, key 0218…F200) | — | the deployment's db key | **none** | image build only: chain check, 5/5 modules signed; no boot on a GPU | 2026-11-21 | **experimental**: built, not validated on GPU hardware |
| Debian 13 | not recorded | open 580.196.07, DKMS in build stage | 580.196.07 (NVIDIA repo `debian12`) | — | db key of that build (platform keyring) | A100 80GB PCIe, passed through to a virtual machine | pre-release cycle: install, Kubernetes join, device plugin and CDI, inference workload under load, reboots, A/B update and rollback of the GPU node | 2026-11-20 | passed for that pre-release; not repeated with 610.57.04 |
| Debian 13.7 | 6.12.117+deb13-amd64 | open 580.196.07, DKMS in build stage | 580.196.07 (NVIDIA repo `debian12`) | 13.0 | db key of that build (platform keyring) | A100 80GB PCIe | modprobe, nvidia-smi, cuInit + context + 1 MiB alloc | 2026-11-15 | accepted for PoC |
| Debian 13 | 6.12.107, .111, .113, .115, .116, .117 | open 580.196.07, DKMS | — | — | db key of that build | — | DKMS build only | 2026-11-15 | build verified |
| Debian 13 | 6.12.117 | open 580.105.08 | — | — | — | — | **does not build**: `pci_resize_resource` API change backported in 6.12.100 | 2026-11-15 | rejected |
| Ubuntu 26.04 | 7.0.0-43-generic | open 580.178.04, Canonical package | 580.178.04 (Ubuntu archive) | 13.0 | Canonical | A100 80GB PCIe | modprobe, nvidia-smi | 2026-11-15 | fallback |

Rules:
- The driver version is pinned in the image profile, the build manifest and the SBOM.
- Every Debian security kernel is test-built against the pinned driver before release; the time from the kernel
  appearing in the security archive to a verified image is recorded per release.
- Not yet covered: NCCL, multi-GPU, MIG, GPU sharing (HAMi), other GPU models.
