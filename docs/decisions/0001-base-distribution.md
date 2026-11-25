# 0001. Base distribution

- Status: accepted (2026-11-15)

## Decision
Debian 13 (trixie) is the primary base. Ubuntu 26.04 LTS is kept as a tested fallback
until several Debian security-kernel cycles have gone through the full pipeline.

## Context (measured in the PoC)
- Kernel fix in linux-stable → package in the security archive, median: Debian 13 — 1 day
  (n=8; there was a 140-day gap without security kernels in 2025–26); Ubuntu 26.04 GA — 59 days.
- Ubuntu ships prebuilt, Canonical-signed NVIDIA open modules; Debian ships only DKMS.
  With Secure Boot both kernels accept modules signed by a certificate in UEFI db
  (platform keyring), so the project builds NVIDIA modules at image build time and signs them.
- The whole boot stack (systemd-boot, ukify, repart, sysupdate) is in Debian `main`.
- Debian's trademark policy has no "modified images require approval" clause.

## Consequences
- The project owns an NVIDIA module pipeline per security kernel (DKMS → sign → image).
- Debian backports kernel API changes into stable; NVIDIA releases may stop building
  (seen with 580.105.08 on 6.12.100). The pipeline must test-build every security kernel.
- containerd 2.x is packaged by the project from upstream.
