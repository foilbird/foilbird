# A/B updates (Debian image)

Status: proof of concept, `images/debian/mkosi`. Decisions: [0002](decisions/0002-update-staging.md) (staging),
[0003](decisions/0003-boot-loop-recovery.md) (boot loop, recovery). Boot assessment: [boot-assessment.md](boot-assessment.md).

## Layout

| Partition | Created by | Size | Label |
|---|---|---|---|
| ESP | image build | 512M | `esp` |
| `/usr` slot A: erofs + verity hash + verity signature | image build (`mkosi.repart/`) | 2560M + 32M + small (see below) | `usr_<release>`, `usr-verity_<release>`, `usr-verity-sig_<release>` |
| `/usr` slot B | first boot: `foil-repart.service` on the host from `/usr/lib/foilbird/repart.d` (the initrd runs no repart) | same | `_empty` until the first update |
| reserved state (v1-alpha: empty, see below) | first boot, same (`25-state.conf`) | 256M | `_reserved-state`, type `linux-generic` |
| `/var` | first boot, same | rest of the disk | `var` |

Slot size: every later release must fit the slot the first image created. Measured 16.11.2026 on the k8s-worker image
with NVIDIA 580.196.07 and Kubernetes 1.34.3: erofs (uncompressed) 1403.7 MiB, of it NVIDIA ≈777 MiB, Kubernetes and
containers ≈348 MiB, kernel modules 115 MiB. With 1700M that left 17 %; expected growth within the supported versions
(NVIDIA branch +40…120 MiB, Kubernetes minors +15…30 MiB, kernel ±5 MiB) would leave 7–14 %. 2560M leaves 45 % now and
≥38 % after that growth; the verity hash tree of 2560M (≈20 MiB) still fits 32M. A node partitioned with a smaller slot
cannot take a release built for a larger one (no such nodes exist).

### Reserved state partition (v1-alpha)

`/usr/lib/foilbird/repart.d/25-state.conf` reserves 256 MiB between slot B and `/var` (ADR 0006). In v1-alpha nothing
formats, encrypts, opens or mounts it: no `Format=`, no `Encrypt=`, no unit refers to it. It exists so that a later release
can move the node's own state out of `/var` without reinstalling the node: `/var` takes the rest of the disk and ext4 on
LUKS2 cannot be shrunk online, so a partition cannot be added to an installed node later. The migration will set the
final GPT type and label (table entries only, no data moves), then encrypt and format it.

What the state partition is for, and its size:

| Content (moved from `/var` by a later release) | Today | Bound |
|---|---|---|
| node configuration `config.pb` + `generation`, a second copy per schema/release (ADR 0005) | `/var/lib/foil-agent` | a `NodeConfig` arrives in one gRPC message (4 MiB limit): ≤ 8 MiB for two copies; real configs, with an inline cluster CA, are tens of KiB |
| anti-rollback floor, committed releases, `/var` epochs and epoch keys | `/var/lib/foilbird` | < 1 MiB |
| node identity: agent TLS key, certificate and CA chain; later registration credentials (TPM AK/EK certificates) | ESP bridge / credentials | < 1 MiB |
| control plane PKI and kubeconfigs (`/etc/kubernetes/pki`, `*.conf`) | `/var` | kubeadm writes about 30 files, < 1 MiB |
| **not** in it: update downloads (`/var/lib/foil-agent/staging`, a release is ≈ 2.7 GiB), etcd data (stays on `/var` in v1-alpha), logs, container images | `/var` | — |

Overhead on 256 MiB (measured 21.11.2026 on Debian 13): LUKS2 header 16 MiB (cryptsetup default), ext4 on the
remaining 240 MiB leaves 219 MiB free (12 MiB of it reserved for root unless formatted with `-m 0`). Against a worst case
of ≈ 10 MiB of content that is a margin of about 20×, against real contents (< 2 MiB) more than 100×; the margin is for
contents a later release adds (history of configurations, more certificates) without a new partition. For comparison,
Talos reserves 100 MiB for STATE and 1 MiB for META. 256 MiB is 1.5 % of a 16 GiB disk.

`foil-repart.service` runs only on a fresh installation, while the boot disk has no `/var` partition
(`ConditionPathExists=!/dev/disk/by-partlabel/var`); slot B, the state partition and `/var` are written in that one run.
There every partition is required: a disk without room for all of them fails the unit and with it the installation
(no `/var`), instead of a layout without the state partition (the fixed partitions take 5.8 GiB, `/var` needs at least
1 GiB). **Nodes installed before the state partition existed are not migrated**: they have `/var`, the unit is
skipped, their layout stays as it is, and a release that needs the state partition requires reinstalling them.
The same holds for any partition a later release defines (for example a small unencrypted META partition): since
`foil-repart.service` never runs on a node that has `/var`, new partition definitions apply only to fresh
installations; an installed node gets them only by reinstalling. This is a decision (one repartitioning, at
installation, never on a node with data), not a defect.

The slot size is fixed: `systemd-sysupdate` writes a release into an existing partition, so every later `/usr` must
fit. The kernel command line (inside the signed UKI) carries `usrhash=`; the initrd finds the data and hash partitions by
partition UUIDs derived from the root hash, so the update channel carries the UUIDs in its file names (`@u`).

## Update channel

Files per release, all listed in `SHA256SUMS` with a detached `SHA256SUMS.gpg` (release key):

```
<image-id>_<release>.usr-x86-64.<uuid>.raw.xz
<image-id>_<release>.usr-x86-64-verity.<uuid>.raw.xz
<image-id>_<release>.usr-x86-64-verity-sig.<uuid>.raw.xz
<image-id>_<release>.efi
```

Transfers: `/usr/lib/sysupdate.d/` (UKI last; until it is on the ESP the new slot cannot boot). The source URL in the
tree is a placeholder; `images/debian/build-image.sh --channel <url>` writes the deployment's channel into the image
(`/usr/lib/foil-agent/channel` and every `Path=`, checked by `mkosi.finalize`). Staging (decision 0002) replaces direct
download.

## Install from the agent's staging (decision 0002)

The agent downloads and checks a release into `/var/lib/foil-agent/staging/current` and starts `foil-install@<v>`. The
installer does not rely on that check: `foil-var-epoch stage-<v>` (ExecStartPre) copies the staged files into
`/var/lib/foilbird/staged/<v>`, outside the agent's writable paths (a copy, not a move: the agent could keep a file open),
and checks the copy: `SHA256SUMS` signed by the release key in `/usr`, every copied file listed with its hash (the
channel's `SHA256SUMS` may list other releases; a file without a line is refused), the UKI's `.osrel` version, and the
floor (`<v>` not below `/var/lib/foilbird/min_version` or the booted `FOILBIRD_MIN_VERSION`). `systemd-sysupdate --component=staged`
reads only `/var/lib/foilbird/staged/current`; the copy is removed after the install. Verified in QEMU: a file changed
after the agent's check, an unlisted file, and a release below the floor are refused before anything is written.

## Pitfalls found in the PoC (keep these)

| # | Pitfall | Where verified | What the image does |
|---|---|---|---|
| 1 | Without `ProtectVersion=%A` sysupdate treats the newest *installed* release as current and may erase the booted slot (seen: booted N, installed bad N+1, update to N+2 overwrote the live `/usr`, then an endless loop) | 259 and 257 (Debian: `list` shows the bad newest release as `current`; with the setting the bad one is vacuumed, not the booted one) | `ProtectVersion=%A` in every transfer |
| 2 | Space is freed **before** the download is verified: a rejected update leaves one bootable release | 259 and 257 (Debian: `Removing old …` before `DOWNLOAD INVALID: Checksum …`) | decision 0002: the agent verifies the whole release in staging before the installer runs; verified on Debian (below) |
| 3 | The stock `systemd-sysupdate.timer` / `systemd-sysupdate-reboot.timer` update and reboot on their own; a `disable` preset did not stop them on an image with empty `/etc` | 259; 257: removed in the image too | units removed (`RemoveFiles=`) |
| 4 | Debian 13 ships `/usr/lib/systemd/import-pubring.gpg` with **Fedora, Ubuntu and openSUSE signing keys**; systemd 257 reads that name (259 reads `.pgp`). With the default file, `Verify=yes` accepts channels signed by any of them | 257 | the build must put the release key under both names; `mkosi.finalize` refuses an image with the default keyring |
| 5 | systemd-pull 257 in Debian 13 has no zstd: a `.zst` source is written to the partition **compressed**, sysupdate reports success (the hash covers the download), the slot fails in the initrd | 257 | channel uses `.xz` |
| 6 | A slot that fails in the initrd (here: verity setup) drops into emergency mode and never reboots, so its try is not spent and there is no rollback | 257 | emergency/rescue reboot in the initrd and the system (`docs/image-policy.md`); verified: three reboots → previous release |
| 7 | `InstancesMax=` belongs to `[Target]` | 259 | done |

## Verified on Debian 13 (systemd 257.13, QEMU/OVMF Secure Boot, 15.11.2026)

| Test | Result |
|---|---|
| update 1 → 2 from the signed channel | written in 27–33 s; with the preset policy release 2 boots and is committed (an earlier run failed the boot check because preset-enabled `systemd-pcrlock-make-policy.service` failed) |
| tampered `/usr` file in the channel | `DOWNLOAD INVALID: Checksum …`, nothing installed (after the old slot was freed, pitfall 2) |
| `SHA256SUMS.gpg` by another key | `Can't check signature: No public key`, nothing touched |
| SIGKILL and hard reset during the write | the booted release boots, the next update succeeds |
| one corrupted byte in the new `/usr` (erofs superblock) | `dm-verity device corrupted` → reboot, three times → previous release |
| release whose boot check fails | three tries → `+0-3` → previous release |

| broken verity metadata of the new slot (fails in the initrd) | three reboots ("emergency mode is disabled, rebooting") → previous release |

| both slots bad: `/usr` of the committed, re-armed release 2 and of release 1 corrupted | 2, 2, 2, 1, 1, 1 → recovery entry (no loop); recovery reports both slots `CORRUPT`, the partition table and both slots unchanged; an intact slot is reported `OK`. **Withdrawn with the re-arm (decision 0003, amendment):** a corrupted committed release now reboots in a loop (an open limitation); the recovery diagnosis itself is unchanged |

| rejected update with staging (pitfall 2): release 3 whose `/usr` was changed after signing, image with the agent | `StageUpdate` fails with `HashMismatch`, the installer never runs, both slots byte-identical, both entries on the ESP; with 2 marked exhausted release 1 boots and opens `/var` |

Boot counting, ESP check and recovery entry: [boot-assessment.md](boot-assessment.md) (decision 0003).
