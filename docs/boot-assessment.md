# Boot assessment: when a boot counts as successful

Status: proof of concept (Debian image, `images/debian/mkosi`). Decision: [0003](decisions/0003-boot-loop-recovery.md).

A new release boots from a boot entry with a try counter. The entry is committed only after the node confirms it is
healthy. Until then every failed or hung boot spends one try, and an entry with no tries left is skipped by the boot
loader, so the previous release boots. This document is the contract between the image (boot chain, ESP, counters) and
the node agent (health decision).

## Mechanism (owned by the image)

| Piece | What it does |
|---|---|
| UKI file names | `/EFI/Linux/<image-id>_<version>.efi` = committed; `<image-id>_<version>+<left>-<done>.efi` = being assessed; `+0-<n>` = exhausted ("bad"), sorted last by systemd-boot. `systemd-sysupdate` installs a new release as `+3-0` |
| disk image | the UKI on the ESP of the installation image is `foilbird-deb_<version>+3-0.efi` (`mkosi.conf.d/70-uki-name.conf`, `UnifiedKernelImageFormat=`), the name an update gets: visible to sysupdate and to Rollback after the first A/B, and the first boot is counted and blessed like any other. So the first boot from the disk is under the gate as well: 3 failed checks → `+0-3` → the recovery entry (there is no other slot yet). A node that is not configured yet passes the gate: the network-config check is Skipped without a network config, and without a join there are no kubelet checks |
| systemd-boot | on every boot of a counted entry renames it (`+3-0` → `+2-1` …) **before** starting it, so a crash, a hang reset or a reboot all count |
| `boot-complete.target` | pulled in by `systemd-bless-boot-generator` only when the current entry has a counter |
| `systemd-bless-boot.service` | `After=boot-complete.target`; renames the entry to the committed name (counter removed). Runs only on a counted boot (`systemd-bless-boot.service.d/50-foil-counted-only.conf`: `ConditionPathExists=` the `LoaderBootCountPath` EFI variable, as the upstream generator decides): `foil-boot-committed.service` pulls it in on every boot, and on a committed `<v>.efi` (no counter since re-arm was withdrawn, decision 0003) it would fail every time |
| ESP | mounted at `/boot` (vfat, rw) by `systemd-gpt-auto-generator` as an automount: mounted on first access, unmounted after 60 s idle (`boot.automount.d/50-foil-esp.conf`); no unit requires `boot.mount` (no `/boot` in `RequiresMountsFor=`): the idle stop of the mount would cancel a unit bound to it (install, rollback), they reach `/boot` by path with `After=boot.automount`, and the build fails on such a requirement (`mkosi.finalize`), vfat `flush,noatime` (`boot.mount.d/50-foil-esp.conf`; its `Options=` replaces the generator's line, so it repeats the generator's options: the drop-in pins the systemd version they were read on, and the build fails on another systemd version or if one of them is missing). Before the first mount of a boot `systemd-fsck@` checks and repairs it (`fsck.fat -a`, the only dosfstools binary in the image; the generator adds the dependency because `fsck.vfat` exists). So a FAT left dirty by a power loss is repaired before bless, sysupdate, Rollback or the agent touch it, and for most of the uptime it is not mounted at all. A FAT that turns `ro` during the uptime (an error found while mounted) is repaired only by a reboot: `systemd-fsck@` stays active (`RemainAfterExit`), so a later mount after an idle unmount runs without fsck; GetHealth `esp-writable` says so (CRITICAL, "reboot the node"). The agent reads it, it never writes it; it touches it only for the `esp-writable` probe (at most every 10 min at rest) and the boot counter (only while mounted) |
| current entry | EFI variable `LoaderEntrySelected` (`bootctl status`, "Current Entry"), id without the counter |
| booted release | `IMAGE_VERSION` in `/usr/lib/os-release` (not `systemd-sysupdate list` "current", which is the newest *installed* release) |

No re-arm (decision 0003, amendment of 2026-11-16): a committed release keeps `foilbird-deb_<v>.efi` and is not counted again, as
in systemd and Talos. A healthy boot of a committed release writes nothing to the ESP (checked: the ESP bytes are the same
before and after two boots); for that the image also has no `systemd-boot-random-seed.service` and no seed file, which
systemd-boot would otherwise rewrite on every boot. A committed release that breaks
later (corrupted `/usr`) reboots in a loop until a watchdog or an operator intervenes (an open limitation, decision 0003).

UKI names in steady state: `+3-0` = installed, never booted; `+N-M` = being assessed; no counter = committed;
`+0` / `+0-N` = abandoned (operator Rollback / tries exhausted). `+3` (no done count) appears only on entries re-armed by
an older image. The agent reads these names, it never renames them.

## Recovery entry (decision 0003)

`images/debian/recovery` builds `foilbird-recovery.efi`, a UKI with the whole system in its initrd, signed with the same
Secure Boot key. `build.sh` stages it in `recovery/out/`, and the slots image copies it onto the ESP
(`mkosi.conf.d/60-recovery.conf`). It is independent of the A/B slots and is not touched by an update: sysupdate
matches only `foilbird-deb_@v…`, and the Rollback unit renames only the booted release.

| Property | How |
|---|---|
| place in the menu | no counter, `IMAGE_ID=foilbird-recovery`. systemd-boot sorts entries with no tries left (`+0-N`) last, the rest by `IMAGE_ID` (`foilbird-deb` < `foilbird-recovery`), so the recovery comes after a bootable slot and is the default once both slots are `+0-N` |
| read-only | ESP mounted `ro` (`boot.mount`, no gpt-auto), no partition is opened read-write, no getty and no shell |
| diagnosis | `foil-recovery-diag` (C, no shell): per slot `usr_<v>` the root hash from `usr-verity-sig_<v>` (the signature itself is not checked) and `veritysetup verify` of data against hash tree; the ESP entries with their counters. Console and `/run/foilbird-recovery/report` |
| /var | not mounted; with a TPM-bound `/var` it cannot be unlocked either (the recovery is a different UKI) |

Not done yet: driving the recovery from the management plane (network and the agent in the recovery), and updating the
recovery UKI itself.

## Contract for the health check (owned by the agent)

The agent's `foil-boot-check.service` (`agent/systemd/`) decides "healthy":

- `RequiredBy=boot-complete.target`, `Before=boot-complete.target`, `FailureAction=reboot`, `TimeoutStartSec=` bounded:
  a failed **or hung** check reboots right away and so spends one try.
- Exit 0: all mandatory checks of the profile passed; `boot-complete.target` is reached and the entry is committed.
  After the last failed try the previous release boots.
- `WantedBy=multi-user.target` as well, so the check also runs on a committed entry (no counter, no
  `boot-complete.target`); there its result affects nothing in the boot chain, it is only reported.
- Result for the API: `/run/foilbird/boot-check.result` (`PASS`/`FAIL`).
- Not covered by the check: a boot that never reaches it. Found on Debian 13: a slot that fails in the initrd (for
  example verity setup) stops in emergency mode and never reboots, so no try is spent. This needs reboot-on-failure in
  the initrd or a watchdog; open, see `docs/updates.md`.

Verified on the Ubuntu PoC (systemd 259): three failed checks of a new release → `+0-3` → the previous release boots.
Debian 13 (systemd 257): three failed checks of release 4 → `+0-3` → release 1 boots; details in `docs/updates.md`.
