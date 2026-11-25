# 0003. No endless boot loop: re-armed boot counting and recovery entry

- Status: accepted (2026-11-15)

## Problem
A committed boot entry has no boot counter. If the committed version gets corrupted while
the other slot is bad, the node reboots forever.

## Decision
- Division of work (amended 2026-11-15): the node agent decides whether a boot is healthy
  (its checks gate `boot-complete.target`; "successful" is the agent's confirmation, not reaching
  user space). A unit shipped in the image re-arms the boot counter of the current entry after
  `systemd-bless-boot`; the agent only reads the ESP. **Withdrawn 2026-11-16, see below.**
- A recovery UKI, independent of the A/B slots and signed by the project, is the last boot
  entry. It is read-only, diagnoses both slots and can be driven by the management plane.
- Failures after boot-complete (for example a GPU driver failing later) are handled by the
  agent and, where present, a hardware watchdog.

## Amendment 2026-11-16: no re-arm
The per-boot re-arm is removed, as in systemd and Talos: a committed release is not assessed again, the boot counter
exists only between an update (or the first boot from the disk) and the commit. Reasons: the re-arm and the counting it
causes write the ESP three times on every boot of a healthy node (systemd-boot's rename, bless, re-arm; systemd-boot's
own write happens in the firmware, before any fsck), and a FAT that is written on every boot is what a power loss
corrupts (found in p.31: dirty ESP → read-only → bless, sysupdate and Rollback fail); and after three resets caused by
the environment (power, hardware) it abandoned a healthy release.

Accepted consequence: a committed release that breaks later (corrupted `/usr`) reboots in a loop until someone
intervenes (watchdog, operator); systemd-boot does not move on to the previous release or the recovery entry. The
recovery entry is still reached when a new release fails its tries and no good entry is left (for example on the first
boot from the disk). Open for v1: arm a counter only on a sign of trouble (for example the emergency unit in the
initrd gives the current entry a counter before it reboots), with no ESP write on a healthy boot.

For the same reason the image ships no `systemd-boot-random-seed.service`: it creates `\loader\random-seed` on the ESP,
and systemd-boot rewrites an existing seed file from the firmware on every boot. The kernel's entropy comes from the EFI
RNG, RDRAND and the TPM; the image has no seed file (mkosi removes it). A node installed from an older image keeps the
file it already has (and its rewrite at boot); there is no fleet yet, so it is not removed.
