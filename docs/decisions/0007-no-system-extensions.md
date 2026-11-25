# 0007. No system or configuration extensions at runtime

- Status: accepted (2026-11-21, owner); implemented (package A), this record documents it
- Scope: image (`images/debian/mkosi`, `images/debian/foilbird-initrd`, recovery UKI), kernel command line

## Problem

`/usr` is an erofs image under dm-verity whose root hash is in the signed UKI (`usrhash=`); `/etc` is empty after every
boot. systemd can still change what the node runs without touching either:

- `systemd-sysext` / `systemd-confext` merge extension images over `/usr` and `/etc`. In systemd 257 the default image
  policy accepts **unsigned** images from `/var/lib/extensions`, `/var/lib/confexts`, `/run/extensions` and the ESP
  (stub `.extra.d/`, `/.extra/sysext`). Root on the node (or anyone writing the ESP) could add a persistent binary or unit
  that survives reboot.
- Userspace dm-verity signature checks accept certificates from `/etc/verity.d` and `/run/verity.d`, which root can add.

Both break the property "the system part cannot be changed unnoticed" and the image-is-the-host rule.

## Decision

1. The image has no extension machinery. `RemoveFiles=` drops `systemd-sysext.service`, `systemd-confext.service`,
   `systemd-sysext.socket`, `systemd-sysext@.service`, the socket's `.wants` link and the `systemd-sysext` /
   `systemd-confext` binaries (`images/debian/mkosi/mkosi.conf`), from the main image, the recovery UKI and the initrd.
2. The kernel command line carries `systemd.allow_userspace_verity=0`: dm-verity signatures are checked only by the
   kernel keyring, never against certificates in `/etc/verity.d` or `/run/verity.d`.
3. Files that root leaves in `/var/lib/extensions*` or `/var/lib/confexts` stay on the persistent `/var`, but nothing on
   the node reads them (no merging code exists). A persistent-path allow-list for `/var` is not implemented in v1-alpha.
4. Everything that changes the host arrives as a new signed image. This matches Talos, which has
   no extensions at runtime (its system extensions are baked into the installer image at build time).

Signed verity extensions (for example a kubelet minor as an extension, model B of decision 0004) are possible later only
through a new decision that states: who signs them (not the release key alone), how they are measured (PCR), how they
roll back with the slot, and how a node refuses an extension made for another release.

## Consequences

- Kubernetes minors, NVIDIA userspace and tools ship inside `/usr` of the release (decision 0004, model A).
- Nothing on `/var`, `/run` or the ESP can add code to `/usr` or `/etc`.

## Test

T16: root places an unsigned `.raw` in `/var/lib/extensions` and `/var/lib/confexts` and a `.crt` in
`/run/verity.d`, reboots; nothing is merged, `systemd-sysext` does not exist on the node. Status in v1-alpha: the image
contents are checked at build (`RemoveFiles=`, `docs/image-policy.md`); T16 as a QEMU test belongs to the test harness
[not yet run as a separate test].
