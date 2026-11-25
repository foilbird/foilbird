# 0002. Verify updates before touching the fallback slot

- Status: accepted (2026-11-15)

## Problem
`systemd-sysupdate` (259) frees an instance before streaming the new image into it; the
file hash is verified while writing. A rejected update therefore leaves only one bootable
version.

## Decision
1. Download the complete release into a staging directory independent of the
   sysupdate-managed slots (e.g. `/var/lib/<os>/staging`), verify the signed manifest, every
   file hash, the version and anti-rollback policy, and completeness (UKI, `/usr`, verity,
   signature). Only then install into the inactive slot from the staging source.
2. The controller does not start another update on a node until the previous one is
   committed (boot counting finished, health confirmed).

## Notes
`ProtectVersion=%A` is mandatory in every transfer; without it sysupdate may remove the
booted version. The stock `systemd-sysupdate*.timer` units are removed from the image.

## Addendum (2026-11-15): release channel and trust
- The channel (where the release is downloaded from) is configuration, not
  trust. The image names a default channel (`/usr/lib/foil-agent/channel`:
  directory, `https://`, or `http://` for lab builds only); `NodeConfig` may
  override it with an `https://` URL and CA (planned, `ApplyConfig`, level
  DESTRUCTIVE).
- Trust comes only from the `SHA256SUMS` signature by the release key built
  into the image under verity. The key is never configurable through the API.
- Consequence for an attacker who controls the channel URL or the network
  (including a compromised gateway setting the override): denial of service
  (no update, or a download that fails verification) or a different release
  that is still correctly signed. Older signed releases are refused below the
  anti-rollback minimum (`min_version`); within the allowed range the
  controller decides versions anyway. Content cannot be altered.
