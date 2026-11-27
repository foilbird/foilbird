# /var encryption and anti-rollback (Debian image)

Status: proof of concept, `images/debian/mkosi`. Covers the TPM-bound `/var` and anti-rollback.

## /var

| Piece | What |
|---|---|
| Partition | `/usr/lib/foilbird/repart.d/30-var.conf`: `Type=var`, `Encrypt=tpm2`, ext4, rest of the disk, created on first boot |
| Who creates it | `foil-repart.service` on the host, with an explicit policy: `--tpm2-pcrs=7 --tpm2-public-key=/usr/lib/foilbird/pcr-key.pem --tpm2-public-key-pcrs=11 --seed=random` |
| Key slots | one TPM2 slot; no passphrase, no recovery key |
| Policy | PCR 7 (Secure Boot state, literal) **and** PCR 11 (UKI contents and boot phase) through a policy **signed** by the PCR key. Any UKI whose `.pcrsig` is signed by that key unlocks `/var`; a different signer does not |
| PCR key | separate from the Secure Boot db key; the build passes it (`--sign-expected-pcr-key=`, `--sign-expected-pcr-certificate=`) and puts its public half at `/usr/lib/foilbird/pcr-key.pem`. Without these options mkosi signs PCR 11 with the Secure Boot key |
| Unlock | `foil-var-unlock.service` (only if the var partition holds LUKS2): `cryptsetup open --token-only --token-id N` for N = 0…7, then `test -b /dev/mapper/var`. No prompt, no fallback |
| Mount | `var.mount` from `/dev/disk/foilbird/var-fs` (udev, `61-foil-var.rules`): the opened dm-crypt device, or a plain ext4 var partition. If an encrypted `/var` does not open, `var-fs` never appears and `var.mount` fails; `local-fs.target` only wants it, so the node stays up without `/var` ("When no token opens /var"): no temporary or plain `/var` |
| State | `foilbird-var:luks-tpm2` or `foilbird-var:plain` is measured into PCR 15 (`systemd-pcrextend`); the agent reports `var_protection` |

### Pitfalls (keep these)
1. **The initrd also runs systemd-repart** (it reads `/usr/lib/repart.d` through `/sysusr`) and enrolls with its own
   defaults: no PCR 7, PCR 11 bound to the UKI's `.pcrpkey`. Seen on Ubuntu 26.04; the host-side unlock then failed with
   `TPM_RC_POLICY_FAIL`. Therefore the definitions live in `/usr/lib/foilbird/repart.d`, which the initrd does not read.
2. **systemd-gpt-auto-generator claims `/var`** when its partition UUID is derived from the machine-id (repart's default
   seed) and the machine-id is stable: it adds `systemd-cryptsetup@var.service`, which races with our unlock and fails,
   and `dev-mapper-var.device` then fails with it. `--seed=random` avoids it.
3. Without the device-mapper udev rules (`dmsetup` package) libcryptsetup waits forever for udev while repart formats
   the volume.
4. **systemd-cryptsetup 257 tries only the first TPM2 token**: if it has no signature for its key (`Couldn't find signature
   for this PCR bank, PCR index and public key`, ENXIO) the next token is never asked. With one token per epoch only the
   first epoch would unlock. `foil-var-unlock` therefore tries the tokens one by one with `cryptsetup open --token-id`.
   Ids 0…7 rather than one per live epoch: a power loss inside `systemd-cryptenroll --wipe-slot` (between the keyslot and
   the token update, ~3 ms in QEMU) leaves a `systemd-tpm2` token with no keyslot, which cryptenroll never removes, and the
   next enrolled token gets the next free id. `foil-var-epoch@sync-booted` removes such tokens at every boot; the wider
   range covers the time until it does.
5. `systemd-repart` is a separate package in Debian 13 (and Ubuntu 26.04); mkosi puts it only into the initrd.

## Anti-rollback: minimum version as "PCR key epochs that still have a key slot"

systemd 257 cannot compare a TPM NV counter in the `/var` policy (no PolicyNV in `systemd-cryptenroll`); pcrlock uses an
NV index for a different purpose (predicted PCR values). The PoC therefore expresses `min_version` through the PCR key:

- every release carries its epoch and floor in os-release: `FOILBIRD_PCR_EPOCH`, `FOILBIRD_MIN_VERSION` (the build passes
  `FOILBIRD_PCR_EPOCH`, `FOILBIRD_MIN_VERSION`; `mkosi.finalize` refuses an image without them). They are also in the UKI
  `.osrel`, next to the epoch's public key in `.pcrpkey`;
- a security release that raises the minimum starts a new epoch (new PCR key);
- `images/debian/mkosi/release-epochs` lists every epoch with its first release (`<epoch> <first release>`, append-only).
  `mkosi.finalize` refuses a release whose version is outside its epoch's range, or whose `FOILBIRD_MIN_VERSION` is below the
  first release of its epoch: a node raised to such a floor has wiped the older epochs' slots, yet would still accept
  (Rollback, StageUpdate) a release of an older epoch that cannot open `/var`. Lab builds may pass the table
  as `FOILBIRD_RELEASE_EPOCHS=<epoch>:<first>,...` (commas: mkosi splits environment values at spaces) instead;
- **before** installing it, the agent starts `foil-var-epoch@enroll-<version>.service`: a key slot for the new epoch.
  Both epochs unlock `/var` now, so a failed update rolls back without losing `/var`;
- **after** the new release is committed, the controller decides when (soak, security) and the agent starts
  `foil-var-epoch@raise-<version>.service`: the slots of the older epochs are wiped and the floor is written. From then
  on an older release, even correctly signed for Secure Boot, cannot open `/var`. Slots of newer epochs (enrolled for a
  staged release) stay, so a raise between enroll and install does not lock the staged release out.

The slots are reconciled, not only changed on request: the wanted set is {TPM2 slots of epochs ≥ the booted one} ∪
{every slot that is not a TPM2 slot, such as a recovery key}. Every operation first removes what is outside it and safe to
remove (tokens without a key slot, the tokenless keyslot of an interrupted enroll); only raise wipes slots that once worked. The slot `/var` was opened with is never wiped: only the
booted key can open it, the booted UKI carries PCR 11 signatures of its own key only.

### Units (image) and files

| | |
|---|---|
| `foil-var-epoch@enroll-<v>` | staged release `<v>` in `/var/lib/foil-agent/staging/current`. Nothing the agent wrote is trusted: `SHA256SUMS`, `SHA256SUMS.gpg` and the UKI are copied into a private directory in `/run`, the signature is checked with the release key from `/usr` (`import-pubring.gpg`, verity), the copy of the UKI against `SHA256SUMS`; key (`.pcrpkey`), version and epoch (`.osrel`) come from that copy. An epoch older than the booted one, or the booted epoch with another key, is refused. Idempotent (a slot for that key already there → ok) |
| `foil-var-epoch@raise-<v>` | `<v>` must be the booted release and committed, the booted key must have a working slot. Wipes the numeric key slots of every `systemd-tpm2` token whose key is neither the booted one nor that of the **verified staged release**, then writes the floor. The staged release (`/var/lib/foil-agent/staging/current`) is verified as enroll verifies it (`SHA256SUMS` signed by the release key in `/usr`, the UKI copy hashed, `.pcrpkey` and `FOILBIRD_PCR_EPOCH` from the copy's sections) and its key is kept only with an epoch above the booted one; nothing staged → every other key is wiped (enroll makes the slot again on the next Stage). A release newer than the booted one already installed on the ESP (`/boot/EFI/Linux/foilbird-deb_<v>[+t[-d]].efi`, not `+0`) that is not the verified staged release (verified with an epoch not below the booted one is enough: a release of the booted epoch boots with the booted key, which raise never wipes; a verified one with a lower epoch — a release pipeline error, enroll refuses it — is refused too: it would boot with an older key that raise wipes) → `refused`, nothing wiped: its key slot would go and it could not open `/var` (staging replaced or cleared after install); boot it, stage it again or roll it back first. An unreadable ESP → `refused`. `epoch-keys/` is written under `/var` and decides nothing (root could rename `0.pem` to `99.pem`): it is a cache for `var-epochs` and the report. Then the booted epoch is brought to exactly one `systemd-tpm2` token with exactly one key slot: token JSON can be edited by root, so the TPM decides (`cryptsetup open --test-passphrase --token-only --token-id N [--key-slot S]`). The first token of the booted key that opens `/var` **and whose JSON policy is our enroll's** (`tpm2-pcrs=[7]`, `tpm2_pubkey_pcrs=[11]`, no PIN or pcrlock; the bank is not compared, systemd picks it per TPM; the same constants as the enroll command; the TPM test proves the blob matches its JSON, the comparison proves the JSON is ours) is kept; an opening token with another policy (root: `systemd-cryptenroll --tpm2-public-key=<ours> --tpm2-pcrs=`, Secure Boot state unbound) is wiped like a fake one, and none with our policy → error, nothing wiped. Its key slots it does not open are unassigned and wiped; the other tokens claiming the booted key lose their slots (shared slots are unassigned first). Every wipe of raise (older epochs and the reconciliation) is prepared so that `systemd-cryptenroll --wipe-slot`, which drops every token naming a wiped slot together with that token's other slots, removes exactly the tokens meant: a removed token keeps only slots being wiped, every other token (any type) is unassigned from them, and a slot that a kept `systemd-tpm2` token of the booted key names too is not wiped with an old or fake token (root adding our slot to an old epoch's token would otherwise make raise wipe our slot and token). A token of another type does not keep such a slot: root could name an old epoch's slot in a token of type `x`, raise would only unassign it from the old token, and the old, vulnerable release would still unseal it; the slot is unassigned from that token and wiped, the token stays (reported). Nor does a token of the staged release's key (its pubkey is public, root can write a token with it naming an old slot, and the TPM cannot test it before that release boots): only a token of the booted key keeps a slot of a removed token. A slot that root put under both an old token and the staged release's token is wiped; the staged release loses only that slot, and enroll makes it again. v1: `crypt_keyslot_destroy()` of libcryptsetup (the `LUKS2_keyslot_wipe` of `luksKillSlot`, no passphrase) wipes a slot and drops it from every token in one header write; the journal and the unassign step would go. The slots to wipe are journaled in `/var/lib/foilbird/wiping` (`slot=<n> salt=<hex>`) before the first unassign: a cut between unassign and wipe (in either stage: older epochs or the reconciliation) can leave one tokenless, and the next run wipes the listed slots that are still tokenless with the same salt; a listed slot still under a token is left to the next raise. The order cannot be wipe-then-unassign: libcryptsetup refuses a header whose token names a missing slot, and `cryptsetup luksKillSlot` (both in one header write) wants another slot's passphrase without a tty. Slots the kept token opens are never wiped. Slots named only by tokens of another type are only reported. Keys of unknown epoch are wiped as well: enroll records every key before its slot, so such a slot was not enrolled by the image (root on the node). A raise cut before its end is not repeated by the node: the operator repeats `RaiseMinVersion`; until then the floor is not raised and the older release still opens `/var`. Repeated → ok, nothing to wipe. Security flag and soak are the controller's decision, not checked here |
| `foil-var-epoch@sync-booted` | every boot, enabled in `multi-user.target`: removes tokens without a key slot, finishes an interrupted enroll (below), writes `var-epochs`; wipes no other slot. TPM2 slots of unknown keys and key slots without a token (password, recovery) are reported in `/run/foilbird/var-epoch/slots`, not wiped |
| all | first remove `systemd-tpm2` tokens without a key slot (left by a power loss inside a wipe); a token whose key cannot be read stops a raise (it could be the own one). `/var` not LUKS2 → `noop`, exit 0. Result for the agent: unit result and `/run/foilbird/var-epoch/<op>-<v>.result` (`result=ok|noop|refused|error`, `detail=`). Program `/usr/libexec/foil-var-epoch` (C, no shell; runs `cryptsetup`, `systemd-cryptenroll`, `gpg`, `sha256sum`) |
| `foil-boot-committed.service` | after `systemd-bless-boot` (only reached through `boot-complete.target`): `/var/lib/foilbird/committed/<IMAGE_VERSION>`, written once, mtime = commit time. The UKI name alone cannot tell on a node updated from an image with re-arm (a re-armed release is `+3` and boots as `+2-1` … like a new one); without re-arm (decision 0003) a committed release is `<v>.efi` |
| `/var/lib/foilbird/min_version` | the floor, one number, written only by raise (temp + fsync + rename, never lowered). The agent's floor = max(this, `FOILBIRD_MIN_VERSION`) |
| `/var/lib/foilbird/enrolling` | intent journal of enroll: `epoch=<E>`, `slots=<key slots before>`, written durably before `systemd-cryptenroll`, removed after it. cryptenroll adds the keyslot before its token; a run that finds the journal wipes every key slot without a token that is not listed (the keyslot of the cut enroll), then removes the journal |
| `/run/foilbird/var-epoch/slots` | rewritten by every run, read by the agent (GetHealth CRITICAL + audit for a non-empty `unknown_tpm2_slots`, `tokenless_slots`, `foreign_tokens`, `foreign_token_slots`, `tpm2_bad_tokens`, `duplicate_epoch_tokens` or `epoch_keys_suspect`, not in the boot gate). `schema=1`, then `op=`, `time_unix=`, `unknown_tpm2_slots=`, `wiped_unknown_slots=`, `tokenless_slots=`, `interrupted_enroll_removed=`, `orphan_tokens_removed=`, then `foreign_tokens=`, `foreign_token_slots=`, `tpm2_bad_tokens=` (also a policy other than our enroll's), `duplicate_epoch_tokens=`, `wiped_extra_slots=`, `removed_tokens=`, then `epoch_keys_suspect=` (epochs in `epoch-keys/` whose key body is also filed under another epoch, or above both the booted epoch and the staged release's: verified when raise or enroll ran, else read from the staged UKI unchecked; CRITICAL, as the cache decides nothing but a mismatch is root at work); lists ascending, comma-separated, empty = none; unknown keys are ignored by readers. Slots without a token are only reported until ADR 0010 marks the recovery slot |
| `/var/lib/foilbird/var-epochs` | epochs that have a working key slot, ascending, one line (`1 2`); empty = no TPM `/var` |
| `/var/lib/foilbird/epoch-keys/<E>.pem` | the verified key of each epoch seen (the booted one and every enrolled one), to name the slots; enroll writes it before the slot, so no slot has a key of unknown epoch |

## Disks set up before /var encryption

`systemd-repart` never re-encrypts an existing partition (`Encrypt=` applies to partitions it creates). A node whose
`/var` was created plain keeps it plain after an A/B update to an image with TPM-bound `/var`: udev links the plain
partition as `var-fs`, the unlock unit is skipped, PCR 15 gets `foilbird-var:plain`, the agent reports `NONE`.

**Known limitation:** a plain `/var` stays plain for good; encryption comes only with a reinstall (no in-place
migration in the PoC). The live test node set up before this change has a plain `/var`.

The agent reports the state in `GetInfo.var_protection` (`LUKS2_TPM2` | `NONE` | `OTHER` | `UNSPECIFIED`, from the dm
UUID of the `/var` block device).

Risk: with offline access to the disk, an attacker can reformat an encrypted var partition as ext4 with their own
content; the node then boots it as a plain `/var`. The image cannot tell this from a legacy node. It is caught by policy:
the controller admits `NONE` only for an explicit allow list of legacy nodes, and a node that reported `LUKS2_TPM2`
before and `NONE` now is an incident, not a migration. PCR 15 makes the state visible to remote attestation.

> **v1-alpha limitation** (fix planned for v1-alpha4): "`/var` is unreadable on a stolen disk" (threat model, attacker
> C) holds for a disk without its machine. With physical access to the node itself (disk and TPM together) an attacker
> can replace the encrypted `/var` by a plain ext4 partition with their own content, as above, and it is not inert: the
> node boots it as a plain `/var` (`var_protection` `NONE`) and applies the configuration stored on it
> (`/var/lib/foil-agent/config.pb`: the cluster to join, registries, hosts, update channel), so it runs what the
> attacker's cluster schedules, which is root on the node. The key policy of the original `/var` is PCR 7 and a signed
> PCR 11; the `/var` state goes to PCR 15 only, so on that boot the policy is still met and the key of a kept copy of
> the original `/var` can be unsealed. The policy check above detects this only afterwards, and needs a controller.

## When no token opens /var (open question)

Seen after a TPM reset (QEMU, swtpm state removed): no release opens `/var`, there is no recovery key. `foil-repart`
does not recreate the partition (it exists), `var.mount` fails, but `local-fs.target` only wants it, so the node stays
up without `/var` (units that need `/var` fail); on a committed entry nothing reboots. Without re-arm (decision 0003, amendment) a committed release is not
counted, so the node stays on it without `/var` (with re-arm it ended in the recovery entry). Proposed policy for nodes whose `/var` is disposable (k8s-worker): when every token fails on every release,
recreate `/var` (data lost, the node re-registers), visible through `var_protection` and an agent event. Not decided,
not implemented.

## Results

Verified in QEMU with a lab agent (not part of the image).

## Unseal retries and timeouts

Any PCR extend between the start of the TPM policy session and the unseal fails it with `TPM_RC_PCR_CHANGED` (the TPM's
update counter covers all PCRs, not only 7 and 11). systemd 257 restarts the policy session up to 30 more times without
a pause (`RETRY_UNSEAL_MAX`, `src/shared/tpm2-util.c`). Extends that happen while `/var` is unlocked: kernel IMA (PCR 10,
every loaded module under the Secure Boot policy), in the lab one retry per boot.

| Limit | Value | When it bites |
|---|---|---|
| unseal tries | 31 | extends faster than one policy session; then `foil-var-unlock` fails, the boot check fails, one boot try is spent |
| `/dev/disk/by-partlabel/var` device wait | 360 s (`JobRunningTimeoutSec=`, drop-in) | first boot only: the partition appears when `foil-repart` (at most 300 s) has formatted `/var` and written the table; without it the default 30 s from boot start fails `/var` on a slow disk, the boot check reboots and the boot is spent |
| `/dev/disk/foilbird/var-fs` device wait | 480 s (`JobRunningTimeoutSec=`, drop-in) | the first boot's repart plus the unlock; without it the default 30 s from boot start: an unlock that succeeds late still leaves the node without `/var`. A failed unlock does not wait for it: `var.mount` has `Requires=foil-var-unlock.service` |
| `foil-boot-check` | `After=foil-repart.service` | first boot only: the boot check and its reboot wait for the repartitioning; a reboot in the middle lost it (the table is written last) and the next boot started over |
| `foil-var-unlock` | `TimeoutStartSec=90` | a hung TPM |

Measured on QEMU/swtpm (PCR 13 extended in parallel loops during the unlock, ~7 extends/s): 1 loop — unlock 2.6–3.5 s,
1–2 retries; 4 loops — 11.5–19.6 s, 9–17 retries; 16 loops — 29 retries, unlocked after 47 s, which the 30 s device
wait had already given up on.
