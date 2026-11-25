# 0012. Release signing and keys: what v1-alpha signs, where trust comes from, what changes before production

- Status: accepted (2026-11-21, owner); the choice of key holders is deferred to the first release with signed images
- Scope: build (`images/debian/build-image.sh`), update channel (`docs/updates.md`), agent (`agent/src/update.rs`),
  CI, published artifacts

## Problem

The project builds images whose integrity rests on several keys. v1-alpha publishes source code and build recipes only:
the one image profile contains NVIDIA components, and no built artifact with NVIDIA components is published in alpha.
The project therefore has no signed artifact of its own to publish yet. It still has to say what is signed, by which
key, where the root of trust is, and what must exist before a production release, so that test keys are never mistaken
for a trust anchor.

## What is signed and how it is checked (all keys are build parameters, none is in the tree)

| Key | Signs | Checked by | Where the trusted half lives |
|---|---|---|---|
| Secure Boot db key (`--sb-key`/`--sb-cert`) | the UKIs of both slots and the recovery UKI; the `/usr` verity signature partition; NVIDIA kernel modules built for the image | UEFI firmware (db) before the UKI runs; kernel `.platform` keyring for the modules (`module.sig_enforce=1`, `lockdown=integrity`) | firmware db, enrolled by the deployment (`SecureBootAutoEnroll=yes` writes PK/KEK/db when the machine is in setup mode on first boot) |
| PCR 11 policy key (`--pcr-key`/`--pcr-cert`) | the expected PCR 11 policy embedded in each UKI (`.pcrsig`) | TPM, when `/var` is unlocked (`docs/disk-encryption.md`) | public half in `/usr/lib/foilbird/pcr-key.pem` (under verity) and in the LUKS2 token |
| Release key, OpenPGP (`--release-keyring`) | `SHA256SUMS` of the update channel (`SHA256SUMS.gpg`), which lists every file of a release | agent (`verify_signature`, staging) and again the installer (`foil-var-epoch stage-<v>`), decision 0002 | `/usr/lib/systemd/import-pubring.{gpg,pgp}` under verity; the build refuses a keyring that is not exactly the release key |
| `/usr` content | — | dm-verity root hash `usrhash=` in the signed UKI command line | covered by the db signature of the UKI |

**Root of trust:** the Secure Boot keys enrolled in the machine's firmware by the deployment. Everything after the UKI
follows from it: `usrhash=` fixes `/usr`, `/usr` fixes the release key and the PCR key. The update channel and the network
are not trusted (decision 0002). First-boot enrollment in setup mode is trust on first use: whoever controls the machine
before the first boot chooses the keys.

## Why no threshold (k-of-n) signature

The agent accepts `SHA256SUMS.gpg` if **one** signature verifies with **any** key of the image keyring
(`agent/src/update.rs`), and the build allows exactly one release key. A threshold (two signatures from different holders
required on the node, as in TUF) would change the channel format and the agent. It is not done in v1-alpha because there
is no project release key to protect yet, and because dual control at the signing ceremony (below) gives most of the
benefit with no code. A threshold can be added later compatibly: an additional signature file in the channel that a newer
agent requires and an older agent ignores.

## Decision

### v1-alpha (now)

1. The project creates and uses **no** release, Secure Boot, PCR or agent CA key. Every key in CI and in the test harness
   is ephemeral, generated in the job, and carries `TEST` in its CN or user ID. **A TEST key is not a root of trust**; the
   documentation and the release notes say so. Deployments build with their own keys.
2. Production keys (of any deployment) are never on build machines, test stands, CI runners or in CI secrets.
3. Integrity of what alpha publishes does not depend on keys: for each published artifact (source archive, recipes,
   SBOM) its SHA-256; the exact commit and build parameters (`build-params.txt`: channel, release key fingerprint, SHA-256
   of the db and PCR certificates); SBOM (CycloneDX) and build provenance (CI attestation). Signatures with TEST keys, where
   any appear, are labelled as non-production.
4. No signed binary artifact is published in v1-alpha.

### Before the first production release with signed images (conditions, not implemented)

1. Separate keys per purpose (release, Secure Boot db, PCR policy, agent client CA, emergency CA) and per environment
   (`dev`, `nightly`, `release`). Signing is a separate stage outside the build job; build jobs hold no keys.
2. Key holders: two people. The key is generated once on an offline machine in the presence of both, imported into two
   hardware tokens (primary and backup, kept apart), with an encrypted offline copy or a secret split between the holders;
   the generation machine is wiped. Each release is signed in a ceremony with two people: the second compares the SHA-256
   of the unsigned candidate with the CI provenance and with an independent rebuild. The ceremony is logged.
3. Decide whether the image keyring holds one release key or a primary and a backup key. With exactly one key, **losing the
   key means no node accepts another update (reinstall)**; after a theft, rotating by a chain of releases does not help
   (the thief can sign a chain too).
4. Release metadata with an expiry (`expires`, as in TUF/Bottlerocket): until then, the only protection against an older
   signed release served by a hostile channel is the anti-rollback floor `min_version`.
5. Verify PKCS#11 (hardware token) signing in mkosi, ukify and sbsign for the db and PCR keys [not verified].
6. Secure Boot for external users: own keys (current model) or shim + MOK — decide before images are published.
7. Promote the same bytes through channels (nightly → candidate → stable) or rebuild per channel — decide with the
   reproducible build.

## Consequences

- v1-alpha users verify the published sources by commit and SHA-256 and build images with their own keys.
- Nothing in alpha can be "signed by the project"; any such claim is wrong.
