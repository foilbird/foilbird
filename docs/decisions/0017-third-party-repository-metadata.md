# 0017. Third-party repository metadata: package provenance in the image, fetch provenance in the build manifest

- Status: accepted (2026-11-26)
- Scope: the third-party apt sets of an image build (`images/debian/apt-pin.conf`, `profiles/k8s-worker/apt-pin.conf`:
  NVIDIA CUDA `debian13/x86_64`, NVIDIA container toolkit `stable`, pkgs.k8s.io `v1.34`), what the image says about
  them and what the build manifest records; not the Debian packages (one `snapshot.debian.org` timestamp, pinned in
  `images/debian/reproducible.conf`)

## Context

A third-party repository is not a snapshot. Its signed `InRelease` and its Packages index are replaced whenever the
repository is re-signed: NVIDIA's CUDA repository every few days (seen 18.11, 23.11 and 26.11.2026), the container
toolkit and pkgs.k8s.io when they publish. A replaced `InRelease` cannot be fetched again. Two builds of one commit that
fetched on different days therefore read different metadata, although every `.deb` they install is the same file,
pinned by sha256 and size in the lock (`apt-pin.lock`) and checked through the signed chain (`apt-pin.py`).

Before this decision the difference reached two places:
- the build input `apt-pin-inputs.json` (one `input file` line of the manifest): an unexplained difference between two
  otherwise equal builds;
- the image itself, in the `gpu` variant: `/usr/share/foilbird/sbom/nvidia-inputs.json` carried the `InRelease` sha256
  and date and the index hash, and the image SBOM named the `InRelease` sha256. The same commit gave a different `/usr`
  depending on the day of the fetch.

Pinning the `InRelease` in the lock was considered and rejected: a fresh CI runner would fail after every re-signing
until a new lock is committed, and the only way around that, carrying the signed metadata (InRelease and Packages
index, NVIDIA's is about 0.8 MB) in the tree, makes the project redistribute third-party repository metadata.

## Decision

Two kinds of provenance, each in one place.

1. **Package provenance, in the image.** What the image installed and where it comes from, independent of the day of
   the fetch: the repository, its origin, label and suite, the signing key's fingerprint, every `.deb` (name, version,
   sha256, size), the sha256 of the lock and the result of the chain check. `apt-pin.py prepare` gives the image this
   provenance without the fields of the fetched `InRelease` and index (`image_prov`); the image SBOM names the
   repository, the version and the key (`foilbird:nvidia-repository`). The same commit, snapshot and lock give the same
   `/usr`, whatever day the metadata was fetched; `/usr` lines are compared strictly.
2. **Fetch provenance, in the build manifest.** The full metadata of the build: `apt-pin-inputs.json` as written by
   `apt-pin.py prepare`, recorded by `build-manifest.py make --apt-inputs` as
   - `input file <sha256> apt-pin-inputs.json:stable`: the file without the fetched fields, strict;
   - `input param ok apt-pin-chain:<set>`: the chain check (the `InRelease` signed by the pinned key, the index equal to
     the signed `InRelease`, every file equal to its Packages stanza and to the lock), strict; a set without it refuses
     the manifest;
   - `input pinned-deb <sha256> <size> <set>:<package>=<version>` per installed third-party `.deb` and
     `input param ok apt-pin-installed` (installed = lock, checked against the package manifest), strict;
   - `keyed inrelease <value> <set>:<field>`: the fetched fields, an expected difference. The list is closed: the three
     sets above at their repositories (`INRELEASE_SETS`), the fields `inrelease.sha256|date|valid_until`,
     `index.sha256|sha512|size`, `packages_gz.*` (`FETCH_FIELDS`). Another set or field is a difference.
   The CI job prints `apt-pin-inputs.json` in its log; `build-manifest.py extract --block apt-pin-inputs.json` and
   `build-manifest.py apt-inputs` give the file and its manifest lines back for the evidence of a run.
3. **The check of the fetched metadata is not relaxed.** `apt-pin.py` verifies every `InRelease` it reads, refuses an
   expired one (`Valid-Until`), and refuses any file that is not in the lock. None of the three repositories sets
   `Valid-Until` today; when one does, a cached `InRelease` past it stops the build until the cache is refreshed.

## Consequences

- **The image carries no binding to a particular `InRelease`.** It is tied to a repository through the signing key and
  the sha256 of each `.deb` in its SBOM; the full repository metadata of a build (the `InRelease` and index it read, their
  date and signature) is in the external build provenance, its build manifest. Checking that an image came from a
  particular signed `InRelease` needs that manifest.
- The build manifest is not signed in v1-alpha3 (provenance and attestation: decision 0012, a later cycle).
- Two builds of one commit with different fetch days give equal `/usr` and differ only in `keyed inrelease` lines.
- Adding a third-party repository is a change of `INRELEASE_SETS` (and of `TRUSTED` in `apt-pin.py`), reviewed; until
  then its fetched fields stay in the strict part.
