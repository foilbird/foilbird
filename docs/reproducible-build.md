# Reproducible build from public sources (v1-alpha)

A node image is built from public sources only, with every input pinned, by one call that is the same on a build host
and in CI: `images/debian/tools/build-all.sh`. Two builds of the same commit and snapshot produce the same build
manifest except for `keyed` lines: those that depend on the signing keys or the deployment parameters, and the fields of
a third-party `InRelease` as fetched ([Expected differences](#expected-differences)). The promise has three parts:

- **The agent's binaries** (`foil-agent`, `foilctl`) are the same bytes only when built with the same Rust toolchain,
  build tools and C toolchain at the same path: in CI that is the pinned Debian image with `agent/c-toolchain.pins`
  ([C toolchain of the agent](#c-toolchain-of-the-agent)). A dist built elsewhere is recorded as
  `input param unrecorded agent-toolchain` and is not claimed to equal a CI one.
- **The content of the image** (`/usr`: file contents, modes, links, packages and versions) is compared strictly. The
  `keyed` lines are signed files and key material, never a fetched date.
- **The recorded inputs** (`input` lines of the build manifest) are strict, except the fetched fields of the
  third-party repository metadata, which are `keyed inrelease` lines from a closed list
  ([decision 0017](decisions/0017-third-party-repository-metadata.md)).

Debian `.deb` files are not pinned by sha256 in this tree: they come from one `snapshot.debian.org` timestamp, which
does not change, through apt's own check against the Debian archive keys.

## Sources and trust anchors

| Input | Source | Anchor | Pinned by |
|---|---|---|---|
| Debian packages of the image, the slot initrd, the recovery UKI | `https://snapshot.debian.org/archive/debian{,-security}/<ts>` (`trixie`, `trixie-security`; `trixie-updates` from the same timestamp through the build sandbox) | Debian archive keys (`debian-archive-keyring`) | `Snapshot=` in `images/debian/reproducible.conf` |
| Debian packages of the **tools tree** (mkosi's `ToolsTree=default`: systemd-repart, ukify, mkfs.erofs, apt, …) | the same snapshot | the same keys | `Snapshot=` in `images/debian/tools-tree/mkosi.conf`, see below |
| mkosi | `github.com/systemd/mkosi`, tag `v26` | commit `84af20892b61c8e177e391f997ded8b4cb5514f2` (checked, a moved tag fails) | `.github/workflows/build.yml`; on a build host, the root-owned copy of the root wrapper |
| NVIDIA driver 610.57.04 (open module source + userspace) | NVIDIA CUDA repository `debian13/x86_64` | key `02182E60104FCDC26EAE1B8597A5D4CB8793F200` | `images/debian/apt-pin.conf` + `apt-pin.lock` |
| nvidia-container-toolkit-base 1.20.2-1 | `nvidia.github.io/libnvidia-container/stable/deb/amd64` | key `C95B321B61E88C1809C4F759DDCAE044F796ECB0` | `profiles/k8s-worker/apt-pin.conf` + `apt-pin.lock` |
| kubelet, kubeadm 1.34.3-1.1, cri-tools 1.34.0-1.1, kubernetes-cni 1.7.1-1.1 | `pkgs.k8s.io/core:/stable:/v1.34/deb` | key `DE15B14486CD377B9E876E1A234654DA9A296436` | the same |
| containerd 2.3.7, runc 1.5.2 | GitHub releases | release `.sha256sum`; runc: GPG against `runc.keyring` of the same tag | `release` lines of `profiles/k8s-worker/apt-pin.lock` |
| the agent | this repository (`agent/`) | — | `agent/rust-toolchain.toml`, `Cargo.lock`, `--locked` |
| C toolchain of the agent (gcc 14.2.0-19, binutils 2.44-3, musl-tools 1.2.5-3.1~deb13u1: ring's C and the link) | the build's Debian snapshot, in the pinned Debian image (`DEBIAN_IMAGE` of `ci/run-stage.sh`) | Debian archive keys | `agent/c-toolchain.pins` (name=version, checked after the install and in `.comment` of `foil-agent`: `ci/agent-toolchain.sh`); the installed versions in the build manifest (`input param … agent-toolchain:<package>`) |

The anchors of the third-party apt repositories are pinned in `images/debian/tools/apt-pin.py` (`TRUSTED`), never in a
set file: a new key is a change of the script.

## Chains of trust

Third-party apt sets (`images/debian/tools/apt-pin.py`). The same check runs for a file downloaded a second ago and for
one from the cache:

file ← its Packages stanza (size, SHA256/SHA512) ← the Packages index, whose hash is in the **signed** text of InRelease
← InRelease signature (sqv; digest not MD5/SHA1/RIPEMD160) ← the anchor: the pinned fingerprint, every self-signature
and binding of the key with a strong digest.

After the chain, the lock: URL, size and sha256 of every file equal to its line, every line has its file. The chain
proves where a file comes from, the lock that it is the same file as in the build that wrote the lock.

- **Only the key's own signatures count.** A certification of the key by another key neither helps nor hurts; apt-pin.py
  names it in its log (`foreign certification ignored: SHA1 (issuer CF0B928CDED64F3B, class 0x13)` for pkgs.k8s.io's
  key, a SHA1 certification by a third party) and does not count it. A SHA1 self-signature or binding is refused.
- **The libnvidia-container repository does not re-sign its metadata:** its InRelease is dated
  `Fri, 27 Apr 2018` and has no `Valid-Until`. An attacker could replay an older, validly signed InRelease, and the
  chain alone would not notice. The lock does: it pins the sha256 of every `.deb` and of the key.
- In the build, the verified copies are the only third-party apt sources (`file:/srv/apt-pin/<set>/`, sandbox tree
  `images/debian/mkosi/aptpin`, absolute path in `pinned.conf`), with apt preferences that admit only the pinned
  packages; apt re-verifies InRelease → index → `.deb` itself. The node has no apt and no repository configuration.

## The tools tree

mkosi 26 does **not** pass `Snapshot=` on to its default tools tree: `finalize_default_tools()` copies only the
multiversal and `ToolsTree*` settings, and `Snapshot=` is universal (`tools=True` only allows it in a tools
configuration). Without a configuration of its own, the tools tree came from the live `http://deb.debian.org`
(hundreds of apt lines outside the snapshot). `images/debian/tools-tree/` (`mkosi.conf` with `Snapshot=`, `mkosi.sandbox` for
`trixie-updates`) is read through the `mkosi.tools.conf` symlink of every build directory (`foilbird-initrd`, `recovery`,
`mkosi`, `profiles/k8s-worker`). The CI stage fails if any apt line comes from a source other than the snapshot and
`file:/srv/apt-pin` (`LIVE MIRROR FAIL`). A tools tree built before this rule must be removed (`mkosi.tools/` of each
build directory).

## Build as root

mkosi runs as root. As an unprivileged user, mkosi 26 maps a single uid: it installs packages with `--suppress-chown`
and writes cpio `--owner=0:0` and repart/mkfs `--become-root`. Every file ends up `0:0`, and in the erofs `/usr` the
setuid and setgid bits are dropped (`unix_chkpwd`, `dbus-daemon-launch-helper`). Two root builds of the slot initrd were
byte-for-byte equal. Only the three mkosi entries run as root:
- `foilbird-initrd/build.sh`;
- `recovery/build.sh`;
- `build-image.sh`.

In CI they run through `sudo env PATH=… SOURCE_DATE_EPOCH=…`. On a build host they run through a root wrapper
(`NL_BUILD`), which fixes the environment and uses a root-owned mkosi. apt-pin.py, fetch-upstream.py, the agent and the
manifest run as the user.

## What is pinned where

| What | Where | How to change |
|---|---|---|
| Debian snapshot | `reproducible.conf`, `tools-tree/mkosi.conf`, `mkosi/mkosi.sandbox/.../debian-updates.sources` | `images/debian/tools/snapshot set <ts>` (all three; every build runs `snapshot check`) |
| third-party apt sets | `apt-pin.conf` (versions), `apt-pin.lock` (files) | change the conf, `apt-pin.py fetch` + `apt-pin.py lock`, review the diff of the lock |
| containerd / runc | `fetch-upstream.py` (`PIN`), `release` lines of the profile's lock | change `PIN`, `fetch-upstream.py fetch` + `lock`, review the diff |
| mkosi | `MKOSI_COMMIT` in `build.yml` | new tag and commit, both checked |
| agent build tools | `CARGO_AUDITABLE_VERSION`, `CARGO_CYCLONEDX_VERSION` in `agent/build-release.sh` | change the version: a new tools set directory (see below) |
| agent C toolchain (CI) | `agent/c-toolchain.pins`; the image `DEBIAN_IMAGE` in `ci/run-stage.sh` | a new snapshot with other versions fails the agent step by name: change the pins in a commit of their own, rebuild the dist |
| partition UUIDs, mtimes | `--seed` = uuid5(profile:version), `SOURCE_DATE_EPOCH` = commit time | — |

A lock is never taken from a run automatically: the CI `lock` stage prints it and fails on purpose; the locks are
reviewed and committed.

## Build tools of the agent

`agent/build-release.sh` builds through `cargo auditable`, which puts itself in as the rustc wrapper; cargo hashes the
wrapper's absolute path into the metadata of every crate of the workspace, so the same tools at another path give other
binaries (checked on the stand: the same tool binaries in another directory, and inside two clones at different places,
gave different `foil-agent` and `foilctl`). The tools therefore live at **one absolute path on every build machine**:

    /opt/foilbird-build-tools/auditable-<V>_cyclonedx-<V>_rust-<V>     (versions from build-release.sh and rust-toolchain.toml)

- Created once by root, owned by the build user: `sudo install -d -o <user> -g <group> /opt/foilbird-build-tools`
  (CI: `ci/run-stage.sh`; a build host: its administrator). `build-release.sh` refuses to build when the tools are not
  there and prints that command; a `TOOLS_ROOT` naming another directory is refused.
- `build-release.sh --install-tools` installs them with `cargo install --locked`, a fixed build directory and the same
  path mapping as the agent, so their binaries do not depend on `CARGO_HOME`. `--locked` takes the `Cargo.lock` shipped
  inside the published `.crate`, which crates.io never changes for a version: the versions name the set completely.
- Offline (`agent/tools/offline-inputs.sh install`) runs the same `--install-tools` with crates.io replaced by the
  vendored crates (the tool crates are vendored too): the same source, command and path as online.
- The path is part of the published binaries: renaming the project renames the directory and changes them.
- This is cargo's behaviour, not a documented contract: a new cargo may hash differently. The offline comparison
  (`ci/offline.sh`: image manifest online = offline) checks it on every counted run.

## C toolchain of the agent

ring (through rustls and tonic) compiles C and assembly with `musl-gcc`, and rustc links the static binaries through
`cc` and `ld`; another gcc or binutils gives other bytes (a build host's gcc 14.2 and a CI runner's gcc 13 gave two
different `foil-agent`). In CI the agent is built inside the pinned Debian image (`DEBIAN_IMAGE` of `ci/run-stage.sh`,
the offline variant in `ci/offline.sh`) with the packages of `agent/c-toolchain.pins`, installed as `name=version` from
the build's own Debian snapshot. `ci/agent-toolchain.sh` then checks what was actually used:

- `check`: every pinned package at exactly its version (`dpkg-query`), `cc --version` names the pinned gcc,
  `ld --version` the pinned binutils, `musl-gcc` present;
- `comment`: `readelf -p .comment` of `foil-agent` carries the pinned lines (`GCC: (Debian 14.2.0-19) 14.2.0` for ring,
  `GCC: (GNU) 9.4.0` for the self-contained musl C runtime shipped by rustc) and no other `GCC:` line;
- `record`: the installed versions go into the dist's `C-TOOLCHAIN` and from there into the build manifest as
  `input param <version> agent-toolchain:<package>`.

A dist without `C-TOOLCHAIN` (built on a build host, outside the CI container) gives the line
`input param unrecorded agent-toolchain`: the image is built, but its agent is not claimed to equal the CI one, and
`compare` against a CI manifest shows the difference. To get the same bytes on a build host, build the
agent in the same image with the same pins (`ci/run-stage.sh`, step `agent`). A new snapshot with other versions fails
the agent step by package name; the pins change in a commit of their own.

## Expected differences

`images/debian/tools/build-manifest.py compare A B` exits 0 when two manifests differ only in `keyed` lines:
- signed kernel modules as shipped (`.ko` are compared without the appended signature);
- the release keyring, the PCR public key, the channel and its CA, the sysupdate `Path=`;
- the SBOM record of the signed modules;
- the partition images and the UKI;
- the key fingerprints in the build parameters;
- the fields of a third-party InRelease as fetched (`keyed inrelease <value> <set>:<field>`).

**Third-party apt metadata.** The metadata of the third-party repositories (InRelease and their indexes) are not
snapshots and change when the repository is re-signed; differences in them are expected, the installed content is
checked strictly against the lock. Closed list (`build-manifest.py`: `INRELEASE_SETS`, `FETCH_FIELDS`): only the sets
`nvidia-driver` (CUDA `debian13/x86_64`), `nvidia-container-toolkit` (libnvidia-container `stable`) and `k8s`
(pkgs.k8s.io `v1.34`), only the fields `inrelease.sha256`, `inrelease.date`, `inrelease.valid_until`,
`index.sha256|sha512`, `index.size` and `packages_gz.*`; another set or field is a difference. Strict: the rest of
`apt-pin-inputs.json` as one line `input file <sha256> apt-pin-inputs.json:stable` (the signing key's fingerprint and
keyring, origin, label, suite, every `.deb` with sha256 and size, the sha256 of the lock) and one line per set
`input param ok apt-pin-chain:<set>` (the InRelease signed by the pinned key, the index = the signed InRelease, every
file = its Packages stanza = the lock; any failure stops the build before the manifest). An InRelease cannot be fetched
again once replaced upstream, so it is not pinned in the lock.

The image carries no InRelease anchor of a third-party repository: the image is tied to the repository through the
signing key and the sha256 of each `.deb` in the SBOM (`/usr/share/foilbird/sbom/nvidia-inputs.json`, the
`foilbird:nvidia-repository` property: repository, version, key); the date and signature of the InRelease of a given
build are in its build manifest (decision 0017).

Every other line — `/usr` file contents and modes, links, directories, packages and versions, input files — must be
equal. Ownership is not in the manifest (an unprivileged extraction cannot read it); it is checked separately on a root
build.

Sizes (manifest v2): `keyed` partition images, the UKI and keyed `/usr` files carry their size in bytes. The size of the
`/usr` verity hash tree (`*.usr-x86-64-verity.raw`) and of the disk image (`<name>_<V>.raw`) must be equal between the
two builds: a different size is a different layout whatever the keys. The other sizes are printed for reference. A v1
manifest has no sizes; compare prints that and does not fail on it.

Nothing of the build host leaks into the image or the manifest: `build-all.sh` sets the modes of the tree to what git
records (0644/0755 for files, 0755 for their directories) and builds under umask 022, so a checkout under another umask
gives the same `/usr`; build parameters and provenance name files relative to the tree, never by an absolute path.

A signed kernel module carries exactly one appended signature, the db one: dkms signs inside the build chroot with a
throwaway key of its own, and `mkosi.build` strips every appended signature before signing with the db key and fails
unless exactly one is present afterwards.

## NVIDIA components

The NVIDIA kernel modules (built from `nvsrc/` by `mkosi.build` and signed with the image's db key) and the NVIDIA
userspace are in the variant `gpu` only. The variant `cp` (`apt-pin.py prepare --source-only nvidia-driver`) carries no
NVIDIA component: no module, no userspace, no SBOM record of one. Neither is redistributable under this
project's licence. A deployment builds them itself from NVIDIA's repository. CI builds them inside the job and publishes
nothing: no upload, no cache.
