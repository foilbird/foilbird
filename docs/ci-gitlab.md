# CI in a closed network (GitLab) and the offline build

The image is built the same way everywhere: `ci/run-stage.sh` holds the whole CI (steps, gates, summary).
`.github/workflows/build.yml` and `offline.yml` on GitHub Actions and `.gitlab-ci.yml` on GitLab only call it and map their
own variables (`CI_TMP`, `CI_SUMMARY`). A network without access to GitHub or to the public package archives builds from
an **input bundle** made outside and checked inside.

GitLab itself was not set up for this release: `.gitlab-ci.yml` was reviewed by hand (gitlab-ci-lint is a GitLab API,
not available offline). The offline build is proven on GitHub Actions by the `offline` stage (below).

## Runner

- GitLab runner with the shell executor, or the docker executor with `privileged = true` (mkosi needs loop devices and
  namespaces); Debian 13 or Ubuntu 24.04.
- `/dev/kvm` for the harness stage (`harness`): the runner must expose KVM to the job (shell executor on a host with KVM,
  or the docker executor with `/dev/kvm` passed in). The `harness` job is manual (web or a harness-try tag), never on a
  push, and its result is informational: the counted harness run is the one on GitHub Actions.
- mkosi runs as root (only the three build entries, with an explicit environment): `sudo env …` for the runner user, or
  the build host wrapper `nl-build` (its `--pkgcache`/`--offline` options are needed for an offline build through it).
- `/opt/foilbird-build-tools`: created once by root, owned by the runner user (`sudo install -d -o <user> -g <group>
  /opt/foilbird-build-tools`; `ci/run-stage.sh` does it through sudo where it can, else it must already exist and be
  writable). The agent's build tools live at one absolute path on every build machine (docs/reproducible-build.md,
  "Build tools of the agent").
- Disk: at least 60 GB free for one job (two tools trees, the build overlay, the image, the bundle).
- The runner's tag is the project variable `NL_RUNNER_TAG`.
- The runner host outlives the job (`NL_SHARED_HOST=1` in `.gitlab-ci.yml`): the job changes nothing of it outside its
  work directory — `HOME` and the TEST keys are there, no toolchain is removed and no docker image pruned, nothing is
  installed with apt-get (the host packages of `ci/run-stage.sh` — `musl-tools rustup uidmap debian-archive-keyring
  python3 git gnupg openssl erofs-utils`, for the harness also `fdisk xz-utils binutils` — are installed beforehand, a
  missing one fails its step by name), and the offline stage puts the host's agent tools set aside and back.
- Docker on the runner host: the job's containers and image carry the job id (`NL_DOCKER_TAG`), are removed when the
  stage starts and on its way out; `NL_DOCKER_CPUS` (a runner or project variable) gives each container `--cpus`,
  since docker's cgroup is outside any CPU quota of the runner.

## The input bundle

`ci/bundle.sh make` writes a directory with:

- the apt-pin and upstream cache (`apt-pin.py fetch`, `fetch-upstream.py fetch`, checked against the committed locks);
- of mkosi's package cache (`PackageCacheDirectory=`), filled by an online build of the same revision, only
  `cache/apt/archives/*.deb`, and of its repository metadata (`CacheDirectory=` = `NL_PKGCACHE/mkosi-cache`, where
  mkosi 26 keeps the apt lists; without it they would be in a temporary directory) only the `*_InRelease` and
  `*_Packages` lists: an explicit list, nothing of apt's own state (`partial/`, `lock`, `auxfiles`, `*.bin`) nor
  `Sources`/`Translation`;
- the default tools tree of that build, one tar made as root (`tar --xattrs --acls --numeric-owner`; the three build
  directories hold the same one, equal `mkosi.tools.manifest`) with its `mkosi.tools.manifest`: mkosi 26 does not pass
  `CacheDirectory=` on to the default tools tree, so an offline build could not build one (no repository metadata);
- mkosi at its pinned commit (`git archive`);
- the agent's offline inputs (`agent/tools/offline-inputs.sh fetch`: the Rust toolchain with its signatures, the crates
  of the release tools, `cargo vendor`);
- `MANIFEST.sha256`: the revision, its commit time, the bundle's creation time, the Debian snapshot, the mkosi commit,
  the sha256 of both lock files and of every file.

`ci/bundle.sh verify` (inside, before anything is used) refuses the bundle unless:

1. `NL_BUNDLE_FPR` is a non-empty list of **full** fingerprints (40 hex digits, commas or spaces); a short key id is
   refused;
2. `MANIFEST.sha256.sig` is a good signature by a key of `NL_BUNDLE_KEYRING` whose **primary** fingerprint is in the
   list (a subkey only as a subkey of a listed key), and the key is neither expired nor revoked (`gpgv --status-fd`:
   any of EXPKEYSIG, EXPSIG, REVKEYSIG, BADSIG, ERRSIG, NO_PUBKEY refuses);
3. the host clock is not behind the bundle's creation time nor the revision's commit time ("clock behind bundle");
4. the revision and both locks are the tree's own;
5. every file is listed with its sha256, none is missing, none is extra; the tools tree is there.

The age of the bundle is reported (`created`); past 30 days a warning, no hard expiry in this release.

A bundle serves one offline build: mkosi runs as root with the bundle's package cache, and apt leaves its own root-owned
files there (`partial/`, `lock`, `cache/apt/pkgcache.bin`, `srcpkgcache.bin`); `verify` of that bundle then finds files
it does not list. A repeat starts from a fresh copy of the signed bundle.

`ci/bundle-apt-verify.py` (in `build-all.sh` with `NL_OFFLINE=1`, after `bundle.sh verify` and the restore of the tools
tree) checks the apt chain of the bundle against the tree, not against the bundle: the Debian archive keyring `.deb`
must have the sha256 pinned in `images/debian/debian-archive-keyring.sha256` for the tree's `Snapshot=` (a new snapshot
needs a new pin); every `InRelease` is verified by sqv (of the pinned Debian 13 tools, never the host's) against its
anchor (that keyring for snapshot.debian.org, the pinned fingerprint of `apt-pin.conf` for the apt-pin sets) and only the
signed text is read; every `Packages` must be in the signed text of its `InRelease` with its sha256 and size; every
`.deb` must have its stanza (package, version, architecture) in a verified `Packages` with its sha256; a `Packages`
without its `InRelease`, an `InRelease` without its `Packages` and a `.deb` without a stanza are refused.
**Valid-Until is not checked:** mkosi 26 runs apt with `Acquire::Check-Valid-Until=false` for every source, online and
offline (it is not a change of this stage). With the snapshot pinned (`Snapshot=`) and the third-party `.deb` pinned by
sha256 in the locks, the metadata of a bundle cannot move on; the signature is checked, the expiry is not.

The signature protects the transfer. Trust in the contents still comes from the same chains as online: `apt-pin.py`
checks every `.deb` against the signed repository metadata and the lock, the agent's inputs against their signatures,
and `ci/bundle-apt-verify.py` checks mkosi's cache (below): apt itself does not verify the lists again when it installs
from a cache. A correct, re-signed manifest over a changed `.deb` is refused by these chains (probes below).

**Clocks.** A closed network trusts its own clock. The expiry of a key is decided by the host clock only; a clock set
back hides an expired key. `verify` refuses a clock behind the bundle, which catches a clock far behind, not a clock a
few weeks off.

## The signing key (decision of the owner)

- The key belongs to the organisational role **bundle-signing**, not to a person. Who holds it and how it is changed
  is written in the network owner's own documents, not in this tree.
- The private part lives only outside the closed network (a vault or a hardware token). Inside there are only the
  public keys (`NL_BUNDLE_KEYRING`) and the protected variable `NL_BUNDLE_FPR`. GitLab in the closed network only
  checks the signature, it never signs; the key is never given to a CI job.
- Signing is a separate step, not a build job: the build outside hands over the bundle and its manifest; the holder
  checks them (`ci/bundle.sh verify OUT --tree DIR --unsigned` and the revision) and signs (`ci/bundle.sh sign`). The key
  never reaches a build environment.
- The key is valid for one year. Rotation: add the new fingerprint to `NL_BUNDLE_FPR`, a period with both keys, remove
  the old one; each change goes into the network's change log.
- Emergency revocation: the revocation certificate is made together with the key and kept offline. A closed network
  does not receive revocation certificates on its own: revocation there **is** removing the fingerprint from
  `NL_BUNDLE_FPR`.
- Different network owners have different keys. The TEST key of the CI job below is never carried anywhere.

What the network owner defines in their own documents (not here):

- who signs (not the person who builds);
- how the bundle is checked before signing;
- who approves a change of `NL_BUNDLE_FPR` and where that change is audited;
- the dates of the rotation window;
- the emergency revocation;
- the recovery after a compromise of the key;
- the log of signatures.

## NL_OFFLINE=1

- `apt-pin.py fetch` and `fetch-upstream.py fetch` refuse; only `verify` and `prepare` from the cache run.
- The three mkosi entries get `--package-cache-dir=$NL_PKGCACHE --cache-directory=$NL_PKGCACHE/mkosi-cache
  --cache-only=always` (`images/debian/tools/mkosi-offline.sh`): the package manager does not contact the network.
- The tools tree is the bundle's, restored as root into the three build directories (`ci/offline.sh`, or `nl-build
  restore-tools` on a build host); `build-all.sh` refuses an offline build where it is missing or not the bundle's
  (`mkosi.tools.manifest`): an offline build never builds one.
- mkosi is the one in the bundle (its commit checked by the manifest), not a clone.
- `build-all.sh` starts only from a verified bundle: `NL_BUNDLE` passes `ci/bundle.sh verify` (signature, every file, only
  regular files and directories) before the first step, `NL_PKGCACHE` and `--cache` are the bundle's own; a refusal stops
  the build before any root entry or mkosi. On a build host with the root wrapper (`NL_BUILD`), `NL_PKGCACHE` and
  `NL_OFFLINE` go as its `--pkgcache` and `--offline`, the only two values it takes from the caller.
- The agent is built from its offline inputs (`offline-inputs.sh verify`, `install`, then `agent/build-release.sh`).

## The offline stage (GitHub Actions, `offline.yml`, `ci/run-stage.sh offline`)

One job, nothing leaves it (no upload; only manifests and the summary go to the log). The job is manual (a push to a
`ci/offline-try-*` branch, an `offline-try-*` tag) and is not part of `build.yml`: a green pipeline without it proves nothing
about the offline build; only this job's run on GitHub Actions does. `.gitlab-ci.yml` has the same stage as its manual
`offline` job (web or an `offline-try-*` tag; the commit carries an `offline-try-*` tag).


1. an online cp build with `NL_PKGCACHE` (manifest A);
2. the bundle, signed with an ephemeral TEST key of the role made in the job (a mechanism check only; its fingerprint is
   only in this job's list; its private part is removed right after the probes, and on any failure of the stage);
3. refusal probes, each on a copy of the bundle, each refused with its own reason: a changed file; an extra and a missing
   file; a foreign key; a fingerprint not listed; another revision and another lock; an expired key; an empty list and a
   short id; a clock behind the bundle; the TEST key against a product list; a symlink in the bundle; `build-all.sh`
   with a changed file of the package cache (refused before its first step), with its positive control: the intact
   bundle with the same inputs and `--check-inputs` passes and stops before the first step. One positive probe: two fingerprints listed,
   the bundle signed by the second. One probe of the chain: a changed `.deb` under a correct, re-signed manifest is
   accepted by `bundle.sh` and refused by `apt-pin.py`. Probes of the bundle's new parts: a file outside the explicit
   list does not reach the bundle; apt's root-only `partial/` does not stop the make; a changed byte of the tools tree
   archive; the manifest signed by the image's key (another role); and of the apt chain under a correct, re-signed
   manifest: an `InRelease` signed by another key, a changed `Packages`, a changed `.deb`, a new `Snapshot=` without a
   new keyring pin; after the clean, an offline build without the restored tools tree (refused, not rebuilt); after the
   restore, the apt chain on the runner host itself with the restored tools tree's sqv (the path of a build host without
   the tools container): the intact bundle passes, a changed `.deb` is refused;
4. every online leftover removed (tools trees, mkosi's cache and output, the mkosi clone, the caches, `~/.cargo`,
   `~/.rustup`, the agent's `target/`), what stays listed with `du`. The online build writes into the tree as root:
   `apt-pin.py`/`fetch-upstream.py prepare` in the tools container (`aptpin/`, `nvsrc/`, `pinned.conf`,
   `apt-pin-inputs.json`, `upstream/`, `__pycache__/`) and `sudo mkosi` (the images under `out/`, the empty mount points
   of `BuildSources=` in `images/debian/mkosi`). The clean removes them as root, the user that wrote them, and then
   refuses the stage when anything in the tree outside `.git` is not the runner user's, with the names. A build host
   that builds through `nl-build` (root) and cleans through `nl-build clean` (root) meets none of this; the runner's
   path (root writes, the runner user cleans) is checked only here;
5. the network cut **for the build only**: a network namespace with `lo` and a dummy default route, where iptables and
   ip6tables count every packet but `lo` (UDP 53 included: its `resolv.conf` names an address behind the dummy route)
   and drop it; the tools container runs with `--network none`. Probes inside (DNS and TCP to the public archives) must
   fail, and each must be counted and dropped (its own counter file: counted > 0, dropped = counted); a control outside
   must reach the network (the runner keeps its own connection, a host-wide drop would cut it);
6. the bundle verified, cp built again from it alone, with `NL_OFFLINE=1` (manifest B);
7. `build-manifest.py compare A B` over the closed keyed list: exit 0; the counter file of the offline build present and
   well-formed (missing = FAIL, never "0 packets"), no packet counted during the offline build.

## Running it in a closed network

1. Outside: build the online stage of the revision, `ci/bundle.sh make`, hand the bundle and the manifest to the holder.
2. The holder: `ci/bundle.sh verify … --unsigned`, compare the revision, `ci/bundle.sh sign`.
3. Carry the bundle in; set `NL_BUNDLE` (its path on the runner), `NL_BUNDLE_FPR`, `NL_BUNDLE_KEYRING` as protected
   variables.
4. Run the build from the bundle: `ci/bundle.sh verify`, then the cp or gpu build with `NL_OFFLINE=1`,
   `NL_PKGCACHE=<bundle>/pkgcache`, `--cache <bundle>/apt-cache`, mkosi from `<bundle>/mkosi.tar` — the steps of
   `ci/offline.sh build`. **Not yet a stage of its own:** in this release `ci/run-stage.sh offline` makes its bundle in the
   same job; a stage that takes an external `NL_BUNDLE` is the next step (the `.gitlab-ci.yml` jobs run online stages and
   the same-job `offline` stage).
