# Debian 13 node image (proof of concept)

mkosi configuration for a Debian 13 (trixie) node image:

- signed UKI (systemd-boot, Secure Boot with the deployment's keys, auto-enroll in setup mode);
- `/usr` as erofs on signed dm-verity, `root=tmpfs`, `lockdown=integrity module.sig_enforce=1`;
- NVIDIA open kernel modules, in an image with the NVIDIA userspace only (`--variant gpu`; version: `apt-pin.conf`, set
  `nvidia-driver`), built with DKMS **in the build stage only** and signed with the
  deployment's db key; only signed `.ko` files end up in the image (no compiler, no DKMS on the node);
- package files that would land in `/etc` are moved to `/usr/share/factory` and restored by tmpfiles.

`poc-checks/` (`foil-poc-check`) with `t9/` and `tools/cuda-init.c` are the PoC boot checks (Secure Boot state, module
signature enforcement, verity read, `nvidia-smi`, CUDA driver init). A product build has none of them: `mkosi.build`
builds the T9 modules and `cuda-init` into `/usr/lib/foil-poc-check` only with `FOILBIRD_POC_CHECKS=1`, and `foil-poc-check` comes only with
the extra tree `poc-checks/tree` (`poc-checks/README.md`).

`tools/lab-gate` fails on a build that carries lab-only code: the agent features `lab-crash-points` and
`esp-bridge-tls`, `foil-var-epoch` built with `-DFOILBIRD_VAR_EPOCH_LAB`, or a PoC boot check (`foil-poc-check`,
`/usr/lib/foil-poc-check`), shipped or pulled in by a unit directory, a preset or a dependency. It checks an agent dist (`--dist`), an image tree (`--root`) or the `/usr` partition image of a
build (`--usr-image out/<V>/foilbird-deb_<V>.usr-x86-64.raw`, needs `fsck.erofs`); exit 0 product, 1 lab code, 2 bad input.
`build-image.sh` runs it on every image it builds (`<output dir>/lab-gate.txt`): a product build fails on lab code; a lab
build is marked `--lab` and fails if the gate finds none.

## Building

```sh
cd images/debian
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=<db> -keyout db.key -out db.crt      # once, never committed
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=<pcr> -keyout pcr.key -out pcr.crt   # PCR 11 policy key
gpg --export <release key fingerprint> > release.gpg                                                # public release key
tools/apt-pin.py fetch   --conf apt-pin.conf --cache ~/apt-cache                 # only what is missing, then verify
tools/apt-pin.py prepare --conf apt-pin.conf --cache ~/apt-cache --out-dir mkosi # verify, write mkosi/pinned.conf
foilbird-initrd/build.sh && recovery/build.sh
./build-image.sh --version 1 --output-dir out/1 --release-keyring release.gpg --sb-key db.key --sb-cert db.crt \
  --pcr-key pcr.key --pcr-cert pcr.crt --epoch 1 --min-version 1 --channel https://updates.example.org/foilbird/ \
  --include mkosi/pinned.conf
```

`tools/build-all.sh` runs the same steps after the fetch, offline from the cache, with the agent, the k8s-worker
profile and the build manifest (`tools/build-manifest.py`), in one call shared by build hosts and CI. The mkosi
entries run as root (`sudo env`, explicit environment): as an unprivileged user mkosi 26 leaves every file 0:0 and drops
setgid bits. `--variant cp` carries no NVIDIA package (the variant table is in the header of `tools/build-all.sh`). `--variant gpu` installs every pinned set and builds the open NVIDIA
modules from `nvsrc/`, signed.

Everything that belongs to a deployment is an argument of `build-image.sh`, not part of the tree: the default update
channel (`--channel`, optional: without it the node takes its channel from `NodeConfig.update_channel`), the release key
(`--release-keyring`, exactly one key), the Secure Boot db key (`--sb-key`/`--sb-cert`) and the PCR policy key
(`--pcr-key`/`--pcr-cert`). A profile is built with `--profile ../../profiles/<name>` and its `--include` files. The
script writes `<output-dir>/build-params.txt` (channel, key fingerprints, epoch).

The release keyring ends up as `usr/lib/systemd/import-pubring.gpg` and, with the same content, `import-pubring.pgp`
(systemd 257 reads the first, 259 the second). The build fails unless that keyring holds exactly the release key:
Debian's default `import-pubring.gpg` carries Fedora, Ubuntu and openSUSE keys and would accept their signatures on the
update channel. It also fails when the channel file and the `sysupdate.d` sources disagree.

### Third-party apt inputs (NVIDIA driver; for a profile also the container toolkit and pkgs.k8s.io)

`tools/apt-pin.py` keeps a local cache of every pinned set of `apt-pin.conf` (NVIDIA: the repository's `InRelease`, the
Packages index, the `cuda-keyring` package, the open-module source and the whole userspace closure of one version) and
checks it with one function, whether a file has just been downloaded or comes from the cache. The cache is never a
second source of trust:

    file  <-  its Packages stanza (Filename, Size, SHA256 or SHA512)
          <-  the Packages index, whose hash is in the signed text of InRelease (only the text sqv returns as verified is read)
          <-  InRelease signature, checked by sqv (the verifier of Debian 13's apt), digest not MD5/SHA1/RIPEMD160
          <-  the repository key: fingerprint pinned in the script (`0218 2E60 104F CDC2 6EAE 1B85 97A5 D4CB 8793 F200`
              for NVIDIA's `debian13` repository); every self-signature and binding of the key must use a strong digest,
              so a SHA1-bound key is refused even with the right fingerprint

Then the lock: every file (URL, size, sha256) must have its line in `apt-pin.lock`, and every line its file. The chain
proves where a file comes from, the lock that it is the same file as in the build that wrote the lock: a republished
repository stops the build instead of changing it. `apt-pin.py lock` rewrites the lock from the verified chain after a
pin changes; the diff is part of the review.

There is no option to skip a check or to trust another key; a new key is a change of the script. `fetch` retries
transient download errors with exponential back-off and then runs the same check; a build with a filled cache never
contacts the repositories: `prepare` copies the verified files and the original signed metadata into
`mkosi/aptpin/srv/apt-pin/<set>` (apt source `file:/srv/apt-pin/<set>/`, re-verified by apt in the build, apt
preferences admit only the pinned packages from it) and writes `pinned.conf`, `nvsrc/` and `nvsrc/nvidia-inputs.json`,
the provenance of every NVIDIA input (key, `InRelease` hash and date, each `.deb` with URL and sha256), which the build
copies to `/usr/share/foilbird/sbom/nvidia-inputs.json` in the image (`apt-pin-inputs.json`: all sets). All of it is
gitignored.
`tools/apt-pin-test.py` runs the refusal probes against a filled cache, for every set: a changed `.deb`, a `.deb` with a
matching sha256 but no signed chain, unsigned or foreign-signed `InRelease`, a planted key, forged hash lines after the
signature, a lock line with another sha256, a missing and a stale lock line; once, a SHA1-bound key (`--sha1-key`).

NVIDIA's licence terms restrict redistribution of its driver and user space: images that contain NVIDIA components (the `.ko` files,
the userspace) are built by each deployment from NVIDIA's repository and are not published by this project.

## Keys

Signing keys are generated by the deployment and never committed; `build-image.sh` copies the db key to `mkosi/mkosi.{key,crt}` (gitignored), where mkosi and the build script read it.
