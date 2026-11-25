#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# One build of a node image from a filled, verified cache (docs/reproducible-build.md): the same call on a build host
# and in CI. It never contacts a third-party repository: the cache is filled before (apt-pin.py fetch for every set file,
# profiles/k8s-worker/tools/fetch-upstream.py fetch) and everything below re-verifies it offline.
#
#   build-all.sh --version <N> --variant <cp|gpu> --keys <dir> --agent-dist <dir> --cache <dir> --output-dir <dir>
#                --epoch <E> --min-version <M> [--profile <dir>] [--channel <url|/path>] [--channel-ca <pem>]
#                [--release-epochs <E:F,...>] [--lab] [--pcr <name>] [--extra-tree <dir>] [--image-only]
#
#   --variant      cp   no NVIDIA package installed: every NVIDIA set of the set files (nvidia_sets below: nvidia-driver,
#                       nvidia-container-toolkit) is verified in full and installs nothing (apt-pin.py prepare
#                       --source-only; nvidia-driver keeps its module source for the provenance), so no userspace, no
#                       kernel module, no toolkit, no nvidia-persistenced or CDI wiring (mkosi.build and mkosi.finalize
#                       decide by the userspace; mkosi.finalize of k8s-worker refuses an NVIDIA package in dpkg status)
#                  gpu  every pinned set installed: NVIDIA userspace, the open NVIDIA modules built from nvsrc/ and signed
#   --keys         a key set in the layout of tests/lib/keys.sh (sb/db.{key,crt}, pcr/pcr-e1.{key,crt}, release.pgp); in
#                  CI the ephemeral TEST set of `keys.sh gen`, never a deployment key
#   --agent-dist   agent dist of agent/build-release.sh (SHA256SUMS checked by agent/stage-image-tree.sh)
#   --cache        the cache of apt-pin.py / fetch-upstream.py (filled and verified before)
#   --output-dir   build-image.sh output; build-all.sh adds build-manifest.txt (tools/build-manifest.py make)
#   --pcr          PCR signing key of the release in --keys: pcr/<name>.{key,crt} (default pcr-e1; an epoch-2 release
#                  of the test harness: pcr-e2)
#   --extra-tree   one more mkosi extra tree for this image only (mkosi --extra-tree=<dir>:/), e.g. the T7 overlay of
#                  tests/overlays; not with NL_BUILD (the build host wrapper fixes the mkosi call). Its file list with
#                  sha256 goes to <output-dir>/extra-tree.sha256 and into the manifest (input file ... extra-tree.sha256)
#   --image-only   skip the slot initrd and the recovery UKI and reuse those of the previous build of this tree (the
#                  harness releases 2-4 of one job): both outputs must exist, the db key in place must be the same
#   other options  passed to build-image.sh as they are
#   Without --pcr, --extra-tree and --image-only the build is the reproducible one, unchanged.
# Environment:
#   TOOLS_EXEC     command prefix for apt-pin.py and fetch-upstream.py, which need Debian 13's sqv (--cleartext): in CI a
#                  Debian 13 container that sees the tree and the cache at the same paths (`docker exec -w <tree> NAME`);
#                  empty = the host (a Debian 13 build host)
#   SOURCE_DATE_EPOCH  default: commit time of the tree
#   NL_BUILD       a build host's root wrapper (/usr/local/sbin/nl-build, the only command its user may sudo): the three
#                  mkosi entries go through `sudo -n $NL_BUILD --tree <tree> --sde <epoch> initrd|recovery|image ...`,
#                  which fixes the environment and mkosi itself. Unset (CI): `sudo env PATH=... SOURCE_DATE_EPOCH=...`
#
# Steps: agent staged -> apt-pin.py prepare (both set files) -> fetch-upstream.py prepare (profile k8s-worker) ->
# foilbird-initrd/build.sh -> recovery/build.sh -> build-image.sh --include mkosi/pinned.conf (lab-gate inside) -> manifest.
# mkosi runs as root (as an unprivileged user mkosi v26 maps one uid and every
# file of the image ends up 0:0, setgid bits of /usr lost). Only the three mkosi entries run as root, through
# `sudo env PATH=... SOURCE_DATE_EPOCH=...` (an explicit environment, never sudo -E); everything else runs as the caller.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd); top=$(cd "$here/../.." && pwd)
die() { echo "build-all.sh: $*" >&2; exit 2; }
step() { echo "== build-all: $*"; }
profile=; version=; variant=; keys=; dist=; cache=; out=; epoch=; minv=; pass=(); pcr=pcr-e1; xtree=; imgonly=0
while [ $# -gt 0 ]; do
  case $1 in
    --profile) profile=$(cd "${2:?}" && pwd); shift 2 ;;
    --version) version=${2:?}; shift 2 ;;
    --variant) variant=${2:?}; shift 2 ;;
    --keys) keys=$(cd "${2:?}" && pwd); shift 2 ;;
    --agent-dist) dist=$(cd "${2:?}" && pwd); shift 2 ;;
    --cache) cache=$(cd "${2:?}" && pwd); shift 2 ;;
    --output-dir) out=${2:?}; shift 2 ;;
    --epoch) epoch=${2:?}; shift 2 ;;
    --min-version) minv=${2:?}; shift 2 ;;
    --channel|--channel-ca|--release-epochs) pass+=("$1" "${2:?}"); shift 2 ;;
    --lab) pass+=(--lab); shift ;;
    --pcr) pcr=${2:?}; shift 2 ;;
    --extra-tree) xtree=$(cd "${2:?}" && pwd); shift 2 ;;
    --image-only) imgonly=1; shift ;;
    *) die "unknown option $1 (see the header of this script)" ;;
  esac
done
for v in version:--version variant:--variant keys:--keys dist:--agent-dist cache:--cache out:--output-dir epoch:--epoch \
         minv:--min-version; do n=${v%%:*}; [ -n "${!n}" ] || die "${v#*:} missing (see the header)"; done
case $variant in cp|gpu) ;; *) die "--variant is cp or gpu" ;; esac
case $pcr in ''|*[!a-z0-9-]*) die "--pcr: a key name such as pcr-e2";; esac
[ -z "$xtree" ] || [ -z "${NL_BUILD:-}" ] || die "--extra-tree is not supported through NL_BUILD"
for f in sb/db.key sb/db.crt pcr/$pcr.key pcr/$pcr.crt release.pgp; do [ -s "$keys/$f" ] || die "--keys: $keys/$f missing"; done
[ -s "$dist/SHA256SUMS" ] || die "--agent-dist: $dist/SHA256SUMS missing"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then SOURCE_DATE_EPOCH=$(git -C "$top" log -1 --format=%ct); fi
case $SOURCE_DATE_EPOCH in ''|*[!0-9]*) die "SOURCE_DATE_EPOCH must be a number";; esac
export SOURCE_DATE_EPOCH
read -r -a tx <<< "${TOOLS_EXEC:-}"

# modes of the tree as git records them, whatever umask the checkout ran with: mkosi copies the modes of the extra trees
# into /usr, and git keeps only the executable bit, so a checkout under umask 0002 gave 0664 files and 0775 directories in
# the image where a checkout under 0022 gives 0644/0755. Every tracked file gets 0644 or 0755 (its git mode), every
# directory holding one 0755; what this script and the tools it calls create afterwards follows umask 022.
umask 022
python3 -I - "$top" <<'PY'
import os, subprocess, sys
top = sys.argv[1]
out = subprocess.run(["git", "-C", top, "ls-files", "-s", "-z"], capture_output=True, check=True).stdout
want, uid = {}, os.getuid()
for e in out.split(b"\0"):
    if not e:
        continue
    meta, path = e.split(b"\t", 1)
    mode = meta.split()[0]
    if mode in (b"100644", b"100755"):
        want[path] = 0o755 if mode == b"100755" else 0o644
    d = os.path.dirname(path)
    while d:
        want.setdefault(d + b"/", 0o755)
        d = os.path.dirname(d)
n = 0
for rel, m in sorted(want.items()):
    p = os.path.join(top.encode(), rel.rstrip(b"/"))
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        continue
    # only what the caller owns (a root build's output under a tracked directory stays as it is); never through a link
    if os.path.islink(p) or st.st_uid != uid or (st.st_mode & 0o7777) == m:
        continue
    os.chmod(p, m)
    n += 1
print("build-all: tree modes as in git (umask-independent): %d paths changed" % n)
PY

# root for the mkosi entries only, with an explicit environment: entry <initrd|recovery|image> [build-image.sh options]
entry() {
  local e=$1; shift
  if [ -n "${NL_BUILD:-}" ]; then sudo -n "$NL_BUILD" --tree "$top" --sde "$SOURCE_DATE_EPOCH" "$e" "$@"; return; fi
  local cmd
  case $e in initrd) cd "$here/foilbird-initrd"; cmd=(./build.sh) ;; recovery) cd "$here/recovery"; cmd=(./build.sh) ;;
             image) cmd=("$here/build-image.sh") ;; esac
  if [ "$(id -u)" = 0 ]; then env PATH="$PATH" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "${cmd[@]}" "$@"
  else sudo env PATH="$PATH" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "${cmd[@]}" "$@"; fi
}

confs=(--conf "$here/apt-pin.conf"); locks=(--input "images/debian/apt-pin.lock=$here/apt-pin.lock")
pname=base
if [ -n "$profile" ]; then
  pname=$(basename "$profile")
  if [ -f "$profile/apt-pin.conf" ]; then
    confs+=(--conf "$profile/apt-pin.conf"); locks+=(--input "profiles/$pname/apt-pin.lock=$profile/apt-pin.lock")
  fi
fi
# The NVIDIA sets, one list for every variant decision: cp passes each set of the list that the set files of this build
# have as --source-only (verified, nothing installed), gpu installs every set
# (apt-pin.py for every set file; fetch-upstream.py, which lists the profile's installed packages in upstream.json -> the
# image SBOM, for the profile's set file)
nvidia_sets="nvidia-driver nvidia-container-toolkit"
only=(); only_profile=()
if [ "$variant" = cp ]; then
  for s in $nvidia_sets; do
    for ((i = 1; i < ${#confs[@]}; i += 2)); do
      if grep -qxF "[$s]" "${confs[i]}"; then only+=(--source-only "$s"); break; fi
    done
    if [ -n "$profile" ] && [ -f "$profile/apt-pin.conf" ] && grep -qxF "[$s]" "$profile/apt-pin.conf"; then only_profile+=(--source-only "$s"); fi
  done
fi
echo "build-all: profile $pname variant $variant version $version SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH snapshot $(sh "$here/tools/snapshot" check)"

step "agent staged from $dist"
"$top/agent/stage-image-tree.sh" "$dist"

step "apt-pin.py prepare ${only[*]:-(every set installed)}"
"${tx[@]}" python3 "$here/tools/apt-pin.py" prepare "${confs[@]}" --cache "$cache" --out-dir "$here/mkosi" "${only[@]}"
inputs=("${locks[@]}" --input "apt-pin-inputs.json=$here/mkosi/apt-pin-inputs.json" --input "agent-dist/SHA256SUMS=$dist/SHA256SUMS")
if [ -n "$profile" ] && [ -f "$profile/tools/fetch-upstream.py" ]; then
  step "fetch-upstream.py prepare ${only_profile[*]:-(every set a component)}"
  "${tx[@]}" python3 "$profile/tools/fetch-upstream.py" prepare --cache "$cache" --out "$profile/upstream" "${only_profile[@]}"
  inputs+=(--input "profiles/$pname/upstream.json=$profile/upstream/upstream.json")
fi

# the db key where mkosi reads it (images/debian/mkosi/mkosi.{key,crt}, gitignored): recovery/mkosi.conf signs the
# recovery UKI with ../mkosi/mkosi.key before build-image.sh would copy it there; the same rule as
# build-image.sh: a different key already in place stops the build
for n in key crt; do
  src=$keys/sb/db.$n; dst=$here/mkosi/mkosi.$n
  if [ -e "$dst" ]; then
    [ -r "$dst" ] || die "$dst exists and is not readable (left by a root build?): remove it first"
    cmp -s "$src" "$dst" || die "$dst holds a different key; remove it first"
  else install -m 0600 "$src" "$dst"; fi
done

if [ $imgonly = 1 ]; then
  ini=$here/foilbird-initrd/out/initrd.cpio.zst; rec=$here/recovery/out/EFI/Linux/foilbird-recovery.efi
  [ -s "$ini" ] && [ -s "$rec" ] || die "--image-only: no slot initrd or recovery UKI of a previous build ($ini, $rec)"
  step "slot initrd and recovery UKI reused (--image-only): initrd $(sha256sum < "$ini" | cut -c1-16) recovery $(sha256sum < "$rec" | cut -c1-16)"
else
  step "slot initrd (root)"
  (entry initrd)
  step "recovery UKI (root)"
  (entry recovery)
fi

step "image (root): build-image.sh"
mkdir -p "$out"; out=$(cd "$out" && pwd)   # the caller owns the output directory; mkosi writes into it as root
entry image ${profile:+--profile "$profile"} --version "$version" --output-dir "$out" \
  --release-keyring "$keys/release.pgp" --sb-key "$keys/sb/db.key" --sb-cert "$keys/sb/db.crt" \
  --pcr-key "$keys/pcr/$pcr.key" --pcr-cert "$keys/pcr/$pcr.crt" --epoch "$epoch" --min-version "$minv" \
  --include "$here/mkosi/pinned.conf" "${pass[@]}" ${xtree:+-- "--extra-tree=$xtree:/"}

if [ -n "$xtree" ]; then
  # what the extra tree adds, wherever it lands (/usr, /etc, ESP): its file list with sha256 into the output and the manifest
  # regular files by sha256, links by their target (never followed: a link may dangle or point outside the tree)
  (cd "$xtree" && { find . -type f -print0 | xargs -0 -r sha256sum; find . -type l -printf 'l %l %p\n'; } | LC_ALL=C sort -k2) > "$out/extra-tree.sha256"
  inputs+=(--input "extra-tree.sha256=$out/extra-tree.sha256")
  step "extra tree $xtree: $(grep -c . "$out/extra-tree.sha256") files, list sha256 $(sha256sum < "$out/extra-tree.sha256" | cut -c1-16)"
fi
step "manifest"
python3 "$here/tools/build-manifest.py" make --out-dir "$out" "${inputs[@]}" --output "$out/build-manifest.txt"
echo "build-all: done, $out/build-manifest.txt ($(grep -vc '^#' "$out/build-manifest.txt") lines, sha256 $(sha256sum < "$out/build-manifest.txt" | cut -c1-64))"
