#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The input bundle of an offline build (docs/ci-gitlab.md): everything a build without network needs, a manifest of
# sha256 sums, and a detached OpenPGP signature of it by a key of the bundle-signing role.
#
#   ci/bundle.sh make   OUT --tree DIR --cache DIR --pkgcache DIR --mkosi DIR --tools-archive FILE --tools-manifest FILE
#                       [--agent-inputs DIR]
#       copies into OUT, by an explicit list and nothing else: the apt-pin/upstream cache; of mkosi's package cache only
#       cache/apt/archives/*.deb and, of its CacheDirectory (mkosi-cache/<key>.metadata.cache/lib/apt/lists), only the
#       *_InRelease and *_Packages lists (no partial/, lock, auxfiles, Sources, Translation, *.bin: apt's own state); the
#       default tools tree as one tar (made as root: tar --xattrs --acls --numeric-owner) with its mkosi.tools.manifest;
#       the pinned mkosi (git archive of its commit) and the agent's offline inputs; then writes OUT/MANIFEST.sha256
#   ci/bundle.sh sign   OUT --gpg-home DIR --key FPR      a separate step, by the holder of the key, never in a build job
#   ci/bundle.sh verify OUT --tree DIR [--unsigned]
#       refuses unless: NL_BUNDLE_FPR is a non-empty list of full (40 hex) fingerprints (commas or spaces); the signature
#       of MANIFEST.sha256 made by a key of NL_BUNDLE_KEYRING whose PRIMARY fingerprint is in the list (a subkey only as a
#       subkey of such a key), good, not expired, not revoked; the host clock not behind the bundle's creation nor the
#       revision's commit time ("clock behind bundle": expiry is only decided by a right clock); the revision and both
#       lock files of the manifest the tree's own; every file listed with its sha256, none missing, none extra; nothing
#       but regular files and directories (no symlink, device, fifo).
#       --unsigned (the holder's check before signing): everything but the signature and the fingerprint list.
# The signature protects the transfer; trust in the contents still comes from the chains of apt-pin.py and of the
# agent's inputs, checked again after verify (a correct manifest over a forged .deb is refused there).
set -euo pipefail
die() { echo "bundle.sh: $*" >&2; exit 2; }
act=${1:?make|sign|verify}; out=${2:?OUT}; shift 2
tree=; cache=; pkgcache=; mkd=; agent=; ghome=; key=; unsigned=0; tarc=; tman=
while [ $# -gt 0 ]; do
  case $1 in
    --tree) tree=$(cd "${2:?}" && pwd); shift 2 ;;
    --cache) cache=${2:?}; shift 2 ;;
    --pkgcache) pkgcache=${2:?}; shift 2 ;;
    --mkosi) mkd=${2:?}; shift 2 ;;
    --agent-inputs) agent=${2:?}; shift 2 ;;
    --tools-archive) tarc=${2:?}; shift 2 ;;
    --tools-manifest) tman=${2:?}; shift 2 ;;
    --gpg-home) ghome=${2:?}; shift 2 ;;
    --key) key=${2:?}; shift 2 ;;
    --unsigned) unsigned=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
M=MANIFEST.sha256
LOCKS="images/debian/apt-pin.lock profiles/k8s-worker/apt-pin.lock"

case $act in
make)
  [ -n "$tree" ] && [ -d "$cache" ] && [ -d "$pkgcache" ] && [ -d "$mkd/.git" ] || die "make needs --tree --cache --pkgcache --mkosi (a git clone)"
  [ -f "$tarc" ] && [ -f "$tman" ] || die "make needs --tools-archive and --tools-manifest (the default tools tree, tar made as root)"
  [ -e "$out" ] && die "$out exists"
  mkdir -p "$out"
  cp -a "$cache" "$out/apt-cache"
  # mkosi's package cache and its repository metadata, by name: regular files only, nothing of apt's own state
  a=$out/pkgcache/cache/apt/archives; mkdir -p "$a"; nd=0
  for f in "$pkgcache"/cache/apt/archives/*.deb; do [ -f "$f" ] && [ ! -L "$f" ] || continue; cp -- "$f" "$a/"; nd=$((nd + 1)); done
  ni=0; np=0
  for md in "$pkgcache"/mkosi-cache/*.metadata.cache; do
    [ -d "$md/lib/apt/lists" ] || continue
    l=$out/pkgcache/mkosi-cache/$(basename "$md")/lib/apt/lists; mkdir -p "$l"
    for f in "$md"/lib/apt/lists/*_InRelease; do [ -f "$f" ] && [ ! -L "$f" ] || continue; cp -- "$f" "$l/"; ni=$((ni + 1)); done
    for f in "$md"/lib/apt/lists/*_Packages; do [ -f "$f" ] && [ ! -L "$f" ] || continue; cp -- "$f" "$l/"; np=$((np + 1)); done
  done
  [ "$nd" -gt 0 ] && [ "$ni" -gt 0 ] && [ "$np" -gt 0 ] || die "package cache incomplete: $nd .deb, $ni InRelease, $np Packages (an online build with NL_PKGCACHE first)"
  mkdir -p "$out/tools"; cp -- "$tarc" "$out/tools/mkosi.tools.tar"; cp -- "$tman" "$out/tools/mkosi.tools.manifest"
  echo "bundle: package cache $nd .deb, metadata $ni InRelease + $np Packages; tools tree $(du -h "$out/tools/mkosi.tools.tar" | cut -f1) sha256 $(sha256sum < "$out/tools/mkosi.tools.tar" | cut -c1-64), mkosi.tools.manifest sha256 $(sha256sum < "$out/tools/mkosi.tools.manifest" | cut -c1-64)"
  git -C "$mkd" archive --format=tar --prefix=mkosi/ HEAD > "$out/mkosi.tar"
  [ -n "$agent" ] && cp -a "$agent" "$out/agent-inputs"
  {
    echo "# foilbird input bundle v1"
    echo "revision $(git -C "$tree" rev-parse HEAD)"
    echo "commit-time $(git -C "$tree" log -1 --format=%ct)"
    echo "created $(date +%s)"
    echo "snapshot $(sh "$tree/images/debian/tools/snapshot" check)"
    echo "mkosi $(git -C "$mkd" rev-parse HEAD)"
    for l in $LOCKS; do echo "lock $(sha256sum < "$tree/$l" | cut -c1-64) $l"; done
    (cd "$out" && find . -type f ! -name "$M" ! -name "$M.sig" -printf '%P\n' | LC_ALL=C sort | while IFS= read -r f; do
      echo "file $(sha256sum < "$f" | cut -c1-64) $f"; done)
  } > "$out/$M"
  echo "bundle: $(grep -c '^file ' "$out/$M") files, $(du -sh "$out" | cut -f1), manifest sha256 $(sha256sum < "$out/$M" | cut -c1-64)" ;;
sign)
  [ -n "$ghome" ] && [ -n "$key" ] || die "sign needs --gpg-home and --key"
  [ -s "$out/$M" ] || die "no $out/$M"
  gpg --homedir "$ghome" --batch --yes --local-user "$key" --detach-sign --output "$out/$M.sig" "$out/$M"
  echo "bundle: signed by $key" ;;
verify)
  [ -n "$tree" ] || die "verify needs --tree"
  [ -s "$out/$M" ] || die "no $out/$M"
  head -n 1 "$out/$M" | grep -qx '# foilbird input bundle v1' || die "not a v1 bundle manifest"
  if [ $unsigned = 0 ]; then
    fprs=$(printf '%s' "${NL_BUNDLE_FPR:-}" | tr ',' ' ' | tr -s ' ' '\n' | grep . | tr 'a-f' 'A-F' || true)
    [ -n "$fprs" ] || die "NL_BUNDLE_FPR is empty: no key may sign this bundle"
    for f in $fprs; do grep -qE '^[0-9A-F]{40}$' <<< "$f" || die "NL_BUNDLE_FPR: $f is not a full 40-hex fingerprint"; done
    [ -s "${NL_BUNDLE_KEYRING:-}" ] || die "NL_BUNDLE_KEYRING: no public keyring of the bundle-signing role"
    [ -s "$out/$M.sig" ] || die "no signature $out/$M.sig"
    st=$(gpgv --status-fd 1 --keyring "$NL_BUNDLE_KEYRING" "$out/$M.sig" "$out/$M" 2>/dev/null || true)
    if grep -qE '^\[GNUPG:\] (EXPKEYSIG|EXPSIG|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY|KEYEXPIRED|KEYREVOKED)( |$)' <<< "$st"; then
      die "signature refused: $(echo "$st" | grep -oE '^\[GNUPG:\] (EXPKEYSIG|EXPSIG|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY|KEYEXPIRED|KEYREVOKED)' | head -n 1 | cut -d' ' -f2)"
    fi
    grep -q '^\[GNUPG:\] GOODSIG ' <<< "$st" || die "signature refused: no GOODSIG"
    # VALIDSIG <fpr of the signing key> ... <fpr of its primary key> (last field)
    prim=$(echo "$st" | awk '$2 == "VALIDSIG" {print toupper($NF)}' | head -n 1)
    [ -n "$prim" ] || die "signature refused: no VALIDSIG"
    grep -qx "$prim" <<< "$fprs" || die "signature by $prim: not in NL_BUNDLE_FPR"
    echo "bundle: signature good, primary key $prim in NL_BUNDLE_FPR"
  fi
  now=$(date +%s); cr=$(awk '$1 == "created" {print $2}' "$out/$M"); ct=$(awk '$1 == "commit-time" {print $2}' "$out/$M")
  case $cr$ct in ''|*[!0-9]*) die "manifest without created/commit-time" ;; esac
  [ "$now" -ge "$cr" ] && [ "$now" -ge "$ct" ] && [ "$now" -ge "$(git -C "$tree" log -1 --format=%ct)" ] || die "clock behind bundle: now $now, created $cr, commit $ct"
  # no hard expiry in alpha: the age is reported, a warning past 30 days (apt checks no Valid-Until either: mkosi v26)
  age=$(( (now - cr) / 86400 )); echo "bundle: created $(date -u -d "@$cr" +%FT%TZ), age $age days"
  [ "$age" -le 30 ] || echo "bundle: WARN: older than 30 days ($age)"
  rv=$(awk '$1 == "revision" {print $2}' "$out/$M")
  [ "$rv" = "$(git -C "$tree" rev-parse HEAD)" ] || die "bundle of revision $rv, the tree is $(git -C "$tree" rev-parse HEAD)"
  for l in $LOCKS; do
    want=$(awk -v l="$l" '$1 == "lock" && $3 == l {print $2}' "$out/$M")
    [ "$want" = "$(sha256sum < "$tree/$l" | cut -c1-64)" ] || die "lock $l of the bundle is not the tree's"
  done
  # only regular files and directories: a symlink, device or fifo would be neither listed nor checked
  odd=$(cd "$out" && find . -mindepth 1 ! -type f ! -type d -printf '%P\n' | head -n 3 | tr '\n' ' ')
  [ -z "$odd" ] || die "not a regular file or directory: $odd"
  [ -f "$out/tools/mkosi.tools.tar" ] && [ -f "$out/tools/mkosi.tools.manifest" ] || die "no tools tree in the bundle (tools/mkosi.tools.tar, tools/mkosi.tools.manifest)"
  listed=$(grep '^file ' "$out/$M" | cut -d' ' -f3- | LC_ALL=C sort)   # a path may hold spaces: field 3 to the end
  present=$(cd "$out" && find . -type f ! -name "$M" ! -name "$M.sig" -printf '%P\n' | LC_ALL=C sort)
  [ "$listed" = "$present" ] || die "files missing or extra: $(diff <(echo "$listed") <(echo "$present") | grep '^[<>]' | head -n 3 | tr '\n' ' ')"
  (cd "$out" && grep '^file ' "$M" | sed -E 's/^file ([0-9a-f]{64}) /\1  /' | sha256sum -c --quiet --strict) || die "a file does not match its sha256"
  echo "bundle: verified $(echo "$listed" | grep -c .) files, revision $rv$([ $unsigned = 1 ] && echo ' (unsigned check)')" ;;
*) die "make|sign|verify" ;;
esac
