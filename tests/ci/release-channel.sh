#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The harness releases of one build: offline checks of releases 1-4 and the update channel of releases 2 3 4 (tests/README.md
# "Releases and the channel"). Used by the harness stage of .github/workflows/build.yml (STAGE=harness); never contacts the
# network.
#
#   tests/ci/release-channel.sh --out <dir> --keys <dir> --agent-dist <dir> --channel <dir> [--t7-tree <dir>]
#     --out         one build-all.sh output directory per release: <dir>/1 .. <dir>/4 (foilbird-deb_<V>.*, build-params.txt,
#                   lab-gate.txt)
#     --keys        the TEST key set the four were built with (tests/lib/keys.sh: sb/, pcr/, release.pgp, gpg/)
#     --agent-dist  the agent dist in the images (agent/build-release.sh: SHA256SUMS, foil-agent)
#     --channel     new directory: the channel (xz partitions with their partition UUID + UKI of 2 3 4, SHA256SUMS + .gpg
#                   signed with the TEST release key). The harness serves it itself (CHANNEL=<dir>)
#     --t7-tree     the T7 overlay release 3 was built with (default tests/overlays/t7-broken-foil-config)
# Release parameters (the same in tests/README.md and the job):
#   1, 2  epoch 1, min 1, pcr-e1     3  epoch 1, min 1, pcr-e1 + T7 overlay     4  epoch 2, min 4, pcr-e2
#   all four: release epochs 1:1,2:4
# Checks per release: rootHash of the verity signature = usrhash= of the UKI; build-params (epoch/min/table, PCR and db
# certificates of --keys, profile, not a lab build); lab-gate PASS; .osrel FOILBIRD_PCR_EPOCH/FOILBIRD_MIN_VERSION/IMAGE_VERSION and
# FOILBIRD_PROFILE; .pcrpkey = the release's PCR key; the T7 overlay file only in release 3. Then lab-gate --dist on release 1, the
# channel's signature and sums, every channel file = its out file. Last line "CHANNEL PASS|FAIL"; exit 0 only on PASS.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/../.." && pwd)
die() { echo "release-channel.sh: $*" >&2; exit 2; }
out=; keys=; dist=; chan=; t7=$repo/tests/overlays/t7-broken-foil-config
while [ $# -gt 0 ]; do
  case $1 in
    --out) out=${2:?}; shift 2 ;; --keys) keys=${2:?}; shift 2 ;; --agent-dist) dist=${2:?}; shift 2 ;;
    --channel) chan=${2:?}; shift 2 ;; --t7-tree) t7=${2:?}; shift 2 ;;
    *) die "unknown option $1 (see the header)" ;;
  esac
done
[ -n "$out" ] && [ -n "$keys" ] && [ -n "$dist" ] && [ -n "$chan" ] || die "--out, --keys, --agent-dist and --channel are needed"
[ -e "$chan" ] && die "$chan exists: the channel is always new"
TAB=1:1,2:4; PUB="2 3 4"; T7F=usr/lib/systemd/system/foil-config.service.d/99-t7-broken.conf
[ -s "$t7/$T7F" ] || die "no T7 overlay file $t7/$T7F"
spec() { case $1 in 1|2) echo "1 1 pcr-e1" ;; 3) echo "1 1 pcr-e1" ;; 4) echo "2 4 pcr-e2" ;; esac; }
fpr() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
bad=0; fail() { echo "  FAIL $*"; bad=1; }
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT

for v in 1 2 3 4; do
  o=$out/$v; read -r e m p <<< "$(spec $v)"; bd=""
  [ -s "$o/foilbird-deb_$v.efi" ] || { fail "$v: no $o/foilbird-deb_$v.efi"; continue; }
  rh=$(tr -d '\0' < "$o/foilbird-deb_$v.usr-x86-64-verity-sig.raw" | grep -o '"rootHash":"[0-9a-f]*"' | cut -d'"' -f4)
  uh=$(grep -a -o 'usrhash=[0-9a-f]*' "$o/foilbird-deb_$v.efi" | head -1 | cut -d= -f2)
  [ -n "$rh" ] && [ "$rh" = "$uh" ] || bd="$bd rootHash/usrhash"
  bp=$o/build-params.txt
  grep -qx "epoch=$e min_version=$m release_epochs=$TAB" "$bp" || bd="$bd build-params($(grep ^epoch= "$bp"))"
  grep -qx "pcr_cert_sha256=$(fpr "$keys/pcr/$p.crt")" "$bp" || bd="$bd pcr_cert!=$p"
  grep -qx "sb_cert_sha256=$(fpr "$keys/sb/db.crt")" "$bp" || bd="$bd sb_cert"
  grep -qE '^profile=(.*/)?profiles/k8s-worker$' "$bp" || bd="$bd profile($(grep ^profile= "$bp"))"
  grep -q 'lab_build=yes' "$bp" && bd="$bd lab_build"
  tail -n 1 "$o/lab-gate.txt" | grep -q 'result=PASS' || bd="$bd lab-gate"
  objcopy -O binary --only-section=.osrel "$o/foilbird-deb_$v.efi" "$t/osrel"
  objcopy -O binary --only-section=.pcrpkey "$o/foilbird-deb_$v.efi" "$t/pk"
  { grep -qx "FOILBIRD_PCR_EPOCH=$e" "$t/osrel" && grep -qx "FOILBIRD_MIN_VERSION=$m" "$t/osrel" &&
    grep -qE "^IMAGE_VERSION=\"?$v\"?\$" "$t/osrel" && grep -qx 'FOILBIRD_PROFILE=k8s-worker' "$t/osrel"; } ||
    bd="$bd osrel($(grep -E '^(FOILBIRD_|IMAGE_VERSION)' "$t/osrel" | paste -sd,))"
  cmp -s <(openssl pkey -pubin -in "$t/pk" -outform DER 2>/dev/null) <(openssl pkey -pubin -in "$keys/pcr/$p.pem" -outform DER) ||
    bd="$bd .pcrpkey!=$p"
  # the T7 overlay file in the /usr image (EROFS) of release 3 only
  rm -rf "$t/usr"; fsck.erofs --extract="$t/usr" "$o/foilbird-deb_$v.usr-x86-64.raw" > /dev/null 2>&1 || bd="$bd fsck.erofs"
  if [ -f "$t/usr/${T7F#usr/}" ]; then [ $v = 3 ] && cmp -s "$t/usr/${T7F#usr/}" "$t7/$T7F" || bd="$bd t7-overlay-in-$v"
  else [ $v = 3 ] && bd="$bd no-t7-overlay"; fi
  rm -rf "$t/usr"
  [ -z "$bd" ] && echo "  $v PASS epoch=$e min=$m $p usrhash=${rh:0:16} raw=$(sha256sum < "$o/foilbird-deb_$v.raw" | cut -c1-16)" || fail "$v:$bd"
done
f=$(sh "$repo/images/debian/tools/lab-gate" --usr-image "$out/1/foilbird-deb_1.usr-x86-64.raw" --dist "$dist" 2>&1 | tail -n 1)
echo "$f" | grep -q 'result=PASS' && echo "  lab-gate --dist release 1: $f" || fail "lab-gate --dist release 1: $f"

mkdir -p "$chan"
for v in $PUB; do o=$out/$v; raw=$o/foilbird-deb_$v.raw
  for tp in usr-x86-64:usr_ usr-x86-64-verity:usr-verity_ usr-x86-64-verity-sig:usr-verity-sig_; do
    u=$(sfdisk -J "$raw" | python3 -I -c "import json,sys; print([p['uuid'] for p in json.load(sys.stdin)['partitiontable']['partitions'] if p['name'].startswith('${tp#*:}')][0].lower())") ||
      { fail "channel $v ${tp%%:*}: no partition"; continue; }
    xz -T0 -2 -c "$o/foilbird-deb_$v.${tp%%:*}.raw" > "$chan/foilbird-deb_$v.${tp%%:*}.$u.raw.xz" || fail "xz $v ${tp%%:*}"
  done
  cp "$o/foilbird-deb_$v.efi" "$chan/"
done
(cd "$chan" && sha256sum -- * > SHA256SUMS) && gpg --homedir "$keys/gpg" --batch --yes --detach-sign --output "$chan/SHA256SUMS.gpg" "$chan/SHA256SUMS" ||
  fail "channel signature"
gpg --homedir "$keys/gpg" --verify "$chan/SHA256SUMS.gpg" "$chan/SHA256SUMS" 2>&1 | grep -q 'Good signature' || fail "channel: no good signature"
(cd "$chan" && sha256sum -c --quiet SHA256SUMS) || fail "channel sha256sum -c"
for v in $PUB; do o=$out/$v; cmp -s "$o/foilbird-deb_$v.efi" "$chan/foilbird-deb_$v.efi" || fail "channel $v efi"
  for tp in usr-x86-64 usr-x86-64-verity usr-x86-64-verity-sig; do f=$(ls "$chan"/foilbird-deb_$v.$tp.*.raw.xz 2>/dev/null)
    [ "$(echo "$f" | grep -c .)" = 1 ] && [ "$(xz -dc "$f" | sha256sum | cut -c1-64)" = "$(sha256sum < "$o/foilbird-deb_$v.$tp.raw" | cut -c1-64)" ] ||
      fail "channel $v $tp"; done; done
grep -q 'foilbird-deb_1\.' "$chan/SHA256SUMS" && fail "channel lists release 1"
echo "  channel [$PUB]: $(grep -c . "$chan/SHA256SUMS") files, $(du -sh "$chan" | cut -f1), SHA256SUMS $(sha256sum < "$chan/SHA256SUMS" | cut -c1-16)"
echo "CHANNEL $([ $bad = 0 ] && echo PASS || echo FAIL)"
exit $bad
