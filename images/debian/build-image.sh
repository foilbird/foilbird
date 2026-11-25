#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build one node image with the deployment's own parameters: the update channel, the release key and the Secure Boot
# and PCR signing keys are arguments, never part of the tree. Run after foilbird-initrd/build.sh and recovery/build.sh.
#
#   build-image.sh --version <N> --output-dir <dir> --release-keyring <file> --sb-key <key> --sb-cert <crt>
#                  --pcr-key <key> --pcr-cert <crt> --epoch <E> --min-version <M>
#                  [--profile <dir>] [--channel <url|/path>] [--channel-ca <pem>] [--include <file>]...
#                  [--release-epochs <E:F,...>] [--lab] [-- <more mkosi options>]
#
#   --profile          profile directory (e.g. profiles/k8s-worker); default: the base image images/debian/mkosi
#   --channel          default release channel of the image: https://… or a local directory; http://… only for a lab
#                      (decision 0002). Written to /usr/lib/foil-agent/channel and, for a URL, to Path= of every
#                      /usr/lib/sysupdate.d transfer. Without it the image has no default channel: the node takes one
#                      from NodeConfig.update_channel, and sysupdate.d keeps the placeholder source.
#   --channel-ca       CA bundle for an https channel (/usr/lib/foil-agent/channel-ca.pem); default: the system bundle
#   --release-keyring  public keyring holding exactly the release key (`gpg --export <fingerprint>`); sysupdate and
#                      foil-var-epoch verify SHA256SUMS.gpg against it
#   --sb-key/--sb-cert Secure Boot db key: signs the UKI, the /usr verity signature and the NVIDIA modules. mkosi and the
#                      build script read it as images/debian/mkosi/mkosi.{key,crt} (gitignored); it is copied there, and
#                      a different key already in place stops the build
#   --pcr-key/--pcr-cert  key that signs the expected PCR 11 policy in the UKI (disk encryption, docs/disk-encryption.md)
#   --epoch/--min-version PCR epoch of this release and the anti-rollback floor (os-release FOILBIRD_PCR_EPOCH/FOILBIRD_MIN_VERSION)
#   --release-epochs   lab builds only: epoch table instead of images/debian/mkosi/release-epochs
#   --lab              a lab build: tools/lab-gate must FIND lab-only code in the result (a lab build without it is an
#                      error, use a product build). Without --lab the build fails unless lab-gate passes
#   --include          mkosi --include (repeatable): pinned.conf of tools/apt-pin.py prepare
#
# Writes <output-dir>/build-params.txt: channel, release key fingerprint, SHA-256 fingerprints of the db and PCR
# certificates, Debian snapshot, SOURCE_DATE_EPOCH (default: commit time) and the partition seed.
# mkosi.finalize checks the result (keyring, channel, epochs).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); base=$here/mkosi
die() { echo "build-image.sh: $*" >&2; exit 2; }
profile=$base; version=; out=; channel=; channel_ca=; keyring=; sbkey=; sbcert=; pcrkey=; pcrcert=; epoch=; minv=; epochs=; lab=0
incl=()
while [ $# -gt 0 ]; do
  case $1 in
    --profile) profile=$(cd "${2:?}" && pwd); shift 2 ;;
    --version) version=${2:?}; shift 2 ;;
    --output-dir) out=${2:?}; shift 2 ;;
    --channel) channel=${2:?}; shift 2 ;;
    --channel-ca) channel_ca=${2:?}; shift 2 ;;
    --release-keyring) keyring=${2:?}; shift 2 ;;
    --sb-key) sbkey=${2:?}; shift 2 ;;
    --sb-cert) sbcert=${2:?}; shift 2 ;;
    --pcr-key) pcrkey=${2:?}; shift 2 ;;
    --pcr-cert) pcrcert=${2:?}; shift 2 ;;
    --epoch) epoch=${2:?}; shift 2 ;;
    --min-version) minv=${2:?}; shift 2 ;;
    --release-epochs) epochs=${2:?}; shift 2 ;;
    --lab) lab=1; shift ;;
    --include) [ -f "${2:?}" ] || die "--include $2: no such file"; incl+=("--include=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"); shift 2 ;;
    --) shift; break ;;
    *) die "unknown option $1 (see the header of this script)" ;;
  esac
done
for v in version:--version out:--output-dir keyring:--release-keyring sbkey:--sb-key sbcert:--sb-cert pcrkey:--pcr-key \
         pcrcert:--pcr-cert epoch:--epoch minv:--min-version; do n=${v%%:*}; [ -n "${!n}" ] || die "${v#*:} missing (see the header)"; done
for f in "$keyring" "$sbkey" "$sbcert" "$pcrkey" "$pcrcert" ${channel_ca:+"$channel_ca"}; do [ -s "$f" ] || die "$f: missing or empty"; done
case $epoch$minv in *[!0-9]*) die "--epoch and --min-version are numbers";; esac

# channel: https URL, a lab http URL or an absolute directory; a URL ends with / (sysupdate appends file names)
case $channel in
  '') ;;
  https://*/|http://*/) h=${channel#*://}; h=${h%%/*}; [ -n "$h" ] || die "--channel $channel: no host"
    case $channel in *[[:space:]\#\"\']*) die "--channel: no spaces, quotes or #";; esac ;;
  /*) [ -z "$channel_ca" ] || die "--channel-ca applies to an https channel only" ;;
  *) die "--channel must be https://host/path/, http://host/path/ (lab) or an absolute directory, with a trailing /" ;;
esac
case $channel in http://*) echo "build-image.sh: WARNING: http channel $channel (lab only, decision 0002)" >&2 ;; esac
[ -z "$channel_ca" ] || case $channel in https://*) ;; *) die "--channel-ca needs an https channel" ;; esac

# keys: certificate and private key belong together
pub() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-64; }
cpub() { openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -c1-64; }
[ "$(pub "$sbkey")" = "$(cpub "$sbcert")" ] || die "--sb-key does not match --sb-cert"
[ "$(pub "$pcrkey")" = "$(cpub "$pcrcert")" ] || die "--pcr-key does not match --pcr-cert"
fprs=$(GNUPGHOME=$(mktemp -d) gpg --batch --show-keys --with-colons "$keyring" 2>/dev/null | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10;p=0}')
[ "$(echo "$fprs" | grep -c .)" = 1 ] || die "--release-keyring must hold exactly one key, it holds [$(echo $fprs)]"
for n in key crt; do
  src=$sbkey; [ $n = crt ] && src=$sbcert
  if [ -e "$base/mkosi.$n" ]; then cmp -s "$src" "$base/mkosi.$n" || die "$base/mkosi.$n holds a different key; remove it first"
  else install -m 0600 "$src" "$base/mkosi.$n"; fi
done

# reproducible inputs (docs/reproducible-build.md): the Debian snapshot of reproducible.conf (must agree with the
# updates source of the build sandbox), SOURCE_DATE_EPOCH = commit time of the tree (mtimes in /usr, the initrd and the
# SBOM, the NVIDIA build date) unless the caller sets it, and a partition-UUID seed derived from profile and version
snapshot=$(sh "$here/tools/snapshot" check) || die "Debian snapshot: reproducible.conf and the updates source disagree"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$here" log -1 --format=%ct 2>/dev/null) || die "SOURCE_DATE_EPOCH unset and $here is not a git tree"
fi
case $SOURCE_DATE_EPOCH in ''|*[!0-9]*) die "SOURCE_DATE_EPOCH must be a number";; esac
export SOURCE_DATE_EPOCH
seed=$(python3 -c 'import sys, uuid; print(uuid.uuid5(uuid.NAMESPACE_URL, "foilbird-deb:" + sys.argv[1] + ":" + sys.argv[2]))' \
  "$(basename "$profile")" "$version")

# extra tree with the deployment's parameters
gen=$(mktemp -d); trap 'rm -rf "$gen"' EXIT
mkdir -p "$gen/usr/lib/systemd" "$gen/usr/lib/foilbird"
install -m 0644 "$keyring" "$gen/usr/lib/systemd/import-pubring.gpg"
install -m 0644 "$keyring" "$gen/usr/lib/systemd/import-pubring.pgp"
openssl x509 -in "$pcrcert" -noout -pubkey > "$gen/usr/lib/foilbird/pcr-key.pem"
if [ -n "$channel" ]; then
  mkdir -p "$gen/usr/lib/foil-agent"; echo "$channel" > "$gen/usr/lib/foil-agent/channel"
  [ -z "$channel_ca" ] || install -m 0644 "$channel_ca" "$gen/usr/lib/foil-agent/channel-ca.pem"
  case $channel in http*)
    mkdir -p "$gen/usr/lib/sysupdate.d"
    for f in "$base"/mkosi.extra/usr/lib/sysupdate.d/*.transfer; do
      sed "s#^Path=https://updates.example.invalid/foilbird-deb/\$#Path=$channel#" "$f" > "$gen/usr/lib/sysupdate.d/${f##*/}"
      grep -qxF "Path=$channel" "$gen/usr/lib/sysupdate.d/${f##*/}" || die "${f##*/}: placeholder Path= not found"
    done ;;
  esac
fi
fpr=$(echo "$fprs" | tr -d ' ')
mkdir -p "$out"
cd "$profile"
mkosi -f "${incl[@]}" --image-version="$version" --output-dir="$out" --extra-tree="$gen:/" \
  --environment=FOILBIRD_RELEASE_KEY_FPR="$fpr" --environment=FOILBIRD_PCR_EPOCH="$epoch" \
  --environment=FOILBIRD_MIN_VERSION="$minv" ${epochs:+--environment=FOILBIRD_RELEASE_EPOCHS="$epochs"} \
  --sign-expected-pcr-key="$pcrkey" --sign-expected-pcr-certificate="$pcrcert" --seed="$seed" "$@" build
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
{ echo "version=$version"; echo "profile=${profile#"$(cd "$here/../.." && pwd)"/}"; echo "channel=${channel:-none}"
  echo "channel_ca=${channel_ca:+$(sha256sum < "$channel_ca" | cut -c1-64)}"; echo "release_key=$fpr"
  echo "sb_cert_sha256=$(fp "$sbcert")"; echo "pcr_cert_sha256=$(fp "$pcrcert")"
  echo "epoch=$epoch min_version=$minv${epochs:+ release_epochs=$epochs}"
  echo "debian_snapshot=$snapshot source_date_epoch=$SOURCE_DATE_EPOCH seed=$seed"
  echo "mkosi=$(mkosi --version 2>/dev/null | head -n 1)"; } > "$out/build-params.txt"
cat "$out/build-params.txt"
# lab-code gate on the finished image (its /usr partition): a product build carries no lab-only code
usr=$(ls "$out"/*_"$version".usr-x86-64.raw 2>/dev/null | head -n 1); [ -n "$usr" ] || die "no /usr image *_$version.usr-x86-64.raw in $out"
rc=0; sh "$here/tools/lab-gate" --usr-image "$usr" > "$out/lab-gate.txt" 2>&1 || rc=$?
tail -n 1 "$out/lab-gate.txt"
case $lab:$rc in
  0:0) echo "lab-gate: product build, no lab code" ;;
  1:1) echo "lab-gate: lab build, lab code found as expected (never publish this image)"; echo "lab_build=yes" >> "$out/build-params.txt" ;;
  0:1) cat "$out/lab-gate.txt" >&2; die "lab-gate FAIL: lab-only code in a product build ($out/lab-gate.txt)" ;;
  1:0) die "--lab, but lab-gate found no lab code: build it as a product image" ;;
  *) cat "$out/lab-gate.txt" >&2; die "lab-gate could not check the image (rc=$rc)" ;;
esac
