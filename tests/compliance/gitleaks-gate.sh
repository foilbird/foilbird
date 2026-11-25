#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Publication gate: gitleaks over the files of a revision (no history: the publication is one commit). Seconds.
#   tests/compliance/gitleaks-gate.sh [--repo DIR] [--rev REV]          (default: . and HEAD)
# The scanner: Debian package gitleaks 8.16.0-1+b12 (amd64), downloaded from snapshot.debian.org at the build's own
# Snapshot= (images/debian/reproducible.conf), accepted only with the pinned sha256 below, unpacked with dpkg-deb -x
# (no apt, no root). GITLEAKS=<binary> runs a given binary instead. Either way the binary must have the pinned
# BIN_SHA256 (Debian's build prints no version: "version is set by build process").
# gitleaks 8.16.0 is old: rules for token formats introduced after it may be missing. Update the package (version,
# file name, sha256) together with the next change of Snapshot=; a Snapshot= without this version fails the download.
# 1. probe: a copy of the tree plus a generated test secret (a fresh EC private key in PEM, made by openssl at run time
#    and nowhere else) must be reported - a scanner that misses it fails the gate;
# 2. the tree: 0 findings. Findings are printed redacted (file:line and rule only).
# A line that is a known false positive carries "gitleaks:allow" with its reason (gitleaks' own marker), one line at a
# time; there is no allowlist by rule or path.
# Last line: "GITLEAKS-GATE PASS|FAIL ..."; exit 0 PASS, 1 FAIL, 2 bad input or no scanner.
set -eu
DEB=gitleaks_8.16.0-1+b12_amd64.deb
SHA256=77da749c812cb875e95bcd7a3dd48cd0ac2420a1c88487f15c996197b81cdfa9
BIN_SHA256=634c8a33c6fd95ef87339f1cc345304655e3d38535a942fd096c37393bd72f8a   # usr/bin/gitleaks of that package
repo=. rev=HEAD
while [ $# -gt 0 ]; do
    case $1 in
        --repo) repo=$2; shift 2 ;;
        --rev) rev=$2; shift 2 ;;
        *) echo "gitleaks-gate: unknown argument $1" >&2; exit 2 ;;
    esac
done
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
die() { echo "gitleaks-gate: $*" >&2; echo "GITLEAKS-GATE FAIL $*"; exit 2; }
R=$(git -C "$repo" rev-parse --verify "$rev^{commit}") || die "no commit $rev in $repo"

if [ -z "${GITLEAKS:-}" ]; then
    snap=$(git -C "$repo" show "$R:images/debian/reproducible.conf" | sed -n 's/^Snapshot=\([0-9TZ]*\)$/\1/p')
    [ -n "$snap" ] || die "no Snapshot= in images/debian/reproducible.conf of $R"
    url="https://snapshot.debian.org/archive/debian/$snap/pool/main/g/gitleaks/$(echo "$DEB" | sed 's/+/%2B/g')"
    curl -fsSL --retry 3 --retry-delay 5 --max-time 300 -o "$t/$DEB" "$url" || die "download $url"
    echo "$SHA256  $t/$DEB" | sha256sum -c --quiet - || die "$DEB: sha256 is not the pinned $SHA256"
    dpkg-deb -x "$t/$DEB" "$t/pkg"
    GITLEAKS=$t/pkg/usr/bin/gitleaks
    echo "scanner $DEB from $url, sha256 $SHA256 (pinned)"
fi
b=$(sha256sum < "$GITLEAKS" | cut -c1-64)
[ "$b" = "$BIN_SHA256" ] || die "$GITLEAKS: sha256 $b is not the pinned $BIN_SHA256 (gitleaks 8.16.0 of $DEB)"
echo "scanner $GITLEAKS sha256 $b (pinned, gitleaks 8.16.0)"

scan() { # scan <dir> <report.json>: findings count; rc 0/1 of gitleaks kept apart from a failure to run
    "$GITLEAKS" detect --no-git --source "$1" --redact --no-banner --report-format json --report-path "$2" \
        > "$2.log" 2>&1 || true
    [ -s "$2" ] || { cat "$2.log" >&2; die "gitleaks wrote no report for $1"; }
    python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$2"
}
mkdir -p "$t/tree"; git -C "$repo" archive "$R" | tar xf - -C "$t/tree"

cp -a "$t/tree" "$t/probe"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$t/probe/zz-gitleaks-probe.pem" 2>/dev/null \
    || die "openssl genpkey"
n=$(scan "$t/probe" "$t/probe.json")
p=$(python3 -I -c 'import json,sys; print(sum("zz-gitleaks-probe" in f["File"] for f in json.load(open(sys.argv[1]))))' "$t/probe.json")
if [ "$p" -ge 1 ]; then probe=ok; else probe=FAIL; fi
echo "probe: a generated test private key in a copy of the tree: $p finding(s) on it ($probe)"

n=$(scan "$t/tree" "$t/tree.json")
python3 -I -c '
import json, sys
for f in json.load(open(sys.argv[1])):
    print("  leak %s:%s rule=%s" % (f["File"].replace(sys.argv[2] + "/", ""), f["StartLine"], f["RuleID"]))' "$t/tree.json" "$t/tree"
echo "tree $R: $n finding(s)"
if [ "$probe" = ok ] && [ "$n" -eq 0 ]; then
    echo "GITLEAKS-GATE PASS rev $R findings=0 probe=ok"
else
    echo "GITLEAKS-GATE FAIL rev $R findings=$n probe=$probe"; exit 1
fi
