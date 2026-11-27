#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The agent's C toolchain (agent/c-toolchain.pins) in the container the CI builds the agent in (ci/run-stage.sh step
# agent online, ci/offline.sh build offline): what is installed is the toolchain actually used, read back from it.
#   ci/agent-toolchain.sh apt-args                    the pinned packages as name=version, for apt-get install
#   ci/agent-toolchain.sh check <exec...>             in the container (<exec...>: docker exec <name>): every pinned
#                                                     package at exactly its version (dpkg-query), cc = the pinned gcc,
#                                                     ld = the pinned binutils, musl-gcc there; one line, rc 1 otherwise
#   ci/agent-toolchain.sh comment <binary> <exec...>  readelf -p .comment of <binary> (read in the container) carries every
#                                                     pinned comment line and no "GCC: (...)" line that is not pinned; one
#                                                     line, rc 1 otherwise
#   ci/agent-toolchain.sh record <file> <exec...>     the installed version of every pinned package, "<package> <version>"
#                                                     per line, into <file> (the dist's C-TOOLCHAIN; build-all.sh puts it
#                                                     into the build manifest); rc 1 if a package is missing
# Exit: 0 as pinned, 1 a difference (named), 2 usage or no pins.
set -euo pipefail
top=$(cd "$(dirname "$0")/.." && pwd)
PINS=$top/agent/c-toolchain.pins
pkgs() { awk '$1 == "package" && NF == 3 {print $2, $3}' "$PINS"; }
want=$(sed -n 's/^comment //p' "$PINS")          # every pinned comment line, one per line
wcc=$(grep -m1 '^GCC: (Debian ' <<< "$want" || true)   # the Debian gcc: cc --version must name it
[ -n "$(pkgs)" ] && [ -n "$wcc" ] || { echo "agent-toolchain: $PINS has no package or no 'comment GCC: (Debian ...)' line" >&2; exit 2; }
first() { printf '%s\n' "${1%%$'\n'*}"; }   # first line of a captured output (no head in a pipe: no SIGPIPE)
case ${1:-} in
apt-args) pkgs | awk '{printf "%s%s=%s", (NR > 1 ? " " : ""), $1, $2} END {print ""}' ;;
check)
  shift; [ $# -gt 0 ] || { echo "agent-toolchain: check <exec...>" >&2; exit 2; }
  bad=; got=
  while read -r n v; do
    h=$("$@" dpkg-query -W -f '${Version}' "$n" 2>/dev/null) || h=missing
    got="$got $n $h,"
    [ "$h" = "$v" ] || bad="$bad $n $h (pinned $v);"
  done < <(pkgs)
  o=$("$@" cc --version 2>/dev/null) || o=missing; cc=$(first "$o")
  # cc names the gcc of the comment line: "cc (Debian 14.2.0-19) 14.2.0" for "GCC: (Debian 14.2.0-19) 14.2.0"
  [ "${cc#cc }" = "${wcc#GCC: }" ] || bad="$bad cc [$cc] is not ${wcc#GCC: };"
  o=$("$@" ld --version 2>/dev/null) || o=missing; ld=$(first "$o")
  bv=$(pkgs | awk '$1 == "binutils" {sub(/-[^-]*$/, "", $2); print $2}')
  case $ld in "GNU ld "*" $bv") ;; *) bad="$bad ld [$ld] is not binutils $bv;" ;; esac
  mg=$("$@" sh -c 'command -v musl-gcc' 2>/dev/null) || { mg=missing; bad="$bad no musl-gcc;"; }
  echo "agent C toolchain $([ -z "$bad" ] && echo PASS || echo FAIL) (agent/c-toolchain.pins):${got%,}; cc: $cc; ld: $ld; musl-gcc: $mg${bad:+; differs:$bad}"
  [ -z "$bad" ] ;;
comment)
  b=${2:?binary}; shift 2; [ $# -gt 0 ] || { echo "agent-toolchain: comment <binary> <exec...>" >&2; exit 2; }
  if ! o=$("$@" readelf -p .comment "$b" 2>&1); then echo "agent .comment FAIL: readelf -p .comment $b: $(first "$o")"; exit 1; fi
  lines=$(sed -n 's/^ *\[ *[0-9a-f]*\] *//p' <<< "$o" | LC_ALL=C sort -u)
  other=$(grep -E '^GCC: \(' <<< "$lines" | grep -vxF -f <(printf '%s\n' "$want") || true)
  missing=$(grep -vxF -f <(printf '%s\n' "$lines") <<< "$want" || true)
  r=0; [ -z "$other" ] && [ -z "$missing" ] || r=1
  echo "agent .comment $([ $r = 0 ] && echo PASS || echo FAIL) ($(basename "$b"); pinned [$(paste -sd'|' <<< "$want" | sed 's/|/ | /g')]): $(paste -sd'|' <<< "$lines" | sed 's/|/ | /g')${missing:+; missing: $(paste -sd'|' <<< "$missing")}${other:+; not pinned: $(paste -sd'|' <<< "$other")}"
  exit $r ;;
record)
  f=${2:?file}; shift 2; [ $# -gt 0 ] || { echo "agent-toolchain: record <file> <exec...>" >&2; exit 2; }
  : > "$f"
  while read -r n v; do
    h=$("$@" dpkg-query -W -f '${Version}' "$n" 2>/dev/null) || { echo "agent-toolchain: record: $n not installed" >&2; exit 1; }
    echo "$n $h" >> "$f"
  done < <(pkgs) ;;
*) sed -n '2,16p' "$0" >&2; exit 2 ;;
esac
