#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Probe of ci/hosts-guard.sh on files of a temporary directory only (never /etc/hosts): no build, no network, no root,
# seconds. A stand-in for the gpu image step appends the lines nvidia_offline writes (ci/run-stage.sh).
#
#   tests/ci/hosts-guard.sh      last line "HOSTS GUARD PROBE PASS|FAIL <passed>/<checks>"; exit 0 only on PASS
#
# Checks (input -> expectation):
#   save-clean        a hosts file without NVIDIA 0.0.0.0 lines -> rc 0, copy + copy.sha256 written
#   restore-changed   the two lines of nvidia_offline appended -> rc 0, "put back", sha256 = the copy's, same inode
#   restore-same      restore again -> rc 0, "unchanged"
#   leftover          0.0.0.0 nvidia.github.io already there -> save rc 1, "HOSTS GUARD FAIL: … carries a 0.0.0.0 line", no copy
#   leftover-multi    0.0.0.0 with an NVIDIA host as its second name -> save rc 1
#   comment           "# 0.0.0.0 nvidia.github.io" -> save rc 0 (a comment is not a line of the file)
#   other-blocked     0.0.0.0 of another host -> save rc 0
#   copy-exists       save onto an existing copy -> rc 1, "a copy of another run"
#   copy-tampered     the copy changed after save -> restore rc 1, "differs from its sha256"
#   final             final with a copy -> rc 0, the file back, copy and copy.sha256 removed
#   final-no-copy     final without a copy, clean file -> rc 0; with a leftover line -> rc 1
set -uo pipefail
G=$(cd "$(dirname "$0")/../.." && pwd)/ci/hosts-guard.sh
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
n=0; ok=0
check() { # check <name> <want rc: 0|nz> <rc> <out file> [<line the output must carry>]
  n=$((n + 1)); local good=1
  case $2 in 0) [ "$3" = 0 ] || good=0 ;; nz) [ "$3" != 0 ] || good=0 ;; esac
  [ -z "${5:-}" ] || grep -q -F -- "$5" "$4" || good=0
  if [ $good = 1 ]; then ok=$((ok + 1)); echo "ok   $1 (rc $3)"; else echo "FAIL $1 (rc $3): $(tail -n 2 "$4" | paste -sd'|')"; fi
}
run() { local o=$1; shift; rc=0; "$G" "$@" > "$o" 2>&1 || rc=$?; }
base() { printf '127.0.0.1\tlocalhost\n127.0.1.1\tstand\n::1\tlocalhost ip6-localhost\n' > "$1"; }
sha() { sha256sum < "$1" | cut -c1-64; }

h=$t/hosts; c=$t/job.hosts; base "$h"; s0=$(sha "$h"); i0=$(stat -c %i "$h")
run "$t/o1" save "$h" "$c"; [ -s "$c" ] && [ "$(cat "$c.sha256")" = "$s0" ] || rc=99; check save-clean 0 "$rc" "$t/o1" "saved"

for x in developer.download.nvidia.com nvidia.github.io; do echo "0.0.0.0 $x" >> "$h"; done   # as nvidia_offline
run "$t/o2" restore "$h" "$c"; { [ "$(sha "$h")" = "$s0" ] && [ "$(stat -c %i "$h")" = "$i0" ]; } || rc=99
check restore-changed 0 "$rc" "$t/o2" "put back"
run "$t/o3" restore "$h" "$c"; check restore-same 0 "$rc" "$t/o3" "unchanged"

l=$t/left; base "$l"; echo "0.0.0.0 nvidia.github.io" >> "$l"
run "$t/o4" save "$l" "$t/left.copy"; [ ! -e "$t/left.copy" ] || rc=0
check leftover nz "$rc" "$t/o4" "HOSTS GUARD FAIL: $l carries a 0.0.0.0 line of an NVIDIA host"
base "$l"; printf '0.0.0.0\tblocked.example.invalid developer.download.nvidia.com\n' >> "$l"
run "$t/o5" save "$l" "$t/left2.copy"; check leftover-multi nz "$rc" "$t/o5" "HOSTS GUARD FAIL"
base "$l"; echo "# 0.0.0.0 nvidia.github.io" >> "$l"
run "$t/o6" save "$l" "$t/left3.copy"; check comment 0 "$rc" "$t/o6" "saved"
base "$l"; echo "0.0.0.0 blocked.example.invalid" >> "$l"
run "$t/o7" save "$l" "$t/left4.copy"; check other-blocked 0 "$rc" "$t/o7" "saved"

run "$t/o8" save "$h" "$c"; check copy-exists nz "$rc" "$t/o8" "a copy of another run"
cp "$c" "$t/c.keep"; echo "# changed" >> "$c"
run "$t/o9" restore "$h" "$c"; check copy-tampered nz "$rc" "$t/o9" "differs from its sha256"
cp "$t/c.keep" "$c"

echo "0.0.0.0 nvidia.github.io" >> "$h"
run "$t/o10" final "$h" "$c"; { [ "$(sha "$h")" = "$s0" ] && [ ! -e "$c" ] && [ ! -e "$c.sha256" ]; } || rc=99
check final 0 "$rc" "$t/o10" "put back"
run "$t/o11" final "$h" "$c"; check final-no-copy 0 "$rc" "$t/o11" "no copy"
echo "0.0.0.0 developer.download.nvidia.com" >> "$h"
run "$t/o12" final "$h" "$c"; check final-no-copy-left nz "$rc" "$t/o12" "HOSTS GUARD FAIL"

v=FAIL; [ "$ok" = "$n" ] && v=PASS
echo "HOSTS GUARD PROBE $v $ok/$n"
[ $v = PASS ]
