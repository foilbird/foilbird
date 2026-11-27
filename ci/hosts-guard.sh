#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The host's hosts file on a shared build host (NL_SHARED_HOST=1, docs/ci-gitlab.md): the gpu image step makes both
# NVIDIA hosts unreachable by 0.0.0.0 lines in it (ci/run-stage.sh nvidia_offline), so the job keeps a copy from its
# start and puts it back on the way out, whatever step fails: in the EXIT trap of run-stage.sh and again from the CI's
# after_script (a cancelled job may never reach the trap).
#
#   ci/hosts-guard.sh save    HOSTS COPY   refuses (rc 1) when HOSTS already has a 0.0.0.0 line of an NVIDIA host (left
#                                          by a job before: nothing to compare against), else COPY + COPY.sha256
#   ci/hosts-guard.sh restore HOSTS COPY   HOSTS back to COPY when they differ, then the sha256 of HOSTS must be the one of
#                                          COPY at save; no COPY: only the check below. rc 1 on any failure
#   ci/hosts-guard.sh final   HOSTS COPY   restore, then COPY removed (after_script, the last user of the copy)
#   ci/hosts-guard.sh check   HOSTS        rc 1 when HOSTS has a 0.0.0.0 line of an NVIDIA host
#
# HOSTS is written in place (its inode, owner and mode stay): directly when writable, else through `sudo -n tee`.
# Every refusal is one line "HOSTS GUARD FAIL: ..." on stdout.
set -uo pipefail
NV_HOSTS="developer.download.nvidia.com nvidia.github.io"   # the hosts of nvidia_offline (ci/run-stage.sh)
fail() { echo "HOSTS GUARD FAIL: $*"; exit 1; }

# the 0.0.0.0 lines of an NVIDIA host (any name of the line), printed
nv_lines() { awk -v hs="$NV_HOSTS" 'BEGIN { n = split(hs, h, " ") }
  /^[[:space:]]*#/ { next }
  $1 == "0.0.0.0" { for (i = 2; i <= NF; i++) for (j = 1; j <= n; j++) if ($i == h[j]) { print; next } }' "$1"; }

check() {
  local f=$1 l
  [ -r "$f" ] || fail "$f: not readable"
  l=$(nv_lines "$f") || fail "$f: not read"
  [ -z "$l" ] || fail "$f carries a 0.0.0.0 line of an NVIDIA host (left by a job before; put the host's file back by hand): $(echo "$l" | head -n 2 | paste -sd'|')"
}

sha() { sha256sum < "$1" | cut -c1-64; }

save() {
  local f=$1 c=$2
  check "$f"
  [ ! -e "$c" ] || fail "$c exists: a copy of another run"
  mkdir -p "$(dirname "$c")" && cp -- "$f" "$c" && sha "$c" > "$c.sha256" || fail "copy of $f to $c"
  [ "$(sha "$f")" = "$(cat "$c.sha256")" ] || fail "$f changed while copied"
  echo "hosts guard: $f saved ($(cat "$c.sha256" | cut -c1-16)), put back on the way out"
}

restore() {
  local f=$1 c=$2 want
  if [ ! -e "$c" ]; then check "$f"; echo "hosts guard: no copy ($c), $f has no NVIDIA 0.0.0.0 line"; return 0; fi
  want=$(cat "$c.sha256" 2>/dev/null) || fail "$c.sha256 missing"
  [ "$(sha "$c")" = "$want" ] || fail "$c differs from its sha256 at save"
  if [ "$(sha "$f")" != "$want" ]; then
    if [ -w "$f" ]; then cat -- "$c" > "$f" || fail "write of $f"
    else sudo -n tee -- "$f" < "$c" > /dev/null || fail "write of $f through sudo -n tee"; fi
    [ "$(sha "$f")" = "$want" ] || fail "$f is not the copy after the write"
    echo "hosts guard: $f put back ($(echo "$want" | cut -c1-16))"
  else
    echo "hosts guard: $f unchanged ($(echo "$want" | cut -c1-16))"
  fi
  check "$f"
}

case ${1:-} in
  save) save "${2:?HOSTS}" "${3:?COPY}" ;;
  restore) restore "${2:?HOSTS}" "${3:?COPY}" ;;
  final) restore "${2:?HOSTS}" "${3:?COPY}" && rm -f -- "$3" "$3.sha256" ;;
  check) check "${2:?HOSTS}"; echo "hosts guard: ${2} has no NVIDIA 0.0.0.0 line" ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
