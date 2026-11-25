# SPDX-License-Identifier: Apache-2.0
# Shared helpers of the test harness (sourced; bash). See tests/README.md.
#
# Results: every check writes one line to $RESULTS and to stdout:
#   TEST <scenario> <node> <check> PASS|FAIL|SKIP <detail>
# A run passes when it wrote at least one PASS and no FAIL; SKIP (an input of the check is missing) is counted apart,
# and with STRICT=1 it fails the run like a FAIL.

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_DIR=$(cd "$TESTS_DIR/.." && pwd)

ts() { date -u +%H:%M:%S.%3N; }
log() { echo "$(ts) $*" >&2; }
die() { echo "harness: $*" >&2; exit 2; }

# res <node> <check> <PASS|FAIL|SKIP> <detail...>
res() {
  local node=$1 check=$2 verdict=$3; shift 3
  echo "TEST ${SCENARIO:-?} $node $check $verdict $*" | tee -a "${RESULTS:?}"
  case $verdict in PASS) ;; SKIP) [ "${STRICT:-0}" = 1 ] && FAILS=$((${FAILS:-0} + 1)) ;; *) FAILS=$((${FAILS:-0} + 1)) ;; esac
}

# free TCP port on 127.0.0.1
free_port() {
  python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# seconds since an epoch value from `date +%s.%N`
since() { awk -v a="$1" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }'; }

# a directory on a RAM file system for key material (never on disk): $XDG_RUNTIME_DIR, else /dev/shm
ram_dir() {
  local base
  for base in "${XDG_RUNTIME_DIR:-}" /dev/shm; do
    [ -n "$base" ] && [ -d "$base" ] && [ -w "$base" ] || continue
    case $(stat -f -c %T "$base" 2>/dev/null) in tmpfs|ramfs) mktemp -d "$base/harness-keys.XXXXXX"; return 0;; esac
  done
  die "no tmpfs for the test keys (XDG_RUNTIME_DIR or /dev/shm); set KEYS to a directory you made yourself"
}

# need <command>... : stop with the list of what is missing
need() {
  local c miss=""
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || miss="$miss $c"; done
  [ -z "$miss" ] || die "missing:$miss (packages: tests/deps.txt)"
}
