#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Test harness: boots a built image in QEMU (OVMF, Secure Boot, swtpm) and checks it through the agent API.
# Building is not done here: the image and foilctl are inputs. See tests/README.md.
#
#   tests/run.sh [scenario...]          default: every tests/scenarios/NN-*.sh in order; a name is "install" or "10-install"
#   tests/run.sh --list
#   tests/run.sh --selfcheck            the harness's own tools, no image needed (tools, OVMF, KVM, keys, swtpm, virt-fw-vars)
# Inputs (environment): IMAGE (foilbird-deb_N.raw), FOILCTL (foilctl of the same agent dist); optional VERSION (expected
# image version), KEYS (key set of tests/lib/keys.sh; default: generated on tmpfs for this run), ENROLL (auto|vars),
# CHANNEL (published releases for the scenarios after ApplyConfig, lib/channel.sh; signed with the release key of KEYS),
# AGENT_SUMS (SHA256SUMS of the agent dist; default next to FOILCTL), STRICT=1 (a SKIP fails the run), NODE, NTP,
# BASE_VERSION AB_VERSION T7_VERSION EPOCH_VERSION EPOCH (releases, lib/steps.sh), MAXSHUT, T7_TIMEOUT,
# WORK (work directory; default a new one under ${TMPDIR:-/var/tmp}), KEEP=1 (keep guests' disks, keys and WORK),
# API_TIMEOUT, SETTLE, DISK_SIZE, VM_MEM, VM_SMP, VM_CPUS, ACCEL.
# Output: TEST lines (tests/lib/common.sh) on stdout and in $WORK/results.txt, logs in $WORK/logs/<scenario>/, last
# line "HARNESS PASS|FAIL <passed>/<checks> checks, <skipped> skipped, ..."; exit 0 only when no check failed (and,
# with STRICT=1, none was skipped).
set -uo pipefail
. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
. "$TESTS_DIR/lib/vm.sh"
. "$TESTS_DIR/lib/check.sh"
. "$TESTS_DIR/lib/codes.sh"
. "$TESTS_DIR/lib/channel.sh"
. "$TESTS_DIR/lib/node.sh"
. "$TESTS_DIR/lib/steps.sh"

scen_files() { ls "$TESTS_DIR"/scenarios/[0-9][0-9]-*.sh 2>/dev/null | sort; }
if [ "${1:-}" = --list ]; then for f in $(scen_files); do b=$(basename "$f" .sh); echo "$b: $(sed -n 2p "$f" | sed 's/^# //')"; done; exit 0; fi

# --selfcheck: the harness's own tools, without an image (tools, OVMF, KVM, keys, swtpm, virt-fw-vars enrollment)
selfcheck() {
  WORK=${WORK:-$(mktemp -d "${TMPDIR:-/var/tmp}/harness.XXXXXX")}; mkdir -p "$WORK"; RESULTS=$WORK/results.txt; : > "$RESULTS"
  SCENARIO=selfcheck; local c miss="" k d
  for c in qemu-system-x86_64 swtpm openssl gpg python3 virt-fw-vars fsck.erofs timeout truncate; do command -v "$c" >/dev/null || miss="$miss $c"; done
  [ -z "$miss" ] && res host tools PASS "$(qemu-system-x86_64 --version | head -1); $(swtpm --version 2>&1 | head -1)" || res host tools FAIL "missing:$miss"
  miss=""
  for c in "$OVMF_CODE_SB" "$OVMF_CODE" "$OVMF_VARS"; do [ -s "$c" ] || miss="$miss $c"; done
  [ -z "$miss" ] && res host ovmf PASS "$(basename "$OVMF_CODE_SB") $(basename "$OVMF_VARS")" || res host ovmf FAIL "missing:$miss"
  if python3 -I -c 'import fcntl,os; fd=os.open("/dev/kvm", os.O_RDWR); assert fcntl.ioctl(fd, 0xAE00) == 12; os.close(fcntl.ioctl(fd, 0xAE01, 0))' 2>/dev/null
  then res host kvm PASS "KVM_GET_API_VERSION=12, KVM_CREATE_VM ok"; else res host kvm FAIL "/dev/kvm not usable (guests would run under TCG)"; fi
  k=$(ram_dir) && bash "$TESTS_DIR/lib/keys.sh" gen "$k" > "$WORK/keys.txt" && bash "$TESTS_DIR/lib/keys.sh" check "$k" \
    && res host keys PASS "TEST set on $(stat -f -c %T "$k"): $(wc -l < "$WORK/keys.txt") fingerprints" || res host keys FAIL "keys.sh"
  d=$WORK/selfcheck; mkdir -p "$d/tpm"
  if swtpm socket --tpm2 --tpmstate dir="$d/tpm" --ctrl type=unixio,path="$d/swtpm.sock" --pid file="$d/swtpm.pid" --daemon; then
    sleep 0.5; [ -S "$d/swtpm.sock" ] && res host swtpm PASS "socket up" || res host swtpm FAIL "no socket"; kill "$(cat "$d/swtpm.pid")" 2>/dev/null
  else res host swtpm FAIL "swtpm did not start"; fi
  if [ -n "${k:-}" ] && virt-fw-vars --input "$OVMF_VARS" --output "$d/vars.fd" --set-pk "$(cat "$k/sb/owner.guid")" "$k/sb/PK.crt" \
       --add-kek "$(cat "$k/sb/owner.guid")" "$k/sb/KEK.crt" --add-db "$(cat "$k/sb/owner.guid")" "$k/sb/db.crt" --secure-boot > "$d/enroll.log" 2>&1
  then res host enroll-vars PASS "PK/KEK/db enrolled, Secure Boot on ($(stat -c %s "$d/vars.fd") bytes)"; else res host enroll-vars FAIL "virt-fw-vars (log $d/enroll.log)"; fi
  [ -n "${k:-}" ] && rm -rf "$k"
  local total failed; total=$(grep -c '^TEST ' "$RESULTS"); failed=$(awk '$1 == "TEST" && $5 == "FAIL"' "$RESULTS" | grep -c . || true)
  echo "HARNESS $([ "$failed" = 0 ] && echo PASS || echo FAIL) $((total - failed))/$total checks (selfcheck), work $WORK" | tee -a "$RESULTS"
  [ "$failed" = 0 ]
}
if [ "${1:-}" = --selfcheck ]; then selfcheck; exit; fi

sel=()
if [ $# -eq 0 ]; then sel=($(scen_files)); else
  for s in "$@"; do f=$(ls "$TESTS_DIR"/scenarios/"$s".sh "$TESTS_DIR"/scenarios/[0-9][0-9]-"$s".sh 2>/dev/null | head -1)
    [ -n "$f" ] || die "no scenario $s (tests/run.sh --list)"; sel+=("$f"); done
fi

need qemu-system-x86_64 swtpm openssl gpg python3 base64 timeout truncate
[ "${ENROLL:-auto}" = vars ] && need virt-fw-vars
for f in "$OVMF_CODE_SB" "$OVMF_VARS"; do [ -s "$f" ] || die "missing $f (package ovmf)"; done
[ -x "${FOILCTL:-}" ] || die "FOILCTL=<foilctl of the agent dist> missing or not executable"
[ -s "${IMAGE:-}" ] || die "IMAGE=<foilbird-deb_N.raw> missing"
IMAGE=$(readlink -f "$IMAGE"); FOILCTL=$(readlink -f "$FOILCTL")
[ -z "${CHANNEL:-}" ] || { CHANNEL=$(readlink -f "$CHANNEL"); [ -d "$CHANNEL" ] || die "CHANNEL=$CHANNEL is not a directory"; need fsck.erofs; }
[ "$(vm_accel)" = kvm ] || log "WARNING: no usable /dev/kvm, guests run under TCG (slow; raise API_TIMEOUT)"

WORK=${WORK:-$(mktemp -d "${TMPDIR:-/var/tmp}/harness.XXXXXX")}; mkdir -p "$WORK"; WORK=$(readlink -f "$WORK")
own_keys=0
if [ -z "${KEYS:-}" ]; then KEYS=$(ram_dir) || exit 2; own_keys=1; bash "$TESTS_DIR/lib/keys.sh" gen "$KEYS" > "$WORK/keys.txt"; fi
bash "$TESTS_DIR/lib/keys.sh" check "$KEYS" || die "KEYS=$KEYS incomplete"
RESULTS=$WORK/results.txt; : > "$RESULTS"
export WORK KEYS RESULTS IMAGE FOILCTL CHANNEL

cleanup() {
  channel_down
  local d; for d in "$WORK"/vm/*/; do [ -d "$d" ] && vm_stop "$(basename "$d")" $([ "${KEEP:-0}" = 1 ] || echo --wipe); done
  [ "$own_keys" = 1 ] && [ "${KEEP:-0}" != 1 ] && rm -rf "$KEYS"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

{ echo "image $IMAGE sha256 $(sha256sum < "$IMAGE" | cut -c1-64)"; echo "foilctl $FOILCTL sha256 $(sha256sum < "$FOILCTL" | cut -c1-64)"
  echo "revision $(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"; echo "accel $(vm_accel)"
  [ -z "${CHANNEL:-}" ] || echo "channel $CHANNEL SHA256SUMS $(sha256sum < "$CHANNEL/SHA256SUMS" | cut -c1-64)"
  qemu-system-x86_64 --version | head -1; swtpm --version 2>&1 | head -1; } | tee "$WORK/inputs.txt" >&2

T0=$(date +%s.%N)
for f in "${sel[@]}"; do
  b=$(basename "$f" .sh); SCENARIO=${b#[0-9][0-9]-}; LOGS=$WORK/logs/$b; mkdir -p "$LOGS"; export SCENARIO LOGS
  . "$f"
  st=$(date +%s.%N); log "=== scenario $b"
  "scenario_${SCENARIO//-/_}"
  log "=== scenario $b done in $(since "$st")s"
done
# the verdict is field 5 of "TEST <scenario> <node> <check> <verdict> <detail>"; a detail may quote "FAIL" (t7: the
# node's boot-check FAIL is the expected fact of a PASS line)
total=$(grep -c '^TEST ' "$RESULTS" || true); failed=$(awk '$1 == "TEST" && $5 == "FAIL"' "$RESULTS" | grep -c . || true)
skipped=$(awk '$1 == "TEST" && $5 == "SKIP"' "$RESULTS" | grep -c . || true); passed=$((total - failed - skipped))
verdict=PASS; { [ "$passed" -gt 0 ] && [ "$failed" = 0 ]; } || verdict=FAIL
[ "${STRICT:-0}" = 1 ] && [ "$skipped" != 0 ] && verdict=FAIL
echo "HARNESS $verdict $passed/$total checks, $skipped skipped, $(since "$T0")s, work $WORK" | tee -a "$RESULTS"
[ "$verdict" = PASS ]
