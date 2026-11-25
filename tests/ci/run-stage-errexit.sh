#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Regression probe of the errexit invariant of ci/run-stage.sh: a step runs in a process of its own (run_step), so its
# `set -e` holds whatever the caller, and every checked pipe/command of the oss, host and image steps fails its step.
# Without a build: probe repositories made from the files of this tree, PATH stubs for sudo/curl, a fake tools container.
# Needs git, python3, openssl and the network of the oss step (gitleaks-gate.sh downloads the pinned scanner). Run on a
# build host or in CI (build.yml step errexit), never on a desktop that must stay idle.
#
#   tests/ci/run-stage-errexit.sh      last line "ERREXIT PROBE PASS|FAIL <passed>/<checks>"; exit 0 only on PASS
#
# Checks (each: step -> rc -> the FAIL line of the step):
#   step-seq a step `false; echo after` under run_step: rc != 0, no "after"   (fails if run_step goes back to `step || rc=$?`)
#   step-pipe a step `false | tee; echo after` under run_step: rc != 0, no "after"
#   agent-result agent -> result across step processes: agent rc 0 -> result rc 0; agent rc 3 -> result rc != 0 (agent.outcome in
#      CI_TMP read by the result step's own process)
#   oss-gate oss: a plan reference (letter O and a number in parentheses, made at run time) committed -> oss-gate.py FAIL -> step rc != 0, "OSS STEP FAIL: oss-gate.py"
#   oss-gate-stage the same through the gate stage (run_stage): rc != 0, "run-stage gate: oss failed"
#   oss-clean oss on the clean tree: rc 0
#   gitleaks oss: a synthetic test key (EC private key in PEM generated here, never a real one) committed -> gitleaks-gate.sh
#      FAIL -> step rc != 0, "OSS STEP FAIL: gitleaks-gate.sh"
#   unshallow oss: shallow repository whose origin is unreachable -> "OSS STEP FAIL: git fetch --unshallow"
#   apt-get host: apt-get failing (sudo stub, rc 100) -> "HOST FAIL: apt-get update rc=100"
#   hosts image gpu: the tools container keeps no 0.0.0.0 line -> "NVIDIA OFFLINE FAIL: /etc/hosts of the tools container"
#   hosts-ok the same with a container that keeps the lines and unreachable hosts: rc 0
#   provenance image: provenance of an unreadable apt-pin-inputs.json -> "PROVENANCE FAIL"
#   provenance-ok provenance of minimal valid inputs: rc 0
set -uo pipefail
top=$(cd "$(dirname "$0")/../.." && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
pass=0; total=0
check() { # check <id> <want: 0|nz> <rc> <output file> [line that must be there] [text that must not be there]
  local id=$1 want=$2 rc=$3 out=$4 need=${5:-} not=${6:-} ok=1 line
  if [ "$want" = 0 ]; then [ "$rc" = 0 ] || ok=0; else [ "$rc" != 0 ] || ok=0; fi
  [ -z "$need" ] || grep -qF -- "$need" "$out" || ok=0
  [ -z "$not" ] || ! grep -qF -- "$not" "$out" || ok=0
  line=$( { [ -n "$need" ] && grep -m1 -F -- "$need" "$out"; } || tail -n 1 "$out")
  total=$((total + 1)); [ $ok = 1 ] && pass=$((pass + 1))
  echo "$([ $ok = 1 ] && echo PASS || echo FAIL) $id: rc=$rc (want ${want/nz/!=0}) | ${line:0:200}"
}
# a probe repository: the tracked files of this tree, one commit, a build-try tag; ci/run-stage.sh gets the probe steps
mkrepo() { # mkrepo <dir> [file to add from stdin]
  local d=$1; mkdir -p "$d"
  (cd "$top" && git ls-files -z | tar --null -T - -cf -) | tar -C "$d" -xf -
  [ -z "${2:-}" ] || { mkdir -p "$d/$(dirname "$2")"; cat > "$d/$2"; }
  awk -v probe="$t/probe-steps.sh" '/^case \$\{1:-\} in$/ && !done { while ((getline l < probe) > 0) print l; done = 1 } { print }' \
    "$d/ci/run-stage.sh" > "$d/ci/run-stage.sh.new" && mv "$d/ci/run-stage.sh.new" "$d/ci/run-stage.sh" && chmod +x "$d/ci/run-stage.sh"
  git -C "$d" init -q && git -C "$d" add -A && { [ -z "${2:-}" ] || git -C "$d" add -f -- "$2"; } && git -C "$d" -c user.name=probe -c user.email=probe@example.invalid \
    -c commit.gpgsign=false commit -q -m "errexit probe" && git -C "$d" tag build-try-errexit-probe
}
cat > "$t/probe-steps.sh" <<'EOF'
# --- probe steps of tests/ci/run-stage-errexit.sh (only in the probe copy) ---
step_zz_seq() (
set -eo pipefail
false
echo "ZZ-AFTER"
)
step_zz_pipe() (
set -eo pipefail
false | tee /dev/null
echo "ZZ-AFTER"
)
step_agent() (
echo "probe agent rc=${ZZ_AGENT_RC:-0}"; exit "${ZZ_AGENT_RC:-0}"
)
EOF
run() { # run <repo> <out> <args...>: ci/run-stage.sh of the repo with its own CI_TMP; rc in $rc
  local d=$1 o=$2; shift 2
  rm -rf "$t/tmp"; mkdir -p "$t/tmp"
  (cd "$d" && env -u CI_GIT_AUTH -u CI_REF -u GITHUB_ACTIONS CI_TMP="$t/tmp" CI_SUMMARY="$t/tmp/summary.md" \
     CI_TAG_GLOB='build-try-*' CI_OWN=zz-errexit-owner/zz-errexit-repo STAGE=gate ci/run-stage.sh "$@") > "$o" 2>&1; rc=$?
  cat "$t/tmp/summary.md" >> "$o" 2>/dev/null
}
run_keep() { # run_keep: like run, CI_TMP kept between calls (agent -> result)
  local d=$1 o=$2; shift 2
  (cd "$d" && env -u CI_GIT_AUTH -u CI_REF CI_TMP="$t/keep" CI_SUMMARY="$t/keep/summary.md" STAGE=gate "$@") > "$o" 2>&1; rc=$?
}

C=$t/clean; mkrepo "$C"
# step-seq, step-pipe: the step body stops at its first failure
run "$C" "$t/z1" step zz_seq;  check step-seq nz "$rc" "$t/z1" "" "ZZ-AFTER"
run "$C" "$t/z2" step zz_pipe; check step-pipe nz "$rc" "$t/z2" "" "ZZ-AFTER"
# agent-result: agent -> result through CI_TMP
mkdir -p "$t/keep"
run_keep "$C" "$t/z3a" env ZZ_AGENT_RC=0 ci/run-stage.sh step agent
run_keep "$C" "$t/z3b" ci/run-stage.sh step result; check agent-result-ok 0 "$rc" "$t/z3b" "agent step: success"
run_keep "$C" "$t/z3c" env ZZ_AGENT_RC=3 ci/run-stage.sh step agent
run_keep "$C" "$t/z3d" ci/run-stage.sh step result; check agent-result-fail nz "$rc" "$t/z3d" "AGENT FAIL"

# oss-gate: a plan reference in a committed file
printf '# Probe\n\nProduct identity (%s%s): a plan reference the publication rules refuse.\n' O 9 | mkrepo "$t/n1" docs/zz-probe-trace.md
run "$t/n1" "$t/n1.out" step oss; check oss-gate nz "$rc" "$t/n1.out" "OSS STEP FAIL: oss-gate.py"
run "$t/n1" "$t/n1s.out" gate;    check oss-gate-stage nz "$rc" "$t/n1s.out" "run-stage gate: oss failed"
# oss-clean: the clean tree
run "$C" "$t/p1" step oss; check oss-clean 0 "$rc" "$t/p1" "OSS-GATE PASS"
# gitleaks: a synthetic test key (generated now, EC P-256, never a real key)
mkdir -p "$t/key"; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$t/key/k.pem" 2>/dev/null
mkrepo "$t/n2" zz-errexit-probe-synthetic.txt < "$t/key/k.pem"   # .txt and add -f: *.pem is ignored by .gitignore
run "$t/n2" "$t/n2.out" step oss; check gitleaks nz "$rc" "$t/n2.out" "OSS STEP FAIL: gitleaks-gate.sh"
# unshallow: a shallow repository that cannot fetch its history
git clone -q --depth 1 "file://$C" "$t/n3" && git -C "$t/n3" remote set-url origin "$t/nowhere.git"
run "$t/n3" "$t/n3.out" step oss; check unshallow nz "$rc" "$t/n3.out" "OSS STEP FAIL: git fetch --unshallow"

# stubs: sudo (apt-get fails with 100; anything else runs as the caller), curl (no host answers)
mkdir -p "$t/stub"
printf '#!/bin/sh\n[ "$1" = apt-get ] && { echo "probe: apt-get refused" >&2; exit 100; }\nexec "$@"\n' > "$t/stub/sudo"
printf '#!/bin/sh\nexit 7\n' > "$t/stub/curl"
# fake tools containers: lossy keeps nothing (a write lost), good keeps the lines in its own hosts file
printf '#!/bin/bash\nif [ "$1" = grep ]; then shift; a=("${@/\\/etc\\/hosts/%s}"); exec grep "${a[@]}"; fi\nexit 0\n' "$t/ctr_empty" > "$t/stub/ctr-lossy"
printf '#!/bin/bash\nif [ "$1" = grep ]; then shift; a=("${@/\\/etc\\/hosts/%s}"); exec grep "${a[@]}"; fi\n[ "$1" = sh ] && [ "$2" = -c ] && exec sh -c "${3//\\/etc\\/hosts/%s}"\nexit 1\n' "$t/ctr_hosts" "$t/ctr_hosts" > "$t/stub/ctr-good"
chmod +x "$t/stub/"*; : > "$t/ctr_empty"; : > "$t/ctr_hosts"
# apt-get: apt-get of the host step
PATH="$t/stub:$PATH" run "$C" "$t/n4" step host; check apt-get nz "$rc" "$t/n4" "HOST FAIL: apt-get update rc=100"
# hosts, hosts-ok: NVIDIA offline (the host's hosts file is a file of the probe, never /etc/hosts)
: > "$t/hosts5"; PATH="$t/stub:$PATH" run "$C" "$t/n5" __fn nvidia_offline "$t/hosts5" "$t/stub/ctr-lossy"
check hosts nz "$rc" "$t/n5" "NVIDIA OFFLINE FAIL: /etc/hosts of the tools container"
: > "$t/hosts5"; PATH="$t/stub:$PATH" run "$C" "$t/p5" __fn nvidia_offline "$t/hosts5" "$t/stub/ctr-good"
check hosts-ok 0 "$rc" "$t/p5"
# provenance, provenance-ok: provenance
echo '{' > "$t/bad.json"; echo '{"components": []}' > "$t/u.json"; echo '{"sets": []}' > "$t/a.json"
run "$C" "$t/n6" __fn provenance_summary "$t/bad.json" "$t/u.json"; check provenance nz "$rc" "$t/n6" "PROVENANCE FAIL"
run "$C" "$t/p6" __fn provenance_summary "$t/a.json" "$t/u.json";   check provenance-ok 0 "$rc" "$t/p6" "provenance (apt-pin-inputs.json"

echo "ERREXIT PROBE $([ $pass = $total ] && echo PASS || echo FAIL) $pass/$total"
[ $pass = $total ]
