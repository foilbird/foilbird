#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The CI of the node image as one script: every CI (GitHub Actions .github/workflows/build.yml, GitLab .gitlab-ci.yml)
# only calls it, so the build, its gates and its summary are the same wherever it runs (docs/reproducible-build.md,
# docs/ci-gitlab.md).
#
#   ci/run-stage.sh step <name>     one step (a CI that shows steps separately: build.yml)
#   ci/run-stage.sh <stage>         every step of a stage in order, stopping at the first failure (a CI with one job per
#                                   stage: .gitlab-ci.yml)
#
# Stages (what each does: the header of .github/workflows/build.yml):
#   selfcheck  preflight tag oss errexit agent host snapshot keyfacts initrd
#   gate       preflight tag oss errexit                            (the publication rules and the errexit invariant only)
#   lock       preflight tag oss keyfacts lock                      (fails on purpose: the locks are reviewed and committed)
#   cp | gpu   preflight tag oss agent disk host snapshot keyfacts image  (image only after a passing agent step)
#   harness    preflight tag oss agent disk host snapshot keyfacts image harness_rel harness_test  (the harness gate:
#              make test STRICT=1 against releases 1-4 built in the job; tag harness-try-*)
#   offline    as cp or gpu (NL_OFFLINE_VARIANT, cp by default; NL_PKGCACHE: mkosi's package cache), then offline_bundle
#              offline_probes offline_clean offline_net offline_build offline_compare (ci/offline.sh), all of that variant
# Steps: preflight tag oss errexit agent disk host snapshot keyfacts initrd lock image harness_rel harness_test offline_* result
# Every step runs in a process of its own (`bash ci/run-stage.sh __step <name>`, started by run_step): a step body called
# from `"step_x" || rc=$?` (or under if/&&/!) runs with errexit ignored - its own `set -e` would do nothing (bash(1)) - so
# a step never runs inside such a context; what a step decides on is still read explicitly (rc, PIPESTATUS, exit).
# The child gets the state through the environment only: CI_TMP, CI_SUMMARY, STAGE, CI_TAG_GLOB, CI_REF, CI_GIT_AUTH,
# CI_OWN, CI_LOG_GROUPS, MKOSI_*, DEBIAN_IMAGE, PATH, NL_PKGCACHE and NL_OFFLINE_VARIANT (offline stage) (exported); files under CI_TMP
# (agent.outcome, dist, cache) are shared.
#
# Environment (the CI maps its own variables onto these; nothing CI-specific below):
#   CI_TMP        work directory outside the tree (required): agent dist, cache, logs, mkosi, output
#   CI_SUMMARY    file the summary lines are appended to (default: $CI_TMP/summary.md)
#   STAGE         gate | selfcheck | lock | cp | gpu | harness | offline (the agent, image and harness steps read it;
#                 offline builds its online image as NL_OFFLINE_VARIANT: cp or gpu, cp when unset)
#   CI_TAG_GLOB   the tag the commit must carry, the build is "by tag" (default build-try-*; harness: harness-try-*)
#   CI_REF        the branch being built: a ci/harness-try-* branch is always STAGE=harness (the stage of the harness gate
#                 comes from the branch, so the commit built is the commit merged)
#   CI_GIT_AUTH   optional git -c http.extraHeader value for fetching the history (oss step: old-hashes rule); without
#                 it the remote's own credentials are used
#   CI_OWN        owner/repository of the remote, for the own-names rule (default: from the origin URL)
#   CI_LOG_GROUPS github: fold the whole build log in the job log (::group::); anything else: plain separators
#   MKOSI_TAG, MKOSI_COMMIT, DEBIAN_IMAGE   pinned below; set only to test another pin
# Exit codes: 75 Debian snapshot unavailable (the run did not take place - not a reproducibility or signature failure),
# other non-zero = failure. mkosi runs as root through sudo with an explicit environment (never sudo -E); every other
# step runs as the caller.
set -uo pipefail
TOP=$(cd "$(dirname "$0")/.." && pwd)
SELF=$TOP/ci/$(basename "$0")
T=${CI_TMP:?CI_TMP: a work directory outside the tree}
mkdir -p "$T"
SUM=${CI_SUMMARY:-$T/summary.md}
CI_SUMMARY=$SUM; export CI_TMP CI_SUMMARY
# NL_SHARED_HOST=1: a build host that outlives the job and serves others (a GitLab runner, as root): the job changes
# nothing of the host outside CI_TMP. HOME is in CI_TMP (cargo, rustup); the TEST keys are in CI_TMP, not on the tmpfs path
# every job shares; the disk step removes no toolchain and prunes no docker image; no apt-get (the host packages are
# installed beforehand, a missing one fails its step by name); the offline stage puts the agent's shared tools set aside
# and puts it back on the way out; the host's hosts file is saved when a stage starts and put back on the way out
# (ci/hosts-guard.sh: the gpu image step writes 0.0.0.0 lines of the NVIDIA hosts into it). Unset (GitHub Actions, a
# fresh runner per job): none of this, as before.
CI_TEST_KEYS=/dev/shm/ci-test-keys
if [ "${NL_SHARED_HOST:-0}" = 1 ]; then HOME=$T/home; mkdir -p "$HOME"; CI_TEST_KEYS=$T/test-keys; fi
export HOME CI_TEST_KEYS
# docker on a host several jobs share (GitLab: NL_DOCKER_TAG = the job id): the job's containers and image carry it in
# their names, are removed when the stage starts and on its way out; NL_DOCKER_CPUS caps each container (docker's own
# cgroup is outside the runner's CPU quota). Both empty (GitHub Actions): the names and runs before, no cap
case ${NL_DOCKER_TAG:-} in *[!A-Za-z0-9_.-]*) echo "run-stage.sh: NL_DOCKER_TAG [$NL_DOCKER_TAG]: only A-Za-z0-9_.-" >&2; exit 2 ;; esac
case ${NL_DOCKER_CPUS:-} in *[!0-9.]*) echo "run-stage.sh: NL_DOCKER_CPUS [$NL_DOCKER_CPUS]: a number" >&2; exit 2 ;; esac
DK_TOOLS=o2tools${NL_DOCKER_TAG:+-$NL_DOCKER_TAG}; DK_OFF=$DK_TOOLS-off; DK_IMG=nl-o2tools-offline${NL_DOCKER_TAG:+-$NL_DOCKER_TAG}
# the agent's container (step agent), its packages kept as an image for the offline stage, and that image's runs there
DK_AGENT=$DK_TOOLS-agent; DK_AOFF=$DK_TOOLS-agent-off; DK_AFETCH=$DK_TOOLS-agent-fetch; DK_AIMG=nl-agent-tools${NL_DOCKER_TAG:+-$NL_DOCKER_TAG}
# the label of $DK_AIMG: the disk step's image prune (a fresh runner, after the agent step) keeps the images with it
DK_KEEP=org.foilbird.ci.keep=agent-tools
export DK_TOOLS DK_OFF DK_IMG DK_AGENT DK_AOFF DK_AFETCH DK_AIMG
DCPU=(); [ -z "${NL_DOCKER_CPUS:-}" ] || DCPU=(--cpus "$NL_DOCKER_CPUS")
dk_clean() { [ -n "${NL_DOCKER_TAG:-}" ] || return 0
  docker rm -f "$DK_TOOLS" "$DK_OFF" "$DK_AGENT" "$DK_AOFF" "$DK_AFETCH" >/dev/null 2>&1 || true
  docker image rm -f "$DK_IMG" "$DK_AIMG" >/dev/null 2>&1 || true; }
# shared host: the host's hosts file (the gpu image step writes 0.0.0.0 lines of the NVIDIA hosts into it) is saved when
# a stage starts and put back last in every EXIT trap of run_stage (ci/hosts-guard.sh); the CI's after_script puts it
# back again (a cancelled job may never reach the trap). NL_HOSTS_COPY: where the copy lives (GitLab: beside CI_TMP, so
# after_script still finds it once CI_TMP is gone; default $CI_TMP/hosts.orig). Not a shared host: nothing saved
HG_COPY=
hosts_back() { [ -n "$HG_COPY" ] || return 0; "$TOP/ci/hosts-guard.sh" restore /etc/hosts "$HG_COPY" || exit 1; }
# shared host: the packages a step needs must be there (nothing installed); prints the missing ones, rc 1
host_has() { local p s m=; for p in "$@"; do s=$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null) || s=; [ "$s" = "install ok installed" ] || m="$m $p"; done
  [ -z "$m" ] || { echo "shared host: packages missing (install them once as root):$m"; return 1; }; }
MKOSI_TAG=${MKOSI_TAG:-v26}
MKOSI_COMMIT=${MKOSI_COMMIT:-84af20892b61c8e177e391f997ded8b4cb5514f2}
# Debian 13 for the tools that need Debian's own versions (sqv of apt-pin.py); the same pinned digest as test.yml
DEBIAN_IMAGE=${DEBIAN_IMAGE:-debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6}
STAGE=${STAGE:-}
case ${CI_REF:-} in
  ci/harness-try-*) STAGE=harness; CI_TAG_GLOB=${CI_TAG_GLOB:-harness-try-*}; export CI_TAG_GLOB ;;
  # the CI branch names before build-try / harness-try / offline-try: refused, never read as a stage
  ci/o[0-9]*-*) echo "run-stage.sh: CI branch $CI_REF has an old name (ci/build-try-*, ci/harness-try-*, ci/offline-try-*)" >&2; exit 2 ;;
esac
# the stage name before harness: refused, never run as a stage of its own
[ "$STAGE" = o3 ] || [ "${1:-}" = o3 ] && { echo "run-stage.sh: stage o3 has an old name (harness)" >&2; exit 2; }
export MKOSI_TAG MKOSI_COMMIT DEBIAN_IMAGE STAGE
# mkosi of the host step, for every later step (the build entries run it under sudo env PATH="$PATH")
[ -d "$T/mkosi/bin" ] && PATH=$T/mkosi/bin:$PATH
group_start() { if [ "${CI_LOG_GROUPS:-}" = github ]; then echo "::group::$*"; else echo "----- $*"; fi; }
group_end() { if [ "${CI_LOG_GROUPS:-}" = github ]; then echo "::endgroup::"; else echo "----- end"; fi; }
# pipe_rc [-a] <file> <command...>: <command> | tee [-a] <file>; the return code is the command's (else tee's), read here
# from PIPESTATUS - never left to errexit/pipefail
pipe_rc() {
  local a=() f s
  [ "$1" = -a ] && { a=(-a); shift; }
  f=$1; shift
  "$@" | tee "${a[@]}" "$f" && return 0
  s=("${PIPESTATUS[@]}"); [ "${s[0]}" != 0 ] && return "${s[0]}"; return "${s[1]:-1}"
}

# nvidia_offline <hosts file> <tools exec...>: both NVIDIA hosts to 0.0.0.0 in the host's hosts file (through sudo) and in
# /etc/hosts of the tools container, each write read back; then neither host may answer on the host. Every failure is a
# NVIDIA OFFLINE FAIL line and rc 1 (image, STAGE=gpu)
nvidia_offline() {
  local hf=$1 h; shift
  for h in developer.download.nvidia.com nvidia.github.io; do
    echo "0.0.0.0 $h" | sudo tee -a "$hf" >/dev/null
    grep -qx "0.0.0.0 $h" "$hf" || { echo "NVIDIA OFFLINE FAIL: $hf of the host has no line 0.0.0.0 $h" | tee -a "$SUM"; return 1; }
    "$@" sh -c "echo '0.0.0.0 $h' >> /etc/hosts"
    "$@" grep -qx "0.0.0.0 $h" /etc/hosts || { echo "NVIDIA OFFLINE FAIL: /etc/hosts of the tools container has no line 0.0.0.0 $h" | tee -a "$SUM"; return 1; }
    if curl -s -o /dev/null -m 15 "https://$h/"; then echo "NVIDIA OFFLINE FAIL: $h still reachable" | tee -a "$SUM"; return 1; fi
  done
}

# provenance_summary <apt-pin-inputs.json> <upstream.json>: provenance of the third-party inputs into the summary; a
# failure to read them is a PROVENANCE FAIL line and rc 1 (image)
provenance_summary() {
  local r=0
  pipe_rc -a "$SUM" python3 -I - "$1" "$2" <<'PY' || r=$?
import json, sys
a = json.load(open(sys.argv[1]))
print("provenance (apt-pin-inputs.json; source only: %s):" % (", ".join(a.get("source_only", [])) or "none"))
for p in a["sets"]:
    roles = {}
    for e in p["files"]:
        roles[e["role"]] = roles.get(e["role"], 0) + 1
    ix = p["index"]
    print("- [%s] %s key %s, InRelease sha256 %s (Date %s, Valid-Until %s), %s %s %s, files %s; lock %s sha256 %s; chain %s" % (
          p["set"], p.get("repository", ""), p["key"]["fingerprint"], p["inrelease"]["sha256"], p["inrelease"]["date"],
          p["inrelease"].get("valid_until") or "none", ix["name"], ix.get("sha256", ix.get("sha512", "")), ix.get("size", ""),
          ", ".join("%s %d" % kv for kv in sorted(roles.items())), p.get("lock"), p.get("lock_sha256"), p.get("chain_check", "missing")))
    for e in p["files"]:
        print("  - %s %s=%s sha256 %s size %d" % (e["role"], e["package"], e["version"], e["sha256"], e["size"]))
u = json.load(open(sys.argv[2]))
for c in u["components"]:
    if not c.get("origin"):
        print("- [release] %s %s sha256 %s %s" % (c["name"], c["version"], c["sha256"][:16], c.get("url", "")))
PY
  [ $r = 0 ] || { echo "PROVENANCE FAIL: rc=$r reading $1 $2" | tee -a "$SUM"; return 1; }
}

# the build is "by tag": the commit must carry a CI_TAG_GLOB tag
step_tag() (
set -eo pipefail
cd "$TOP"
glob=${CI_TAG_GLOB:-build-try-*}
tag=$(git describe --exact-match --tags --match "$glob" HEAD 2>/dev/null) || {
  echo "BUILD BY TAG: $(git rev-parse HEAD) has no $glob tag" | tee -a "$SUM"; exit 1; }
echo "build by tag $tag = $(git rev-parse HEAD) ($(git log -1 --format=%s))" | tee -a "$SUM"
)

# publication rules without a word list (tests/compliance/oss-gate.py), before any build: the history without trees
# (commit ids only) for the old-hashes rule; then the secrets scan of the tree (tests/compliance/gitleaks-gate.sh)
step_oss() (
set -eo pipefail
cd "$TOP"
a=(); [ -n "${CI_GIT_AUTH:-}" ] && a=(-c "http.extraHeader=$CI_GIT_AUTH")
if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
  r=0; git "${a[@]}" fetch -q --unshallow --filter=tree:0 origin '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*' || r=$?
  [ $r = 0 ] || { echo "OSS STEP FAIL: git fetch --unshallow rc=$r (the old-hashes rule needs the whole history)" | tee -a "$SUM"; exit 1; }
fi
own=${CI_OWN:-$(git remote get-url origin | sed -E 's#^.*github\.com[:/]##; s#^https?://[^/]+/##; s#\.git$##')}
r=0; pipe_rc "$T/oss-gate.txt" python3 -I tests/compliance/oss-gate.py --selftest --history --own "$own" || r=$?
{ echo '```'; cat "$T/oss-gate.txt"; echo '```'; } >> "$SUM"
[ $r = 0 ] || { echo "OSS STEP FAIL: oss-gate.py rc=$r" | tee -a "$SUM"; exit 1; }
r=0; pipe_rc "$T/gitleaks-gate.txt" sh tests/compliance/gitleaks-gate.sh || r=$?
{ echo '```'; cat "$T/gitleaks-gate.txt"; echo '```'; } >> "$SUM"
[ $r = 0 ] || { echo "OSS STEP FAIL: gitleaks-gate.sh rc=$r" | tee -a "$SUM"; exit 1; }
)

# the errexit invariant of this script (tests/ci/run-stage-errexit.sh, no build, seconds to a few minutes): a step body
# fails on its first failing command whatever the caller, and every checked pipe of oss, host and image fails its step
step_errexit() (
set -eo pipefail
cd "$TOP"
r=0; pipe_rc "$T/errexit.txt" bash tests/ci/run-stage-errexit.sh || r=$?
{ echo '```'; cat "$T/errexit.txt"; echo '```'; } >> "$SUM"
[ $r = 0 ] || { echo "ERREXIT STEP FAIL: tests/ci/run-stage-errexit.sh rc=$r" | tee -a "$SUM"; exit 1; }
)

# host facts: kernel, user namespaces (never fails)
step_preflight() (
set -eo pipefail
set -u
r=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)
c=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo n/a)
m=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo n/a)
if out=$(unshare --user --map-root-user true 2>&1); then u="ok"; else u="FAIL: $out"; fi
echo "PREFLIGHT kernel $(uname -r); apparmor_restrict_unprivileged_userns=$r unprivileged_userns_clone=$c max_user_namespaces=$m; unshare --user --map-root-user (as $(id -un)): $u" | tee -a "$SUM"
echo "mkosi as root; user namespaces not needed, not relaxed" | tee -a "$SUM"
echo "pins (ci/run-stage.sh): mkosi $MKOSI_TAG $MKOSI_COMMIT; tools image $DEBIAN_IMAGE" | tee -a "$SUM"
echo "locale of the job: LANG=${LANG:-unset} LC_ALL=${LC_ALL:-unset} LC_COLLATE=${LC_COLLATE:-unset} (sorting in this script: LC_ALL=C)" | tee -a "$SUM"
)

# the agent on the pinned toolchain: install-tools, cargo test x3, build-release -> $T/dist. The whole agent build runs
# in a container of the pinned Debian image (DEBIAN_IMAGE) with the C toolchain of agent/c-toolchain.pins from the
# build's own Debian snapshot (ring's C through musl-gcc, the link through cc/ld: a host's own gcc gave other bytes),
# checked after the install and in the binary (ci/agent-toolchain.sh). Mounted at their own paths: the tree, CI_TMP and
# the tools base /opt/foilbird-build-tools (the wrapper's absolute path is in the crates' hashes). It runs as the caller;
# HOME, rustup and cargo are in CI_TMP ($T/agent-home); SOURCE_DATE_EPOCH = the commit time, given (no git inside);
# CARGO_BUILD_JOBS and RUST_TEST_THREADS go in when set (docker's cgroup is outside a runner's quota). The offline stage
# keeps the container's packages as a local image ($DK_AIMG) for the agent built offline (ci/offline.sh).
# gpg + gpg-agent: agent/tools/offline-inputs.sh (gpgcheck: --show-keys, --import, --verify) runs in this image for the
# offline stage's fetch and install; --import starts gpg-agent, and gpg only Recommends gnupg (-> gpg-agent), which
# --no-install-recommends leaves out (G8 alpha3 job 18: import rc=2, "failed to start gpg-agent"). No dirmngr (no
# keyserver or network call of gpg) and no pinentry (no secret key, no passphrase) are needed.
step_agent() (
set -eo pipefail
set +e -uo pipefail   # no errexit here: the failures that decide this step are read explicitly below (rc, fail, exit)
cd "$TOP/agent"
fail=0; line="agent:"
# the agent's build tools: one absolute path on every build machine (docs/reproducible-build.md), named by
# build-release.sh itself; made through sudo here, or once by root on a runner without sudo: then it must exist and be writable
tb=$(dirname "$(./build-release.sh --print-tools-root)")
if [ -d "$tb" ] && [ -w "$tb" ]; then :
elif ! sudo -n install -d -o "$(id -u)" -g "$(id -g)" "$tb" 2>/dev/null; then
  echo "AGENT FAIL agent: $tb missing or not writable, and no sudo -n to make it (create it once as root)" | tee -a "$SUM"; exit 1
fi
ts=$(sh "$TOP"/images/debian/tools/snapshot check) || { echo "AGENT FAIL agent: images/debian/tools/snapshot check" | tee -a "$SUM"; exit 1; }
cc=$("$TOP"/ci/agent-toolchain.sh apt-args) || { echo "AGENT FAIL agent: agent/c-toolchain.pins" | tee -a "$SUM"; exit 1; }
AH=$T/agent-home; mkdir -p "$AH"
docker rm -f "$DK_AGENT" >/dev/null 2>&1; trap 'docker rm -f "$DK_AGENT" >/dev/null 2>&1' EXIT
docker run -d "${DCPU[@]}" --name "$DK_AGENT" -v "$TOP:$TOP" -v "$T:$T" -v "$tb:$tb" -w "$TOP/agent" "$DEBIAN_IMAGE" sleep infinity >/dev/null ||
  { echo "AGENT FAIL agent: docker run $DEBIAN_IMAGE" | tee -a "$SUM"; exit 1; }
srcs="Types: deb\nURIs: http://snapshot.debian.org/archive/debian/$ts\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/$ts\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
ok=0
for d in 0 30 90; do
  sleep $d
  docker exec "$DK_AGENT" sh -c "rm -f /etc/apt/sources.list.d/*; printf '$srcs' > /etc/apt/sources.list.d/snapshot.sources
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update -q &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $cc rustup ca-certificates curl gpg gpg-agent xz-utils python3" > "$T/agent-apt.log" 2>&1 && { ok=1; break; }
  tail -n 5 "$T/agent-apt.log"
done
if [ $ok = 0 ]; then
  if grep -q -E '^(Err:[0-9]+ https?://snapshot\.debian\.org|[EW]: Failed to fetch https?://snapshot\.debian\.org|[EW]: .*snapshot\.debian\.org.*(Could not connect|Connection timed out|Could not resolve))' "$T/agent-apt.log"; then
    echo "AGENT FAIL agent: SNAPSHOT UNAVAILABLE while installing the C toolchain (run did not take place)" | tee -a "$SUM"; exit 75; fi
  echo "AGENT FAIL agent: apt-get in the agent container (snapshot $ts): $(tail -n 1 "$T/agent-apt.log")" | tee -a "$SUM"; exit 1
fi
echo "agent container: $DEBIAN_IMAGE, snapshot $ts, $(docker exec "$DK_AGENT" rustup --version 2>/dev/null | sed -n 1p)" | tee -a "$SUM"
"$TOP"/ci/agent-toolchain.sh check docker exec "$DK_AGENT" | tee -a "$SUM"
[ "${PIPESTATUS[0]}" = 0 ] || { echo "AGENT FAIL agent: the C toolchain in the container is not agent/c-toolchain.pins" | tee -a "$SUM"; exit 1; }
if [ -n "${NL_OFFLINE_VARIANT:-}" ]; then   # the offline stage: the same packages for the offline build, no network then
  docker commit --change "LABEL $DK_KEEP" "$DK_AGENT" "$DK_AIMG" >/dev/null ||
    { echo "AGENT FAIL agent: docker commit $DK_AGENT $DK_AIMG" | tee -a "$SUM"; exit 1; }
fi
A=(docker exec -u "$(id -u):$(id -g)" -w "$TOP/agent" -e HOME="$AH" -e RUSTUP_HOME="$AH/rustup" -e CARGO_HOME="$AH/cargo"
   -e SOURCE_DATE_EPOCH="$(git -C "$TOP" log -1 --format=%ct)")
[ -z "${CARGO_BUILD_JOBS:-}" ] || A+=(-e "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS")
[ -z "${RUST_TEST_THREADS:-}" ] || A+=(-e "RUST_TEST_THREADS=$RUST_TEST_THREADS")
A+=("$DK_AGENT")
"${A[@]}" sh -c 'rustup show active-toolchain || rustup toolchain install' > "$T/agent-rustup.log" 2>&1 ||
  { tail -n 20 "$T/agent-rustup.log"; echo "AGENT FAIL agent: rustup toolchain install in the container" | tee -a "$SUM"; exit 1; }   # rust-toolchain.toml: 1.100.0 + musl target
line="$line rustc $("${A[@]}" rustc --version | cut -d' ' -f2-)"
[ $fail = 1 ] || "${A[@]}" ./build-release.sh --install-tools > "$T/agent-tools.log" 2>&1 || { fail=1; tail -n 30 "$T/agent-tools.log"; }
line="$line; install-tools rc=$fail"
tests='"" esp-bridge-tls lab-crash-points'; [ "${STAGE:-}" = harness ] && tests=   # harness: the dist only, its tests run in the build stages
eval "set -- $tests"
for f in "$@"; do
  "${A[@]}" cargo test --release --locked --no-fail-fast ${f:+--features $f} > "$T/test_${f:-product}.log" 2>&1; rc=$?
  p=$(grep -ho '[0-9]* passed' "$T/test_${f:-product}.log" | awk '{s+=$1} END{print s+0}')
  q=$(grep -ho '[0-9]* failed' "$T/test_${f:-product}.log" | awk '{s+=$1} END{print s+0}')
  line="$line; test ${f:-product} rc=$rc passed=$p failed=$q"
  [ $rc = 0 ] || { fail=1; grep -E '^test .* FAILED|panicked|error(\[|:)' "$T/test_${f:-product}.log" | head -n 20; }
done
"${A[@]}" env OUT="$T/dist" ./build-release.sh > "$T/agent-release.log" 2>&1; rc=$?
[ $rc = 0 ] || { fail=1; tail -n 30 "$T/agent-release.log"; }
line="$line; build-release rc=$rc"
# the toolchain actually installed, with the dist: build-all.sh records it in the build manifest (input param lines)
if [ $rc = 0 ]; then "$TOP"/ci/agent-toolchain.sh record "$T/dist/C-TOOLCHAIN" docker exec "$DK_AGENT" || fail=1; fi
[ -f "$T/dist/SHA256SUMS" ] && line="$line; $(tr '\n' ' ' < "$T/dist/SHA256SUMS")$(cat "$T/dist/FEATURES")"
if [ -f "$T/dist/foil-agent" ]; then
  "$TOP"/ci/agent-toolchain.sh comment "$T/dist/foil-agent" docker exec "$DK_AGENT" | tee -a "$SUM"
  [ "${PIPESTATUS[0]}" = 0 ] || fail=1
fi
echo "AGENT $([ $fail = 0 ] && echo PASS || echo FAIL) $line" | tee -a "$SUM"
exit $fail
)

# free the runner disk (SDKs the job never uses)
step_disk() (
set -eo pipefail
set -uo pipefail
# about 11G free before the build, 7G after the slot initrd and recovery (two tools trees of 1.5G);
# the image adds a third tools tree and the build overlay. Removed: toolchains this job never uses (none of them is
# a build input), docker images other than the tools image are pulled later. The offline stage's agent image ($DK_AIMG,
# made by the agent step before this one) carries the label $DK_KEEP and is kept: the bundle and the offline agent build
# run in it (ci/offline.sh); without the filter the prune removed it (try-12: "no agent container image nl-agent-tools")
before=$(df -h / | awk 'NR==2{print $4}')
if [ "${NL_SHARED_HOST:-0}" = 1 ]; then echo "runner disk: shared host, nothing removed; free on / $before" | tee -a "$SUM"; exit 0; fi
sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup /opt/hostedtoolcache/CodeQL \
  /usr/local/share/boost /usr/share/swift /usr/local/julia* /opt/az /usr/local/share/powershell /opt/microsoft
docker image prune -a -f --filter "label!=$DK_KEEP" >/dev/null 2>&1 || true
if [ -n "${NL_OFFLINE_VARIANT:-}" ] && ! docker image inspect "$DK_AIMG" >/dev/null 2>&1; then
  echo "DISK FAIL: the offline stage's agent image $DK_AIMG is gone after the prune" | tee -a "$SUM"; exit 1; fi
kept=; [ -z "${NL_OFFLINE_VARIANT:-}" ] || kept=", kept $DK_AIMG"
echo "runner disk: free on / $before -> $(df -h / | awk 'NR==2{print $4}')$kept" | tee -a "$SUM"
)

# host packages and mkosi at its pinned commit -> $T/mkosi
step_host() (
set -eo pipefail
set -euo pipefail
# erofs-utils: fsck.erofs for lab-gate and build-manifest.py (they read the /usr image after the build)
pk="uidmap debian-archive-keyring python3 git gnupg openssl erofs-utils"
if [ "${NL_SHARED_HOST:-0}" = 1 ]; then r=0; host_has $pk || r=$?; [ $r = 0 ] || { echo "HOST FAIL: shared host packages" | tee -a "$SUM"; exit 1; }
else
r=0; sudo apt-get update -q >/dev/null || r=$?
[ $r = 0 ] || { echo "HOST FAIL: apt-get update rc=$r" | tee -a "$SUM"; exit 1; }
r=0; sudo apt-get install -y -q --no-install-recommends $pk >/dev/null || r=$?
[ $r = 0 ] || { echo "HOST FAIL: apt-get install rc=$r" | tee -a "$SUM"; exit 1; }
fi
git clone -q --depth 1 --branch "$MKOSI_TAG" https://github.com/systemd/mkosi "$T/mkosi"
got=$(git -C "$T/mkosi" rev-parse HEAD)
[ "$got" = "$MKOSI_COMMIT" ] || { echo "mkosi $MKOSI_TAG is $got, pinned $MKOSI_COMMIT"; exit 1; }
echo "mkosi $("$T/mkosi/bin/mkosi" --version) at $got" | tee -a "$SUM"
)

# the Debian snapshot reachable (75 if not)
step_snapshot() (
set -eo pipefail
set -uo pipefail
ts=$(sh "$TOP"/images/debian/tools/snapshot check) || exit 1
ok=0
for d in 0 15 30 60 120; do
  sleep "$d"
  for u in "debian/$ts/dists/trixie/InRelease" "debian/$ts/dists/trixie-updates/InRelease" \
           "debian-security/$ts/dists/trixie-security/InRelease"; do
    code=$(curl -s -o /dev/null -L --max-time 60 -w '%{http_code} %{url_effective}' "https://snapshot.debian.org/archive/$u") || code="000"
    echo "$u -> $code"
    case $code in 200\ *) ;; *) continue 2 ;; esac
  done
  ok=1; break
done
if [ $ok = 0 ]; then
  echo "SNAPSHOT UNAVAILABLE: snapshot.debian.org $ts (run did not take place)" | tee -a "$SUM"; exit 75
fi
echo "Debian snapshot $ts reachable" | tee -a "$SUM"
curl -s -o /dev/null -w 'resolved trixie InRelease: %{url_effective}\n' -L --max-time 60 \
  "https://snapshot.debian.org/archive/debian/$ts/dists/trixie/InRelease" | tee -a "$SUM"
)

# facts about the third-party repository keys
step_keyfacts() (
set -eo pipefail
set -uo pipefail
k=$T/keys; mkdir -p "$k"; export GNUPGHOME=$k/gnupg; mkdir -m 700 "$GNUPGHOME"
fact() { # fact <name> <url>
  curl -fsSL --retry 3 --max-time 60 -o "$k/$1.asc" "$2" || { echo "$1: download failed ($2)"; return; }
  echo "== $1 $2 sha256 $(sha256sum < "$k/$1.asc" | cut -c1-64)"
  gpg --batch --show-keys --with-colons "$k/$1.asc" 2>/dev/null | awk -F: '$1=="pub"||$1=="sub"||$1=="fpr"||$1=="uid"{print "   " $1, $4, $5, $6, $10}'
  # every signature packet: issuer, class (0x10-0x13 certification of a uid, 0x18 subkey binding, 0x19 primary
  # key binding = back-signature inside a 0x18, 0x1f direct key), digest algo (2 = SHA1, 8 = SHA256,
  # 10 = SHA512); self = issued by the key itself or its subkey (what apt-pin.py's anchor check reads)
  own=$(gpg --batch --show-keys --with-colons "$k/$1.asc" 2>/dev/null | awk -F: '$1=="pub"||$1=="sub"{print $5}' | tr '\n' ' ')
  gpg --batch --list-packets "$k/$1.asc" 2>/dev/null | awk -v own="$own" '
    function name(d) { return d==2 ? "SHA1" : d==8 ? "SHA256" : d==9 ? "SHA384" : d==10 ? "SHA512" : d==11 ? "SHA224" : d==1 ? "MD5" : d==3 ? "RIPEMD160" : "algo" d }
    function out() { if (k != "") printf "   sig issuer %s %s class %s digest %s (%s)\n", k, (index(" " own " ", " " k " ") ? "self" : "FOREIGN"), c, d, name(d); k = "" }
    /^:signature packet:/ { out(); k = $0; sub(/.*keyid /, "", k); c = "?"; d = "?"; next }
    /^:/ { out(); next }
    k != "" && /sigclass/ { c = $0; sub(/.*sigclass /, "", c); sub(/[^0-9a-fx].*/, "", c) }
    k != "" && /^[ \t]+digest algo/ { d = $0; sub(/.*digest algo /, "", d); sub(/[^0-9].*/, "", d) }
    k != "" && /subpkt 32 .*signature:/ { b = $0; sub(/.*class /, "", b); e = b; sub(/,.*/, "", b); sub(/.*digest algo /, "", e); sub(/[^0-9].*/, "", e)
      printf "   embedded back-signature class %s digest %s (%s) in the binding of %s\n", b, e, name(e), k }
    END { out() }'
}
{ fact libnvidia-container https://nvidia.github.io/libnvidia-container/gpgkey
  fact pkgs-k8s-v1.34 'https://pkgs.k8s.io/core:/stable:/v1.34/deb/Release.key'; } | tee "$k/facts.txt"
{ echo '```'; cat "$k/facts.txt"; echo '```'; } >> "$SUM"
)

# selfcheck: the slot initrd from the snapshot with the Debian tools tree
step_initrd() (
set -eo pipefail
set +e -uo pipefail   # no errexit here: the failures that decide this step are read explicitly below (rc, fail, exit)
cd "$TOP/images/debian/foilbird-initrd"
# mkosi as root: only the build entry under sudo, environment listed explicitly
sudo env PATH="$PATH" SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" ./build.sh > "$T/initrd.log" 2>&1; rc=$?
tail -n 40 "$T/initrd.log"
L=$T/initrd.log
if [ $rc != 0 ] && grep -q -E '^(Err:[0-9]+ https://snapshot\.debian\.org|[EW]: Failed to fetch https://snapshot\.debian\.org|[EW]: .*snapshot\.debian\.org.*(Could not connect|Connection timed out|Could not resolve))' "$L"; then
  echo "SNAPSHOT UNAVAILABLE during the initrd build (run did not take place)" | tee -a "$SUM"; exit 75
fi
{
  echo "initrd build rc=$rc"
  echo "apt Get/Hit from snapshot.debian.org: $(grep -c -E '^(Get|Hit):[0-9]+ https://snapshot\.debian\.org' "$L")"
  echo "apt Get/Hit from any other host: $(grep -E '^(Get|Hit):[0-9]+ ' "$L" | grep -v -c 'https://snapshot\.debian\.org')"
  echo "trixie-updates source used: $(grep -c -E 'snapshot\.debian\.org/archive/debian/[0-9T]+Z trixie-updates' "$L")"
  echo "trixie-security source used: $(grep -c -E 'snapshot\.debian\.org/archive/debian-security/[0-9T]+Z trixie-security' "$L")"
  echo "tools tree: $(grep -m1 -i -E 'tools tree|mkosi.tools' "$L" || echo '(no line)')"
  [ -f out/initrd.cpio.zst ] && echo "initrd.cpio.zst sha256 $(sha256sum < out/initrd.cpio.zst | cut -c1-64) (SOURCE_DATE_EPOCH $(git log -1 --format=%ct))"
} | tee -a "$SUM"
exit $rc
)

# lock files from a first fetch (fails on purpose)
step_lock() (
set -eo pipefail
set +e -uo pipefail   # no errexit here: the failures that decide this step are read explicitly below (rc, fail, exit)
cd "$TOP"
L=$T/lock.log; : > "$L"
# apt-pin.py needs Debian 13's sqv (--cleartext; Ubuntu 24.04's sqv is too old): the tools
# run in Debian 13 (pinned image digest, as test.yml), with sqv, gpg, dpkg and python3 from the build's own
# Debian snapshot (reproducible.conf). Mounted: the tree (/src, the locks are written there), the cache, a work dir.
ts=$(sh images/debian/tools/snapshot check) || exit 1
mkdir -p "$T/apt-cache" "$T/work"
docker run -d "${DCPU[@]}" --name "$DK_TOOLS" -v "$PWD:/src" -v "$T/apt-cache:/cache" -v "$T/work:/work" -w /src \
  "$DEBIAN_IMAGE" sleep infinity >/dev/null || { echo "docker run $DEBIAN_IMAGE failed"; exit 1; }
X="docker exec -w /src $DK_TOOLS"; cache=/cache
srcs="Types: deb\nURIs: http://snapshot.debian.org/archive/debian/$ts\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/$ts\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
ok=0
for d in 0 30 90; do
  sleep $d
  $X sh -c "rm -f /etc/apt/sources.list.d/*; printf '$srcs' > /etc/apt/sources.list.d/snapshot.sources
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update -q &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends sqv gpg gpg-agent gpgv dpkg python3 ca-certificates" > "$T/tools.log" 2>&1 && { ok=1; break; }
  tail -n 5 "$T/tools.log"
done
if [ $ok = 0 ]; then
  if grep -q -E '^(Err:[0-9]+ https?://snapshot\.debian\.org|[EW]: Failed to fetch https?://snapshot\.debian\.org|[EW]: .*snapshot\.debian\.org.*(Could not connect|Connection timed out|Could not resolve))' "$T/tools.log"; then echo "SNAPSHOT UNAVAILABLE while installing the tools (run did not take place)" | tee -a "$SUM"; exit 75; fi
  echo "tools container: apt failed"; exit 1
fi
echo "tools: Debian 13 $DEBIAN_IMAGE, snapshot $ts; $($X sqv --version 2>&1 | head -n 1); $($X gpg --version | head -n 1); $($X python3 --version)" | tee -a "$SUM"
base="--conf images/debian/apt-pin.conf"; prof="--conf profiles/k8s-worker/apt-pin.conf"
fail=0
# fetch downloads everything, then verifies against the lock: with an empty lock the ONLY acceptable refusal
# is "not in the lock"; any other refusal (chain, key, SHA1 binding, network) is a finding and stops the stage
step() { # step <label> <command...>
  echo "== $1" | tee -a "$L"; shift
  "$@" >> "$L" 2>&1; rc=$?; tail -n 5 "$L"; return $rc; }
for c in "$base" "$prof"; do
  if ! step "apt-pin fetch $c" $X python3 images/debian/tools/apt-pin.py fetch $c --cache "$cache"; then
    tail -n 1 "$L" | grep -q 'REFUSED: .*lock .* refused: not in the lock' || { echo "FETCH REFUSED (not a lock refusal): $(tail -n 1 "$L")" | tee -a "$SUM"; fail=1; }
  fi
done
if ! step "fetch-upstream fetch" $X python3 profiles/k8s-worker/tools/fetch-upstream.py fetch --cache "$cache"; then
  tail -n 1 "$L" | grep -q 'REFUSED: .*lock .* refused: not in the lock' || { echo "UPSTREAM FETCH REFUSED (not a lock refusal): $(tail -n 1 "$L")" | tee -a "$SUM"; fail=1; }
fi
for c in "$base" "$prof"; do step "apt-pin lock $c" $X python3 images/debian/tools/apt-pin.py lock $c --cache "$cache" || fail=1; done
step "fetch-upstream lock" $X python3 profiles/k8s-worker/tools/fetch-upstream.py lock --cache "$cache" || fail=1
step "apt-pin verify (both set files, with the new locks)" $X python3 images/debian/tools/apt-pin.py verify $base $prof --cache "$cache" || fail=1
step "fetch-upstream prepare (offline check against the new lock)" $X python3 profiles/k8s-worker/tools/fetch-upstream.py prepare --cache "$cache" --out /work/upstream || fail=1
step "apt-pin-test (refusal probes, every set)" $X python3 images/debian/tools/apt-pin-test.py $base $prof --cache "$cache"; t=$?
[ $t = 0 ] || fail=1
# gate: the probes must have run. No "probes: N/M" line, M = 0 or N < M is a failure of the stage
pl=$(grep -E '^probes: [0-9]+/[0-9]+ ' "$L" | tail -n 1)
case $pl in
  "probes: "*) n=${pl#probes: }; m=${n#*/}; m=${m%% *}; n=${n%%/*}
     if [ "$m" -eq 0 ] || [ "$n" -ne "$m" ]; then echo "PROBES FAIL: $pl" | tee -a "$SUM"; fail=1; fi ;;
  *) echo "PROBES FAIL: no probe ran (no 'probes: N/M' line; apt-pin-test rc=$t)" | tee -a "$SUM"; fail=1 ;;
esac
{
  echo "probes: $(grep -E '^probes:' "$L" || echo none)"
  grep -E '^[a-z0-9-]+ (P0|N[0-9]).* FAIL ' "$L" | head -n 20
  echo '```'; for f in images/debian/apt-pin.lock profiles/k8s-worker/apt-pin.lock; do echo "### $f"; cat "$f"; done; echo '```'
  echo "lock sha256: $(sha256sum images/debian/apt-pin.lock profiles/k8s-worker/apt-pin.lock | cut -c1-64 | tr '\n' ' ')"
  for f in images/debian/apt-pin.lock profiles/k8s-worker/apt-pin.lock; do
    echo "lock lines $f: apt $(grep -c '^apt ' "$f"), release $(grep -c '^release ' "$f")"; done
} | tee -a "$SUM"
{ echo '<details><summary>lock stage log (tail)</summary>'; echo; echo '```'; tail -n 150 "$L"; echo '```'; echo '</details>'; } >> "$SUM"
if [ $fail = 0 ]; then echo "LOCK STAGE: locks written, verify and probes PASS; failing on purpose (review + commit the locks)" | tee -a "$SUM"
else echo "LOCK STAGE FAIL: see the lines above" | tee -a "$SUM"; fi
exit 1
)

# the image (cp|gpu) by build-all.sh from the committed locks, TEST keys; gates, manifest, summary
step_image() (
set -eo pipefail
set +e -uo pipefail   # no errexit here: the failures that decide this step are read explicitly below (rc, fail, exit)
cd "$TOP"
echo "NVIDIA components built inside the job, not published" | tee -a "$SUM"
rm -rf agent/target   # the dist is in $T/dist; disk for the build
ts=$(sh images/debian/tools/snapshot check) || exit 1
cache=$T/apt-cache; out=$T/out; L=$T/cp.log; : > "$L"
mkdir -p "$cache"
# tools that need Debian 13's sqv (apt-pin.py, fetch-upstream.py) run in Debian 13 (pinned digest, packages from
# the build's own snapshot), as in the lock stage; the tree and the cache are mounted at THE SAME paths, so
# build-all.sh passes host paths through TOOLS_EXEC unchanged
docker run -d "${DCPU[@]}" --name "$DK_TOOLS" -v "$PWD:$PWD" -v "$cache:$cache" -w "$PWD" "$DEBIAN_IMAGE" sleep infinity >/dev/null ||
  { echo "docker run $DEBIAN_IMAGE failed"; exit 1; }
X="docker exec -w $PWD $DK_TOOLS"
srcs="Types: deb\nURIs: http://snapshot.debian.org/archive/debian/$ts\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/$ts\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
ok=0
for d in 0 30 90; do
  sleep $d
  $X sh -c "rm -f /etc/apt/sources.list.d/*; printf '$srcs' > /etc/apt/sources.list.d/snapshot.sources
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update -q &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends sqv gpg gpg-agent gpgv dpkg python3 ca-certificates" > "$T/tools.log" 2>&1 && { ok=1; break; }
  tail -n 5 "$T/tools.log"
done
if [ $ok = 0 ]; then
  if grep -q -E '^(Err:[0-9]+ https?://snapshot\.debian\.org|[EW]: Failed to fetch https?://snapshot\.debian\.org|[EW]: .*snapshot\.debian\.org.*(Could not connect|Connection timed out|Could not resolve))' "$T/tools.log"; then echo "SNAPSHOT UNAVAILABLE while installing the tools (run did not take place)" | tee -a "$SUM"; exit 75; fi
  echo "tools container: apt failed"; exit 1
fi
echo "tools: Debian 13 $DEBIAN_IMAGE, snapshot $ts; $($X sqv --version 2>&1 | head -n 1); $($X python3 --version)" | tee -a "$SUM"
# the cache from the network, checked against the COMMITTED locks: any refusal stops the stage
base="--conf images/debian/apt-pin.conf"; prof="--conf profiles/k8s-worker/apt-pin.conf"
for c in "$base" "$prof"; do
  $X python3 images/debian/tools/apt-pin.py fetch $c --cache "$cache" >> "$L" 2>&1 ||
    { echo "FETCH REFUSED $c: $(tail -n 1 "$L")" | tee -a "$SUM"; exit 1; }
done
$X python3 profiles/k8s-worker/tools/fetch-upstream.py fetch --cache "$cache" >> "$L" 2>&1 ||
  { echo "UPSTREAM FETCH REFUSED: $(tail -n 1 "$L")" | tee -a "$SUM"; exit 1; }
echo "cache: apt-pin fetch + verify ok (both set files), fetch-upstream fetch ok, against the committed locks $(sha256sum images/debian/apt-pin.lock profiles/k8s-worker/apt-pin.lock | cut -c1-16 | tr '\n' ' ')" | tee -a "$SUM"
if [ "$STAGE" = gpu ]; then
  # offline NVIDIA: from here on neither NVIDIA host is reachable, on the host (mkosi) nor in
  # the tools container; everything below must come from the verified cache
  nvidia_offline /etc/hosts $X || exit 1
  echo "NVIDIA offline: developer.download.nvidia.com, nvidia.github.io -> 0.0.0.0 (host + tools container), unreachable" | tee -a "$SUM"
  for c in "$base" "$prof"; do
    $X python3 images/debian/tools/apt-pin.py fetch $c --cache "$cache" >> "$L" 2>&1 ||
      { echo "OFFLINE FETCH FAIL $c (the cache does not carry the set): $(tail -n 1 "$L")" | tee -a "$SUM"; exit 1; }
  done
  echo "offline: apt-pin fetch + verify of every set from the cache alone: ok" | tee -a "$SUM"
  # refusal probes against the cache, NVIDIA offline (the same gate as the lock stage)
  P=$T/probes.log
  $X python3 images/debian/tools/apt-pin-test.py $base $prof --cache "$cache" > "$P" 2>&1; t=$?
  pl=$(grep -E '^probes: [0-9]+/[0-9]+ ' "$P" | tail -n 1)
  pf=0
  case $pl in
    "probes: "*) n=${pl#probes: }; m=${n#*/}; m=${m%% *}; n=${n%%/*}; { [ "$m" -gt 0 ] && [ "$n" -eq "$m" ] && [ $t = 0 ]; } || pf=1 ;;
    *) pf=1 ;;
  esac
  echo "refusal probes (NVIDIA offline): ${pl:-no probes line} rc=$t $([ $pf = 0 ] && echo PASS || echo FAIL)" | tee -a "$SUM"
  { echo '<details><summary>probe lines</summary>'; echo; echo '```'; grep -E '^[a-z0-9-]+ (P0|N[0-9])' "$P"; echo '```'; echo '</details>'; } >> "$SUM"
  [ $pf = 0 ] || { tail -n 30 "$P"; echo "PROBES FAIL" | tee -a "$SUM"; exit 1; }
fi
# ephemeral TEST keys on tmpfs (a shared host: in CI_TMP), never leave the job
keys=$CI_TEST_KEYS
tests/lib/keys.sh gen "$keys" > "$T/keys.txt" && tests/lib/keys.sh check "$keys" || { echo "TEST keys: keys.sh failed"; exit 1; }
{ echo "TEST keys (ephemeral, tmpfs, this job only):"; echo '```'; cat "$T/keys.txt"; echo '```'; } >> "$SUM"
df -h / "$T" | tail -n +2
# the build: build-all.sh runs as the runner user; mkosi entries under sudo env (mkosi as root)
# harness: release 1 of the harness = variant cp with the harness epoch table (tests/README.md)
variant=$STAGE; hx=(); [ "$STAGE" = harness ] && { variant=cp; hx=(--release-epochs 1:1,2:4); }
TOOLS_EXEC="$X" SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" images/debian/tools/build-all.sh \
  --profile profiles/k8s-worker --variant "$variant" --version 1 --epoch 1 --min-version 1 "${hx[@]}" \
  --keys "$keys" --agent-dist "$T/dist" --cache "$cache" --output-dir "$out" > "$T/build.log" 2>&1; rc=$?
df -h / | tail -n +2
tail -n 60 "$T/build.log"
B=$T/build.log
M=$out/build-manifest.txt
# gate: apt may read only the Debian snapshot and the verified local copies (file:/srv/apt-pin). Any other source
# (such as a tools tree from the live http://deb.debian.org) fails the stage. Per build-all step.
awk '/^== build-all: /{st=$0; sub(/^== build-all: /, "", st); if (!(st in seen)) {seen[st]=1; order[++n]=st}}
     /^(Get|Hit):[0-9]+ [a-z]+:/{ if ($2 ~ /^https:\/\/snapshot\.debian\.org\//) sn[st]++; else if ($2 ~ /^file:/) fl[st]++; else lv[st]++ }
     END{for (i=1; i<=n; i++) {k=order[i]; if (sn[k]+fl[k]+lv[k] == 0) continue; printf "apt sources [%s]: snapshot %d, file %d, live %d\n", k, sn[k], fl[k], lv[k]; t+=lv[k]}; printf "LIVE %d\n", t}' "$B" > "$T/sources.txt"
live=$(sed -n 's/^LIVE //p' "$T/sources.txt")
{
  grep -v '^LIVE ' "$T/sources.txt"
  if [ "${live:-0}" != 0 ]; then
    echo "LIVE MIRROR FAIL: $live apt lines from a source other than the snapshot and file:/srv/apt-pin:"
    grep -E '^(Get|Hit):[0-9]+ [a-z]+:' "$B" | grep -v -E '^(Get|Hit):[0-9]+ (https://snapshot\.debian\.org/|file:)' | head -n 5 | sed 's/^/  live: /'
  else echo "live mirror: 0 apt lines outside the snapshot and file:/srv/apt-pin"; fi
} | tee -a "$SUM"
[ "${live:-0}" = 0 ] || [ $rc != 0 ] || rc=1
{
  echo "build-all.sh rc=$rc (profile k8s-worker, variant $STAGE, version 1, SOURCE_DATE_EPOCH $(git log -1 --format=%ct))"
  grep -E '^== build-all:|^build-all: |REFUSED|ERROR' "$B" | head -n 30
  echo "apt Get/Hit from snapshot.debian.org: $(grep -c -E '^(Get|Hit):[0-9]+ https://snapshot\.debian\.org' "$B")"
  echo "apt Get/Hit from any other host: $(grep -E '^(Get|Hit):[0-9]+ (https?|ftp)://' "$B" | grep -v -c 'https://snapshot\.debian\.org')"
  # by source (scheme://host/first path part): what "other" is, by name
  echo "apt Get/Hit by source: $(grep -o -E '^(Get|Hit):[0-9]+ [a-z]+:/*[^/ ]*/[^/ ]*' "$B" | cut -d' ' -f2 | LC_ALL=C sort | LC_ALL=C uniq -c | awk '{printf "%s %s; ", $2, $1}')"
  grep -E '^(Get|Hit):[0-9]+ (https?|ftp)://' "$B" | grep -v 'https://snapshot\.debian\.org' | head -n 5 | sed 's/^/  other: /'
  echo "trixie-updates source used: $(grep -c -E 'snapshot\.debian\.org/archive/debian/[0-9T]+Z trixie-updates' "$B")"
  # the aptpin sandbox tree is what apt reads (file:/srv/apt-pin/<set>/)
  echo "apt-pin sandbox source used (file:/srv/apt-pin): $(grep -c 'file:/srv/apt-pin' "$B"), sets: $(grep -o 'file:/srv/apt-pin/[a-z0-9-]*' "$B" | LC_ALL=C sort -u | tr '\n' ' ')"
  [ -f "$out/build-params.txt" ] && { echo '```'; cat "$out/build-params.txt"; echo '```'; }
  [ -f "$out/lab-gate.txt" ] && echo "lab-gate: $(tail -n 1 "$out/lab-gate.txt")"
} | tee -a "$SUM"
if [ -f "$M" ]; then
  S=$T/manifest-summary.md
  {
    echo "build manifest: $(grep -vc '^#' "$M") lines, sha256 $(sha256sum < "$M" | cut -c1-64)"
    echo "stable part (without keyed lines): sha256 $(grep -v -e '^#' -e '^keyed ' "$M" | sha256sum | cut -c1-64)"
    echo "lines per class: $(grep -v '^#' "$M" | cut -d' ' -f1,2 | LC_ALL=C sort | LC_ALL=C uniq -c | awk '{printf "%s/%s=%s ", $2, $3, $1}')"
    echo "keyed classes, sha256 of each class's lines (differ by construction between key sets): $(for c in $(grep '^keyed ' "$M" | cut -d' ' -f2 | LC_ALL=C sort -u); do printf '%s=%s ' "$c" "$(grep "^keyed $c " "$M" | sha256sum | cut -c1-12)"; done)"
    echo "CI <-> CI: build-manifest.py extract <raw job log> --output A, the same for the second run, build-manifest.py compare A B (exit 0 = stable part equal)"
    echo "NVIDIA kernel modules in /usr: $(grep -c -E '^usr ko .*/nvidia[^/]*\.ko' "$M"); NVIDIA packages installed: $(grep -E '^package deb ' "$M" | awk '$NF ~ /nvidia/ {printf "%s=%s ", $NF, $3}')"
    echo '<details><summary>manifest: input, package, keyed (usr lines in the job log)</summary>'; echo; echo '```'
    grep -E '^(input|package|keyed) ' "$M"; echo '```'; echo '</details>'
  } > "$S"
  cat "$S" >> "$SUM"; head -n 4 "$S"
  echo "=== BEGIN build-manifest.txt"; cat "$M"; echo "=== END build-manifest.txt"
  # the full provenance of the third-party sets (every InRelease, index, .deb with sha256): the evidence of the run
  # (build-manifest.py extract --block apt-pin-inputs.json; `apt-inputs` gives its manifest lines back)
  echo "=== BEGIN apt-pin-inputs.json"; sed '$a\' images/debian/mkosi/apt-pin-inputs.json; echo "=== END apt-pin-inputs.json"   # sed: the END marker on a line of its own
  provenance_summary images/debian/mkosi/apt-pin-inputs.json profiles/k8s-worker/upstream/upstream.json || exit 1
else
  echo "build manifest: none (build-all.sh rc=$rc)" | tee -a "$SUM"
fi
{ echo '<details><summary>build log (tail)</summary>'; echo; echo '```'; tail -n 150 "$B"; echo '```'; echo '</details>'; } >> "$SUM"
group_start "build log (whole)"; cat "$B"; group_end
# exit 75 only for apt's own fetch errors against the snapshot (Err:/E:/W: lines), never for a Get: line whose
# version or size happens to hold 502 or 429
if [ $rc != 0 ] && grep -q -E '^(Err:[0-9]+ https://snapshot\.debian\.org|[EW]: Failed to fetch https://snapshot\.debian\.org|[EW]: .*snapshot\.debian\.org.*(Could not connect|Connection timed out|Could not resolve))' "$B"; then
  grep -m 3 -E '^(Err:|[EW]: ).*snapshot\.debian\.org' "$B" | sed 's/^/  snapshot: /' | tee -a "$SUM"
  echo "SNAPSHOT UNAVAILABLE during the build (run did not take place)" | tee -a "$SUM"; exit 75
fi
if [ "$STAGE" = harness ]; then echo "HARNESS RELEASE 1 $([ $rc = 0 ] && echo PASS || echo FAIL) (the gate is HARNESS GATE below)" | tee -a "$SUM"
else echo "${STAGE^^} STAGE $([ $rc = 0 ] && echo PASS || echo FAIL)" | tee -a "$SUM"; fi
exit $rc
)

# harness: releases 2 3 4 of the harness from the same tree and keys (build-all.sh --image-only: the slot initrd and recovery
# UKI of release 1), then the channel of 2 3 4 checked offline (tests/ci/release-channel.sh); nothing leaves the job
step_harness_rel() (
set +e -uo pipefail
if [ "${NL_SHARED_HOST:-0}" = 1 ]; then host_has fdisk xz-utils binutils || exit 1
else sudo apt-get install -y -q --no-install-recommends fdisk xz-utils binutils >/dev/null; fi   # sfdisk, xz, objcopy
cd "$TOP"
keys=$CI_TEST_KEYS; cache=$T/apt-cache; R=$T/rel; mkdir -p "$R"; ln -sfn "$T/out" "$R/1"
X="docker exec -w $PWD $DK_TOOLS"; rc=0
for v in 2 3 4; do
  case $v in 2|3) e=1; m=1; p=pcr-e1 ;; 4) e=2; m=4; p=pcr-e2 ;; esac
  x=(); [ $v = 3 ] && x=(--extra-tree tests/overlays/t7-broken-foil-config)
  t0=$(date +%s)
  TOOLS_EXEC="$X" SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" images/debian/tools/build-all.sh \
    --profile profiles/k8s-worker --variant cp --version $v --epoch $e --min-version $m --release-epochs 1:1,2:4 \
    --pcr $p "${x[@]}" --image-only --keys "$keys" --agent-dist "$T/dist" --cache "$cache" \
    --output-dir "$R/$v" > "$T/build_$v.log" 2>&1; b=$?
  echo "release $v: build-all.sh rc=$b $(( $(date +%s) - t0 ))s epoch=$e min=$m $p${x:+ T7 overlay} $(grep -E '^== build-all: slot initrd and recovery' "$T/build_$v.log" | cut -c15-) lab-gate: $(tail -n 1 "$R/$v/lab-gate.txt" 2>/dev/null)" | tee -a "$SUM"
  if [ $b != 0 ]; then
    tail -n 40 "$T/build_$v.log"
    if grep -q -E '^(Err:[0-9]+ https://snapshot\.debian\.org|[EW]: Failed to fetch https://snapshot\.debian\.org|[EW]: .*snapshot\.debian\.org.*(Could not connect|Connection timed out|Could not resolve))' "$T/build_$v.log"; then
      echo "SNAPSHOT UNAVAILABLE during release $v (run did not take place)" | tee -a "$SUM"; exit 75
    fi
    rc=1; break
  fi
done
df -h / | tail -n +2
if [ $rc = 0 ]; then
  tests/ci/release-channel.sh --out "$R" --keys "$keys" --agent-dist "$T/dist" --channel "$T/channel" > "$T/channel.log" 2>&1 || rc=1
  { echo '```'; cat "$T/channel.log"; echo '```'; } | tee -a "$SUM"
fi
echo "HARNESS RELEASES $([ $rc = 0 ] && echo PASS || echo FAIL)" | tee -a "$SUM"
exit $rc
)

# harness: make test-container STRICT=1 over every scenario against release 1, the channel of 2 3 4 and the job's keys. Guests
# sized for a 2 vCPU / 7 GiB runner (one guest at a time). What a failed step needs is printed (the job keeps no files).
step_harness_test() (
set -uo pipefail
[ -e /dev/kvm ] || { echo "no /dev/kvm on this runner"; exit 1; }
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' | sudo tee /etc/udev/rules.d/99-kvm-harness.rules >/dev/null
sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
docker rm -f "$DK_TOOLS" >/dev/null 2>&1 || true   # the build's tools container; memory for the guest
mkdir -p "$T/work"; cd "$TOP"
rc=0
ENGINE=${ENGINE:-docker} VM_MEM=${VM_MEM:-3G} VM_SMP=${VM_SMP:-2} API_TIMEOUT=${API_TIMEOUT:-600} SETTLE=${SETTLE:-60} \
STRICT=1 ENROLL=${ENROLL:-auto} IMAGE="$T/out/foilbird-deb_1.raw" FOILCTL="$T/dist/foilctl" KEYS="$CI_TEST_KEYS" \
  CHANNEL="$T/channel" AGENT_SUMS="$T/dist/SHA256SUMS" WORK="$T/work" make test-container || rc=$?
f=$T/work/results.txt
{ echo '```'; cat "$f" 2>/dev/null || echo "no results.txt"; echo '```'; } >> "$SUM"
cat "$f" 2>/dev/null || true
for t in "$T"/work/logs/*/*.serial_tail.txt; do [ -f "$t" ] && { echo "--- $t"; cat "$t"; }; done
if [ $rc != 0 ]; then
  for t in "$T"/work/logs/*/stage_*.txt "$T"/work/logs/*/*.final.journal.txt "$T"/work/*.final.journal.txt; do
    [ -f "$t" ] && { echo "--- $t"; tail -n 80 "$t" | cut -c1-300; }; done
  [ -f "$T/work/channel/server.log" ] && { echo "--- channel server log (last 60 lines)"; tail -n 60 "$T/work/channel/server.log" | cut -c1-300; }
fi
v=FAIL; [ $rc = 0 ] && tail -n 1 "$f" | grep -q '^HARNESS PASS ' && tail -n 1 "$f" | grep -q ' 0 skipped' && v=PASS
echo "HARNESS GATE $v (make test-container rc=$rc, $(tail -n 1 "$f" 2>/dev/null))" | tee -a "$SUM"
[ $v = PASS ]
)

# the offline stage (docs/ci-gitlab.md): an online cp build feeding mkosi's package cache, then ci/offline.sh
# each step one ci/offline.sh call in the step's own process (run_step); its exit code is the step's
step_offline_bundle() (
set -eo pipefail
cd "$TOP"
ci/offline.sh bundle
)
step_offline_probes() (
set -eo pipefail
cd "$TOP"
ci/offline.sh probes
)
step_offline_clean() (
set -eo pipefail
cd "$TOP"
ci/offline.sh clean
)
step_offline_net() (
set -eo pipefail
cd "$TOP"
ci/offline.sh net
)
step_offline_build() (
set -eo pipefail
cd "$TOP"
ci/offline.sh build
)
step_offline_compare() (
set -eo pipefail
cd "$TOP"
ci/offline.sh compare
)

# the agent step's outcome decides the job (the image step does not run without it)
step_result() (
s=$(cat "$T/agent.outcome" 2>/dev/null || echo skipped)
echo "agent step: $s" | tee -a "$SUM"
[ "$s" = success ] || { echo "AGENT FAIL: fix it forward in agent/ before any other change to agent/"; exit 1; }
)

run_step() { # run_step <name>: the step in a process of its own (its set -e holds whatever the caller), the outcome
  # recorded for the agent (read by result and by stage runs). Never `"step_$1" || rc=$?`: errexit would be off in the step
  local rc=0
  bash "$SELF" __step "$1" || rc=$?
  [ "$1" = agent ] && { [ $rc = 0 ] && echo success || echo failure; } > "$T/agent.outcome"
  return $rc
}

run_stage() { # run_stage <stage>: the steps of build.yml for that stage, in order; the agent may fail (the job then fails
  # at result, after the other steps ran, as in build.yml); any other failing step stops the stage with its exit code
  local s rc=0 order
  case $1 in
    gate)      order="preflight tag oss errexit" ;;
    selfcheck) order="preflight tag oss errexit agent host snapshot keyfacts initrd result" ;;
    lock)      order="preflight tag oss keyfacts lock" ;;
    cp|gpu)    order="preflight tag oss agent disk host snapshot keyfacts image result" ;;
    harness)   order="preflight tag oss agent disk host snapshot keyfacts image harness_rel harness_test result" ;;
    offline)   order="preflight tag oss agent disk host snapshot keyfacts image offline_bundle offline_probes offline_clean offline_net offline_build offline_compare result" ;;
    *) echo "run-stage.sh: unknown stage $1 (gate|selfcheck|lock|cp|gpu|harness|offline)" >&2; return 2 ;;
  esac
  STAGE=$1; export STAGE
  # shared host: a hosts file with an NVIDIA 0.0.0.0 line left from before fails the stage here, before any change
  if [ "${NL_SHARED_HOST:-0}" = 1 ]; then
    HG_COPY=${NL_HOSTS_COPY:-$T/hosts.orig}
    "$TOP/ci/hosts-guard.sh" save /etc/hosts "$HG_COPY" || { HG_COPY=; return 1; }
  fi
  dk_clean; trap 'dk_clean; hosts_back' EXIT   # the job's docker names: none left from before, none left after
  [ "$1" = harness ] && { CI_TAG_GLOB=${CI_TAG_GLOB:-harness-try-*}; export CI_TAG_GLOB; }
  # offline: the online build is the stage's variant (gpu: NVIDIA offline after the fetch, as the gpu stage) and fills
  # mkosi's package cache for the bundle; ci/offline.sh builds the same variant offline
  if [ "$1" = offline ]; then
    NL_OFFLINE_VARIANT=${NL_OFFLINE_VARIANT:-cp}
    case $NL_OFFLINE_VARIANT in cp|gpu) ;; *) echo "run-stage.sh: NL_OFFLINE_VARIANT [$NL_OFFLINE_VARIANT]: cp or gpu" >&2; return 2 ;; esac
    STAGE=$NL_OFFLINE_VARIANT; NL_PKGCACHE=$T/pkgcache; mkdir -p "$NL_PKGCACHE"; export STAGE NL_PKGCACHE NL_OFFLINE_VARIANT
    # the private parts of the job's TEST keys never outlive the stage, whatever step fails (ci/offline.sh clean removes
    # them on the way; this covers a failure before it)
    trap 'rm -rf "$T/bkey" "$T/probes"; dk_clean; hosts_back' EXIT
    # shared host: the agent's tools set at its one absolute path (/opt/foilbird-build-tools/...) is the host's; the stage
    # builds its own there (online) and its clean removes it, as on a fresh runner. The host's set waits beside it and
    # comes back on the way out, whatever step fails; the stage's own set (online or offline built) goes
    if [ "${NL_SHARED_HOST:-0}" = 1 ]; then
      TS=$(cd "$TOP/agent" && ./build-release.sh --print-tools-root) || { echo "run-stage.sh: --print-tools-root failed" >&2; return 1; }
      case $TS in /opt/foilbird-build-tools/?*) ;; *) echo "run-stage.sh: tools set $TS not under /opt/foilbird-build-tools" >&2; return 1 ;; esac
      TSA=$TS.host-aside
      [ ! -e "$TSA" ] || { echo "run-stage.sh: $TSA is there (a stage before did not put it back): put it back by hand" >&2; return 1; }
      [ ! -e "$TS" ] || mv -- "$TS" "$TSA" || { echo "run-stage.sh: could not put $TS aside" >&2; return 1; }
      echo "shared host: the host's agent tools set $([ -e "$TSA" ] && echo "put aside ($TSA)" || echo "absent")"
      trap 'rm -rf "$T/bkey" "$T/probes"; rm -rf --one-file-system -- "$TS"; [ ! -e "$TSA" ] || { mv -- "$TSA" "$TS" && echo "shared host: the host'"'"'s agent tools set put back ($TS)"; }; dk_clean; hosts_back' EXIT
    fi
  fi
  for s in $order; do
    echo "===== run-stage $1: $s"
    case $s in image|harness_rel|harness_test) [ "$(cat "$T/agent.outcome" 2>/dev/null)" != success ] && { echo "$s: skipped (agent step failed)"; continue; } ;; esac
    [ -d "$T/mkosi/bin" ] && case ":$PATH:" in *":$T/mkosi/bin:"*) ;; *) PATH=$T/mkosi/bin:$PATH ;; esac
    if [ "$s" = agent ]; then run_step agent || true; continue; fi
    run_step "$s" || { rc=$?; echo "===== run-stage $1: $s failed rc=$rc"; return $rc; }
  done
}

case ${1:-} in
  step) n=${2:?step name}; declare -F "step_$n" >/dev/null || { echo "run-stage.sh: unknown step $n" >&2; exit 2; }; run_step "$n" ;;
  # the step process of run_step: the step function called here, at the top level of the script, never under || / if
  __step) n=${2:?step name}; declare -F "step_$n" >/dev/null || { echo "run-stage.sh: unknown step $n" >&2; exit 2; }; "step_$n"; exit $? ;;
  # tests/ci/run-stage-errexit.sh only: one checked helper of the image step on its own (no build)
  __fn) case ${2:-} in nvidia_offline|provenance_summary) f=$2; shift 2; "$f" "$@"; exit $? ;; *) echo "run-stage.sh: __fn nvidia_offline|provenance_summary" >&2; exit 2 ;; esac ;;
  gate|selfcheck|lock|cp|gpu|harness|offline) run_stage "$1" ;;
  *) awk 'NR > 1 && !/^#/ {exit} NR > 1' "$0"; exit 2 ;;
esac
