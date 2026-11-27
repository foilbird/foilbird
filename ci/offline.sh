#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The offline part of the CI stage "offline" (ci/run-stage.sh offline, docs/ci-gitlab.md): after an online build of the
# variant (NL_OFFLINE_VARIANT: cp, the default, or gpu) in the same job (manifest A, mkosi's package cache in $T/pkgcache),
# build the input bundle, try to break it, remove every online leftover, cut the network, build the same variant again
# from the bundle alone (manifest B) and compare A with B.
#   ci/offline.sh bundle|probes|clean|net|build|compare      (CI_TMP=$T, the tree is the script's parent)
# The network is cut in a network namespace, not on the host: a host-wide DROP would also cut the CI runner's own
# connection. The namespace has lo and a dummy interface with the default route (192.0.2.1/24, TEST-NET-1), so that every
# packet out is routed, counted by iptables/ip6tables (a counting rule without a target, then the DROP, each with its own
# counter; everything but lo, UDP 53 included: the namespace's resolv.conf names 192.0.2.53) and dropped. Every run in the
# namespace writes its own counter file (a path argument, not the environment: sudo resets it); each probe must be
# counted and dropped, the offline build must have a counter file with nothing counted. The tools (Debian 13: sqv for apt-pin.py) come from the online
# container committed to a local image and run again with --network none, mounting the tree and $T (OFFLINE_TOOLS).
# The TEST key of the role is made in the job ($T/bkey): its private part is never in the tree nor in an artifact, it is
# removed by the clean step right after the probes (and by the EXIT trap of run-stage.sh on any failure), its fingerprint only in this job's list (a probe checks a product list refuses it).
# NL_OFFLINE_AGENT_REQUIRED=1 (the counted run): the agent's offline inputs (agent/tools/offline-inputs.sh) must exist;
# without it (interim) the agent dist built online in this job is carried in the bundle, marked "agent offline: pending".
set -euo pipefail
top=$(cd "$(dirname "$0")/.." && pwd)
T=${CI_TMP:?CI_TMP}; SUM=${CI_SUMMARY:-$T/summary.md}
KEYS=${CI_TEST_KEYS:-/dev/shm/ci-test-keys}   # the image's TEST keys of the online build (ci/run-stage.sh)
B=$T/bundle; NS=$T/netns
# the variant of the stage: the online build A (ci/run-stage.sh), the probe builds and the offline build B are the same one
V=${NL_OFFLINE_VARIANT:-cp}
case $V in cp|gpu) ;; *) echo "offline.sh: NL_OFFLINE_VARIANT [$V]: cp or gpu" >&2; exit 2 ;; esac
fail() { echo "OFFLINE FAIL ($1): $2" | tee -a "$SUM"; exit 1; }
# failtail <log> <step> <reason>: the last 20 non-empty lines of a step's log into the job log, then OFFLINE FAIL with
# the reason and the log's last non-empty line (a log that ends with an empty line, or an empty one, gave an empty reason:
# G8 alpha3 job 18, "offline-inputs.sh fetch: ")
lastline() { grep -v '^[[:space:]]*$' "$1" 2>/dev/null | tail -n "${2:-1}" || true; }
failtail() {
  echo "--- $1: $(wc -l 2>/dev/null < "$1" || echo 'no log,') lines; the last 20 non-empty:"; lastline "$1" 20; echo "--- end of $1"
  fail "$2" "$3; last line: $(lastline "$1" | cut -c1-300)"
}
say() { echo "$*" | tee -a "$SUM"; }
# disk at the points where the stage holds the most (the runner's disk is the limit of a gpu bundle; docs/ci-gitlab.md)
dfp() { say "disk ($V) $1: $(df -h --output=target,used,avail / "$T" 2>/dev/null | awk 'NR > 1 && !s[$1]++ {printf "%s used %s free %s; ", $1, $2, $3}')$T $(du -sh "$T" 2>/dev/null | cut -f1)"; }

# a TEST key of the bundle-signing role: gpg home, primary fingerprint, a public keyring for gpgv
mkkey() { # mkkey <dir> <name> [extra gpg options...]
  local d=$1 n=$2; shift 2; mkdir -m 700 -p "$d"
  gpg --homedir "$d" --batch --pinentry-mode loopback --passphrase '' "$@" --quick-gen-key "TEST $n <bundle@example.invalid>" ed25519 sign 1y 2>/dev/null
  gpg --homedir "$d" --batch --with-colons --list-keys | awk -F: '$1 == "fpr" {print $10; exit}'
}
export_key() { gpg --homedir "$1" --batch --export > "$2"; }
sign_as() { rm -f "$2/MANIFEST.sha256.sig"; gpg --homedir "$1" --batch --yes --pinentry-mode loopback --passphrase '' "${@:3}" --detach-sign --output "$2/MANIFEST.sha256.sig" "$2/MANIFEST.sha256"; }

# the tools container of the offline part: the online o2tools (its packages installed) committed locally, no network
DK_TOOLS=${DK_TOOLS:-o2tools}; DK_OFF=${DK_OFF:-o2tools-off}; DK_IMG=${DK_IMG:-nl-o2tools-offline}   # the job's docker names (ci/run-stage.sh)
DK_AOFF=${DK_AOFF:-o2tools-agent-off}; DK_AFETCH=${DK_AFETCH:-o2tools-agent-fetch}; DK_AIMG=${DK_AIMG:-nl-agent-tools}
DCPU=(); [ -z "${NL_DOCKER_CPUS:-}" ] || DCPU=(--cpus "$NL_DOCKER_CPUS")
# the agent's container image of this job (step agent of ci/run-stage.sh: the pinned Debian image with the C toolchain of
# agent/c-toolchain.pins): the offline inputs are fetched in it (its rustup, the toolchain the agent step installed in
# $T/agent-home) and the agent is built offline in it with --network none; both as the caller, in the tree's agent/
TB=/opt/foilbird-build-tools
agent_env() { # agent_env <home>: the environment options of the agent's runs (the same as the agent step's)
  AE=(-e HOME="$1" -e SOURCE_DATE_EPOCH="$(git -C "$top" log -1 --format=%ct)")
  [ -z "${CARGO_BUILD_JOBS:-}" ] || AE+=(-e "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS")
  [ -z "${RUST_TEST_THREADS:-}" ] || AE+=(-e "RUST_TEST_THREADS=$RUST_TEST_THREADS")
}
OFFLINE_TOOLS="docker exec -w $top $DK_OFF"
tools_offline() {
  docker inspect "$DK_OFF" > /dev/null 2>&1 && return 0
  docker commit "$DK_TOOLS" "$DK_IMG" > /dev/null || fail tools "docker commit $DK_TOOLS"
  docker run -d "${DCPU[@]}" --name "$DK_OFF" --network none -v "$top:$top" -v "$T:$T" -w "$top" "$DK_IMG" sleep infinity > /dev/null || fail tools "docker run --network none"
  say "tools container $DK_OFF: --network none ($(docker inspect -f '{{.HostConfig.NetworkMode}}' "$DK_OFF"))"
}

# the default tools tree of the build: the three build directories hold one (equal mkosi.tools.manifest); one tar of
# it, made as root (owners, modes, xattrs, ACLs), for the bundle
TOOLS_DIRS="images/debian/foilbird-initrd images/debian/recovery profiles/k8s-worker"
tools_archive() {
  local d m m0=
  for d in $TOOLS_DIRS; do
    [ -d "$top/$d/mkosi.tools" ] && [ -f "$top/$d/mkosi.tools.manifest" ] || fail bundle "no tools tree in $d"
    m=$(sha256sum < "$top/$d/mkosi.tools.manifest" | cut -c1-64); [ -z "$m0" ] || [ "$m" = "$m0" ] || fail bundle "the tools trees differ ($d)"; m0=$m
  done
  sudo tar --xattrs --xattrs-include='*' --acls --numeric-owner -C "$top/profiles/k8s-worker" -cf "$T/tools.tar" mkosi.tools || fail bundle "tar of the tools tree"
  sudo chown "$(id -u):$(id -g)" "$T/tools.tar"; cp "$top/profiles/k8s-worker/mkosi.tools.manifest" "$T/tools.manifest"
  say "tools tree: one for $TOOLS_DIRS (mkosi.tools.manifest $m0), tar $(du -h "$T/tools.tar" | cut -f1)"
}
# the bundle's tools tree into every build directory, as root, after the bundle verify; each mkosi.tools.manifest then
# equal to the bundle's
tools_restore() {
  local d bad want
  # the member list once into a file, checked by grep on the file: no pipe from tar (pipefail with grep -q would turn
  # tar's SIGPIPE into a pass exactly when a bad member is found)
  tar -tf "$B/tools/mkosi.tools.tar" > "$T/tools.list" || fail build "tar -tf of the tools archive"
  bad=$(grep -vxE 'mkosi\.tools(/.*)?' "$T/tools.list" | sed -n '1,3p' | tr '\n' ' ') || true
  [ -z "$bad" ] || fail build "tools archive: members outside mkosi.tools/: $bad"
  if grep -qE '(^|/)\.\.(/|$)|^/' "$T/tools.list"; then fail build "tools archive: a member with .. or an absolute one"; fi
  want=$(sha256sum < "$B/tools/mkosi.tools.manifest" | cut -c1-64)
  for d in $TOOLS_DIRS; do
    [ ! -e "$top/$d/mkosi.tools" ] || fail build "$d: a tools tree is there before the restore (clean leaves none)"
    sudo tar --xattrs --xattrs-include='*' --acls --numeric-owner --same-owner --same-permissions -C "$top/$d" -xf "$B/tools/mkosi.tools.tar" || fail build "untar of the tools tree into $d"
    sudo install -m 0644 -o root -g root "$B/tools/mkosi.tools.manifest" "$top/$d/mkosi.tools.manifest"
    [ "$(sha256sum < "$top/$d/mkosi.tools.manifest" | cut -c1-64)" = "$want" ] || fail build "$d: mkosi.tools.manifest is not the bundle's"
  done
  say "tools tree restored from the bundle into $TOOLS_DIRS (mkosi.tools.manifest $want, all three equal)"
}
# a hang is a FAIL, not a silent step timeout: 15 min for one apt chain (a few seconds on the stand)
aptv() { $OFFLINE_TOOLS timeout -k 10 900 python3 "$top/ci/bundle-apt-verify.py" --bundle "$1" --tree "${2:-$top}" -- sqv; }

do_bundle() {
  local ag rc=0
  # the online agent dist, by its SHA256SUMS: the offline one must equal it (do_build); $T/dist itself goes with the clean
  [ -s "$T/dist/SHA256SUMS" ] || fail bundle "no online agent dist ($T/dist/SHA256SUMS)"
  sha256sum < "$T/dist/SHA256SUMS" | cut -c1-64 > "$T/agent-dist-online.sha256"
  cp "$T/out/build-manifest.txt" "$T/manifest-online.txt" || fail bundle "no online manifest ($T/out/build-manifest.txt)"
  dfp "after the online build"
  tools_offline
  if [ -x "$top/agent/tools/offline-inputs.sh" ]; then
    # in the agent's container (network on): cargo vendor with the toolchain of the agent step, no rustup of the host
    docker image inspect "$DK_AIMG" > /dev/null 2>&1 || fail bundle "no agent container image $DK_AIMG (step agent keeps it in the offline stage)"
    agent_env "$T/agent-home"
    rc=0; docker run --rm "${DCPU[@]}" --name "$DK_AFETCH" -u "$(id -u):$(id -g)" -v "$top:$top" -v "$T:$T" -w "$top/agent" "${AE[@]}" \
      -e RUSTUP_HOME="$T/agent-home/rustup" -e CARGO_HOME="$T/agent-home/cargo" "$DK_AIMG" \
      "$top/agent/tools/offline-inputs.sh" fetch "$T/agent-inputs" > "$T/agent-inputs.log" 2>&1 || rc=$?
    [ "$rc" = 0 ] || failtail "$T/agent-inputs.log" bundle "offline-inputs.sh fetch rc=$rc, PROVENANCE $(wc -l 2>/dev/null < "$T/agent-inputs/PROVENANCE" || echo none) lines"
    ag=(--agent-inputs "$T/agent-inputs"); say "agent offline inputs: agent/tools/offline-inputs.sh fetch (in $DK_AIMG)"
  elif [ "${NL_OFFLINE_AGENT_REQUIRED:-0}" = 1 ]; then
    fail bundle "agent/tools/offline-inputs.sh missing (counted run: the agent must be built offline)"
  else
    mkdir -p "$T/agent-inputs/dist"; cp -a "$T/dist/." "$T/agent-inputs/dist/"; ag=(--agent-inputs "$T/agent-inputs")
    say "agent offline: pending the agent's offline inputs (interim: the dist built online in this job is carried in the bundle)"
  fi
  tools_archive
  # probes of the explicit list: a file outside it in the package cache never reaches the bundle, and apt's root-only
  # partial/ (0700) does not stop the make
  echo stray > "$T/pkgcache/stray-outside-the-list"
  sudo test -d "$T/pkgcache/cache/apt/archives/partial" && say "probe list-partial: apt's partial/ is there ($(sudo stat -c '%U %a' "$T/pkgcache/cache/apt/archives/partial"))"
  "$top/ci/bundle.sh" make "$B" --tree "$top" --cache "$T/apt-cache" --pkgcache "$T/pkgcache" --mkosi "$T/mkosi" \
    --tools-archive "$T/tools.tar" --tools-manifest "$T/tools.manifest" "${ag[@]}" | tee -a "$SUM"
  [ "${PIPESTATUS[0]}" = 0 ] || fail bundle "bundle.sh make (probe list-partial: refused with partial/ there)"
  say "probe list-partial: bundle made with partial/ in the package cache"
  [ ! -e "$B/pkgcache/stray-outside-the-list" ] && ! grep -q 'stray-outside-the-list' "$B/MANIFEST.sha256" || fail bundle "probe list-stray: a file outside the list is in the bundle"
  say "probe list-stray: the file outside the list is not in the bundle"; rm -f "$T/pkgcache/stray-outside-the-list"
  FPR=$(mkkey "$T/bkey" "bundle-signing"); export_key "$T/bkey" "$T/bkeyring.gpg"
  sign_as "$T/bkey" "$B"
  echo "$FPR" > "$T/bkey.fpr"
  say "bundle signed with an ephemeral TEST key of the role, $FPR (a mechanism check only: in a closed network the holder signs, outside the build)"
  NL_BUNDLE_FPR=$FPR NL_BUNDLE_KEYRING=$T/bkeyring.gpg "$top/ci/bundle.sh" verify "$B" --tree "$top" | tee -a "$SUM"
  aptv "$B" > "$T/aptv.txt" 2>&1 || rc=$?; tee -a "$SUM" < "$T/aptv.txt"
  [ "$rc" = 0 ] || fail bundle "the apt chain of the bundle (bundle-apt-verify.py rc=$rc; 124 = timeout)"
  # regression probe: the bare name "sqv" is resolved to an absolute path, not to the PATH wrapper (offline-try-3 hang)
  grep -q '^apt-verify: sqv /' "$T/aptv.txt" && grep -qx 'APT-VERIFY PASS' "$T/aptv.txt" || fail bundle "probe a-bare-sqv: the sqv command not resolved to an absolute path"
  dfp "bundle made"
  say "probe a-bare-sqv: \"sqv\" resolved to $(sed -n '/^apt-verify: sqv /{s/^apt-verify: sqv \([^ ]*\) .*/\1/p;q}' "$T/aptv.txt"), apt chain PASS"
}

# probes: every one on a copy of the bundle, refused with the reason expected; one positive (two keys listed, the
# second signs); the apt chain still refuses a changed .deb under a correct, re-signed manifest
do_probes() {
  local fpr kr n=0 ok=0 P=$T/probes; fpr=$(cat "$T/bkey.fpr"); kr=$T/bkeyring.gpg; rm -rf "$P"; mkdir -p "$P"
  cp() { command cp "$@"; }
  # a copy of hard links (the bundle holds GB): a file is unlinked before a probe changes it, the signature removed
  # before a re-sign (sign_as), so the bundle itself never changes
  fresh() { rm -rf "$P/b"; command cp -al "$B" "$P/b"; }
  brk() { command cp -- "$P/b/$1" "$P/b/$1.brk" && mv -f -- "$P/b/$1.brk" "$P/b/$1"; }
  remf() { # remf <path in the bundle>: its sha256 in the manifest updated after a change, then re-signed
    local new; new=$(sha256sum < "$P/b/$1" | cut -c1-64)
    awk -v f="$1" -v s="$new" '$1 == "file" && substr($0, 71) == f {$2 = s} {print}' "$P/b/MANIFEST.sha256" > "$P/m" && mv "$P/m" "$P/b/MANIFEST.sha256"; resign; }
  aexpect() { # aexpect <name> <pattern>: bundle verify accepts $P/b, the apt chain refuses it with <pattern>
    local name=$1 pat=$2 out; n=$((n + 1))
    if ! env "${base[@]}" "$top/ci/bundle.sh" verify "$P/b" --tree "$top" > /dev/null 2>&1; then echo "probe $name: FAIL (the re-signed bundle was refused, the probe did not reach the apt chain)"
    elif out=$(aptv "$P/b" "${3:-$top}" 2>&1); then echo "probe $name: FAIL (the apt chain accepted it)"
    elif grep -q -- "$pat" <<< "$out"; then ok=$((ok + 1)); echo "probe $name: refused by the apt chain as expected ($(echo "$out" | tail -n 1))"
    else echo "probe $name: FAIL (refused for another reason: $(echo "$out" | tail -n 1))"; fi
  }
  resign() { sign_as "$T/bkey" "$P/b"; }
  expect() { # expect <name> <pattern> <env...> : verify on $P/b must fail with <pattern>
    local name=$1 pat=$2; shift 2; n=$((n + 1))
    if out=$(env "$@" "$top/ci/bundle.sh" verify "$P/b" --tree "$top" 2>&1); then echo "probe $name: FAIL (accepted)"
    elif grep -q -- "$pat" <<< "$out"; then ok=$((ok + 1)); echo "probe $name: refused as expected ($(echo "$out" | tail -n 1))"
    else echo "probe $name: FAIL (refused for another reason: $(echo "$out" | tail -n 1))"; fi
  }
  base=(NL_BUNDLE_FPR="$fpr" NL_BUNDLE_KEYRING="$kr")
  first=$(grep -m1 '^file ' "$B/MANIFEST.sha256" | cut -d' ' -f3-)
  fresh; brk "$first"; printf x >> "$P/b/$first";       expect a-changed-file "does not match its sha256" "${base[@]}"
  fresh; echo extra > "$P/b/extra-file";                 expect b-extra-file "files missing or extra" "${base[@]}"
  fresh; rm -f "$P/b/$first";                            expect b-missing-file "files missing or extra" "${base[@]}"
  fresh; ln -s /etc/passwd "$P/b/pkgcache/link";         expect b-symlink "not a regular file or directory" "${base[@]}"
  fpr2=$(mkkey "$P/k2" "other"); export_key "$P/k2" "$P/k2.gpg"
  fresh; sign_as "$P/k2" "$P/b";                         expect c-foreign-key "signature refused" "${base[@]}"
  cat "$kr" "$P/k2.gpg" > "$P/both.gpg"
  fresh; sign_as "$P/k2" "$P/b";                         expect c-fpr-not-listed "not in NL_BUNDLE_FPR" NL_BUNDLE_FPR="$fpr" NL_BUNDLE_KEYRING="$P/both.gpg"
  fresh; sed -i -E 's/^revision [0-9a-f]+/revision 0000000000000000000000000000000000000000/' "$P/b/MANIFEST.sha256"; resign
                                                         expect d-other-revision "bundle of revision" "${base[@]}"
  fresh; sed -i -E '0,/^lock [0-9a-f]{64}/s//lock 0000000000000000000000000000000000000000000000000000000000000000/' "$P/b/MANIFEST.sha256"; resign
                                                         expect d-other-lock "of the bundle is not the tree's" "${base[@]}"
  fpr3=$(mkkey "$P/k3" "expired" --faked-system-time 20200101T000000); export_key "$P/k3" "$P/k3.gpg"
  fresh; sign_as "$P/k3" "$P/b" --faked-system-time 20200101T000100
                                                         expect e-expired-key "signature refused" NL_BUNDLE_FPR="$fpr3" NL_BUNDLE_KEYRING="$P/k3.gpg"
  fresh;                                                 expect f-empty-list "NL_BUNDLE_FPR is empty" NL_BUNDLE_FPR= NL_BUNDLE_KEYRING="$kr"
  fresh;                                                 expect f-short-id "not a full 40-hex fingerprint" NL_BUNDLE_FPR="${fpr: -16}" NL_BUNDLE_KEYRING="$kr"
  fresh; sed -i -E "s/^created [0-9]+/created $(( $(date +%s) + 86400 ))/" "$P/b/MANIFEST.sha256"; resign
                                                         expect g-clock-behind "clock behind bundle" "${base[@]}"
  # the TEST key is in the CI list only: against a product list (the role's keys, the TEST one not among them) a bundle
  # signed with it is refused
  fresh;                                                 expect j-test-key-product-list "not in NL_BUNDLE_FPR" NL_BUNDLE_FPR="$fpr2" NL_BUNDLE_KEYRING="$P/both.gpg"
  # positive: two fingerprints listed, the bundle signed by the key of the second one
  n=$((n + 1)); fresh
  if NL_BUNDLE_FPR="$fpr2,$fpr" NL_BUNDLE_KEYRING="$P/both.gpg" "$top/ci/bundle.sh" verify "$P/b" --tree "$top" > /dev/null 2>&1; then
    ok=$((ok + 1)); echo "probe h-two-keys: accepted as expected (list of two, signed by the second)"
  else echo "probe h-two-keys: FAIL (refused)"; fi
  # the apt chain under a correct manifest: a changed .deb, its sha256 in the manifest, re-signed -> bundle verify
  # accepts, apt-pin.py verify refuses (the signature of the bundle does not replace the chain)
  n=$((n + 1)); fresh
  deb=$(cd "$P/b" && find apt-cache -name '*.deb' | LC_ALL=C sort | sed -n 1p)
  brk "$deb"; printf x >> "$P/b/$deb"; new=$(sha256sum < "$P/b/$deb" | cut -c1-64)
  awk -v f="$deb" -v s="$new" '$1 == "file" && substr($0, 71) == f {$2 = s} {print}' "$P/b/MANIFEST.sha256" > "$P/m" && mv "$P/m" "$P/b/MANIFEST.sha256"; resign
  if ! NL_BUNDLE_FPR="$fpr" NL_BUNDLE_KEYRING="$kr" "$top/ci/bundle.sh" verify "$P/b" --tree "$top" > /dev/null 2>&1; then
    echo "probe i-apt-chain: FAIL (the re-signed bundle was refused, the probe did not reach apt-pin)"
  elif $OFFLINE_TOOLS python3 "$top/images/debian/tools/apt-pin.py" verify --conf "$top/images/debian/apt-pin.conf" --conf "$top/profiles/k8s-worker/apt-pin.conf" --cache "$P/b/apt-cache" > "$P/apt.log" 2>&1; then
    echo "probe i-apt-chain: FAIL (apt-pin.py verify accepted a changed $deb)"
  else ok=$((ok + 1)); echo "probe i-apt-chain: bundle accepted, apt-pin.py verify refused as expected ($(tail -n 1 "$P/apt.log"))"; fi
  # build-all.sh itself refuses an offline build from a bad bundle before its first step: a changed file of the package
  # cache, everything else right (no root entry, no mkosi, no "== build-all:" step line). Positive control on an intact
  # copy with the same inputs: --check-inputs passes every input check and the bundle verify and stops before the first
  # step (a full call would build); so the refusal comes from the bundle, not from another input
  ba() { # ba <bundle> [--check-inputs]: build-all.sh offline from <bundle>, the inputs of the offline build
    env NL_OFFLINE=1 NL_BUNDLE="$1" NL_PKGCACHE="$1/pkgcache" "${base[@]}" TOOLS_EXEC="$OFFLINE_TOOLS" \
      SOURCE_DATE_EPOCH="$(git -C "$top" log -1 --format=%ct)" "$top/images/debian/tools/build-all.sh" \
      --profile "$top/profiles/k8s-worker" --variant "$V" --version 1 --epoch 1 --min-version 1 \
      --keys "$KEYS" --agent-dist "$T/dist" --cache "$1/apt-cache" --output-dir "$P/out" "${@:2}" 2>&1
  }
  n=$((n + 1)); fresh; mkdir -p "$P/out"
  if out=$(ba "$P/b" --check-inputs) && grep -q '^bundle: verified' <<< "$out" && grep -q 'inputs checked, bundle verified' <<< "$out" &&
     ! grep -q '^== build-all:' <<< "$out"; then
    ok=$((ok + 1)); echo "probe k-build-all-control: intact bundle, same inputs: verified, stopped before the first step ($(echo "$out" | tail -n 1))"
  else echo "probe k-build-all-control: FAIL (the intact bundle with the same inputs did not pass: $(echo "$out" | tail -n 1))"; fi
  n=$((n + 1)); fresh
  pf=$(cd "$P/b" && find pkgcache -type f | LC_ALL=C sort | sed -n 1p); brk "$pf"; printf x >> "$P/b/$pf"
  # the pair control / bad differs only by the bundle: the same --check-inputs call on the changed copy is refused
  if out=$(ba "$P/b" --check-inputs); then
    echo "probe k-build-all-bad-check: FAIL (--check-inputs accepted a changed $pf)"
  elif grep -q 'bundle refused' <<< "$out" && ! grep -q 'inputs checked' <<< "$out"; then
    ok=$((ok + 1)); echo "probe k-build-all-bad-check: refused by --check-inputs ($(echo "$out" | tail -n 1))"
  else echo "probe k-build-all-bad-check: FAIL (refused for another reason: $(echo "$out" | tail -n 1))"; fi
  # the full call (no flag) on the same changed copy: the verify stands before every step
  n=$((n + 1))
  if out=$(ba "$P/b"); then
    echo "probe k-build-all-bad-bundle: FAIL (build-all accepted a changed $pf)"
  elif grep -q 'bundle refused' <<< "$out" && grep -q 'does not match its sha256' <<< "$out" && ! grep -q '^== build-all:' <<< "$out"; then
    ok=$((ok + 1)); echo "probe k-build-all-bad-bundle: refused before the first step ($(echo "$out" | tail -n 1))"
  else echo "probe k-build-all-bad-bundle: FAIL (not refused by the bundle check before the first step: $(echo "$out" | tail -n 1))"; fi
  # the tools tree: one changed byte of the archive -> the bundle verify refuses it
  fresh; brk tools/mkosi.tools.tar; printf x >> "$P/b/tools/mkosi.tools.tar"
                                                         expect t-tools-byte "does not match its sha256" "${base[@]}"
  # the image's key (ci-test-keys, the release role) signs the manifest -> not the bundle role's key
  cat "$kr" "$KEYS/release.pgp" > "$P/role2.gpg"
  fresh; sign_as "$KEYS/gpg" "$P/b"; expect r-image-key "not in NL_BUNDLE_FPR" NL_BUNDLE_FPR="$fpr" NL_BUNDLE_KEYRING="$P/role2.gpg"
  # the apt chain under a correct, re-signed manifest (bundle-apt-verify.py)
  L=pkgcache/mkosi-cache; L=$L/$(ls "$B/$L" | grep '\.metadata\.cache$' | head -n 1)/lib/apt/lists
  ir=$L/$(ls "$B/$L" | grep '^snapshot\.debian\.org_.*_InRelease$' | LC_ALL=C sort | sed -n 1p)
  fresh; brk "$ir"; gpg --homedir "$P/k2" --batch --yes --pinentry-mode loopback --passphrase '' --clearsign --output "$P/b/$ir" \
    <(sed -n '/^-----BEGIN PGP SIGNED MESSAGE-----$/,/^-----BEGIN PGP SIGNATURE-----$/p' "$B/$ir" | sed '1,/^$/d;$d') 2>/dev/null; remf "$ir"
                                                         aexpect p-inrelease-foreign-key "signature not valid"
  pk=$L/$(ls "$B/$L" | grep '_binary-amd64_Packages$' | LC_ALL=C sort | sed -n 1p)
  fresh; brk "$pk"; printf '\n' >> "$P/b/$pk"; remf "$pk"; aexpect p-packages-changed "differs from its InRelease"
  db=pkgcache/cache/apt/archives/$(ls "$B/pkgcache/cache/apt/archives" | grep '\.deb$' | grep -v '^debian-archive-keyring_' | LC_ALL=C sort | sed -n 1p)
  fresh; brk "$db"; printf x >> "$P/b/$db"; remf "$db";   aexpect p-deb-changed "differs from its Packages stanza"
  # Snapshot= of the tree changed, the keyring pin not: a worktree of the same commit with another snapshot
  git -C "$top" worktree add -q --detach "$P/t" HEAD && (cd "$P/t" && sh images/debian/tools/snapshot set 20200101T000000Z > /dev/null)
  fresh;                                                 aexpect p-snapshot-without-pin "the pin must change with the snapshot" "$P/t"
  git -C "$top" worktree remove --force "$P/t"
  rm -rf "$P/b" "$P/out"
  say "bundle probes: $ok/$n"
  [ "$ok" = "$n" ] || fail probes "$((n - ok)) probe(s) not as expected"
}

# remove every online leftover the offline build could find; what stays is listed by du
do_clean() {
  local d u left
  u=$(id -un)
  # what the online build left in the tree as another user (TOOLS_EXEC = root in the tools container: apt-pin.py and
  # fetch-upstream.py prepare; sudo mkosi: outputs, mount points of BuildSources), named before it goes
  say "not $u's in the tree before the clean: $(sudo find "$top" -xdev -path "$top/.git" -prune -o ! -user "$u" -print | wc -l)"
  for d in "$top"/images/debian/foilbird-initrd "$top"/images/debian/recovery "$top"/images/debian/mkosi "$top"/profiles/*; do
    sudo rm -rf --one-file-system "$d/mkosi.tools" "$d/mkosi.cache" "$d/mkosi.output" "$d/mkosi.tools.manifest"
  done
  sudo rm -rf --one-file-system "$T/tools.tar" "$T/tools.manifest"   # the online tools tree: offline only the bundle's
  # the online set of the agent's build tools, exactly its directory (build-release.sh names it; the base stays): the
  # offline build installs the bundle's into the same path, never uses the online one
  ts_root=$(cd "$top/agent" && ./build-release.sh --print-tools-root) || fail clean "build-release.sh --print-tools-root"
  case $ts_root in /opt/foilbird-build-tools/?*) ;; *) fail clean "tools set directory not under /opt/foilbird-build-tools/: [$ts_root]" ;; esac
  case $ts_root in */../*|*/..|*/./*|*//*) fail clean "tools set directory $ts_root has . or .. or //" ;; esac
  sudo rm -rf --one-file-system "$T/mkosi" "$T/apt-cache" "$T/pkgcache" "$T/out" "$T/dist" "$T/agent-inputs" "$T/agent-home" "$HOME/.cargo" "$HOME/.rustup" "$top/agent/target" "$ts_root"
  # removed by root, the user that wrote them (the tools container, mkosi): apt-pin.py prepare's out-dir, fetch-upstream.py's
  # out, the images of the online build under out/ (out/.keep is in git), the empty BuildSources mount points mkosi made
  # in images/debian/mkosi, the bytecode of the tree's tools written by python3 as root
  sudo rm -rf --one-file-system "$top/images/debian/mkosi/aptpin" "$top/images/debian/mkosi/nvsrc" \
    "$top/images/debian/mkosi/pinned.conf" "$top/images/debian/mkosi/apt-pin-inputs.json" "$top"/profiles/*/upstream
  for d in "$top"/images/debian/foilbird-initrd/out "$top"/images/debian/recovery/out "$top"/images/debian/mkosi/out "$top"/profiles/*/out; do
    if [ -d "$d" ]; then sudo find "$d" -mindepth 1 -maxdepth 1 ! -name .keep -exec rm -rf --one-file-system {} +; fi
  done
  for d in "$top"/images/debian/mkosi/image-tools "$top"/images/debian/mkosi/k8s-worker; do
    [ ! -e "$d" ] || sudo rmdir "$d" || fail clean "$d: not an empty mount point"
  done
  sudo find "$top" -xdev -path "$top/.git" -prune -o -type d -name __pycache__ -prune -exec rm -rf {} +
  # the private parts of the TEST keys (the role's and the probes' own): not needed after the probes; the public keyring
  # and the fingerprint stay for the verify of the offline build
  rm -rf "$T/bkey" "$T/probes"
  [ ! -e "$T/bkey" ] || fail clean "$T/bkey still there"
  # nothing of another user stays in the tree: the offline build writes only through its own steps (no chmod, no || true)
  left=$(sudo find "$top" -xdev -path "$top/.git" -prune -o ! -user "$u" -print | LC_ALL=C sort)
  [ -z "$left" ] || fail clean "not $u's in the tree after the clean ($(wc -l <<< "$left")): $(sed -n 1,30p <<< "$left" | tr '\n' ' ')"
  say "the tree after the clean: every file is $u's (outside .git)"
  say "after the clean-up (du): $(du -sh --one-file-system "$HOME" "$T" 2>/dev/null | awk '{printf "%s %s; ", $2, $1}')"
  say "left in $T: $(ls "$T" | tr '\n' ' ')"
}

# the network namespace: lo, a dummy default route, counted and dropped; resolv.conf of the namespace -> 192.0.2.53.
# The kernel itself sends nothing on d0: no router solicitation (accept_ra 0, router_solicitations 0), no link-local
# address (addr_gen_mode 1), no duplicate address detection (nodad) - set before d0 is up, lo untouched; the rules are in
# place before d0 is up, so whatever d0 sends is counted (router solicitations of the link-local address, 56 bytes each,
# were once counted as packets of the offline builds). The namespace's own /etc/hosts names localhost and this host (its
# name and FQDN, taken outside the namespace, on 127.0.0.1): the sudo inside resolves the host's name, and a runner
# image without it in /etc/hosts sent those lookups to 192.0.2.53 (4 packets of 60 bytes, A + AAAA twice). Its own
# /etc/nsswitch.conf is the host's with only the hosts line replaced by "hosts: files dns" (added if missing): no
# resolve, myhostname or mdns module of the runner's image answers or asks past the namespace; passwd/group and the rest
# stay as they are (sudo needs them). A step of the set-up that fails stops the run.
ns_run() { # ns_run <counter file> <command...>: as the caller, inside the offline namespace; the counters go to the file
  local cnt=$1 hn fq; shift
  hn=$(hostname) && [ -n "$hn" ] || fail net "hostname of the runner"; fq=$(hostname -f 2>/dev/null) || fq=
  sudo unshare -n -m -- sh -c '
    die() { echo "nl-offline: namespace set-up FAIL: $*" >&2; exit 97; }
    sc() { echo "$2" > "/proc/sys/net/ipv6/conf/$1" || die "net.ipv6.conf.$1=$2"; }
    ip link set lo up || die "lo up"
    for c in default all; do sc $c/accept_ra 0; sc $c/router_solicitations 0; done; sc default/addr_gen_mode 1
    ip link add d0 type dummy || die "dummy d0"
    sc d0/accept_ra 0; sc d0/router_solicitations 0; sc d0/addr_gen_mode 1
    for t in iptables ip6tables; do
      $t -A OUTPUT ! -o lo -m comment --comment nl-count || die "$t counting rule"
      $t -A OUTPUT ! -o lo -m comment --comment nl-drop -j DROP || die "$t drop rule"
    done
    ip link set d0 up || die "d0 up"
    ip addr add 192.0.2.1/24 dev d0 || die "IPv4 address on d0"; ip route add default dev d0 || die "IPv4 default route"
    ip -6 addr add 2001:db8::1/64 dev d0 nodad || die "IPv6 address on d0"; ip -6 route add default dev d0 || die "IPv6 default route"
    { if [ -n "$4" ] && [ "$4" != "$3" ]; then echo "127.0.0.1 localhost $4 $3"; else echo "127.0.0.1 localhost $3"; fi; echo "::1 localhost"; } > "$1/hosts" || die "hosts"
    mount --bind "$1/hosts" /etc/hosts || die "hosts"
    [ -r /etc/nsswitch.conf ] || die "no /etc/nsswitch.conf"
    if grep -q -E "^[[:space:]]*hosts:" /etc/nsswitch.conf; then sed -E "s/^[[:space:]]*hosts:.*/hosts: files dns/" /etc/nsswitch.conf
    else cat /etc/nsswitch.conf && echo "hosts: files dns"; fi > "$1/nsswitch.conf" || die "nsswitch.conf"
    mount --bind "$1/nsswitch.conf" /etc/nsswitch.conf || die "nsswitch.conf"
    echo "nameserver 192.0.2.53" > "$1/resolv.conf"; mount --bind "$1/resolv.conf" /etc/resolv.conf || die "resolv.conf"
    cnt=$2; shift 4; "$@"; rc=$?
    for t in iptables ip6tables; do $t -L OUTPUT -v -x -n | awk -v t=$t "/nl-count/ {print t, \"count\", \$1, \$2} /nl-drop/ {print t, \"drop\", \$1, \$2}"; done > "$cnt"
    exit $rc' nl-offline "$NS" "$cnt" "$hn" "$fq" sudo -u "$(id -un)" env "$@"
}
# a counter file: one line "<iptables|ip6tables> <count|drop> <packets> <bytes>" for each of the four rules
cnt_ok() { [ -s "$1" ] && [ "$(grep -c -x -E '(iptables|ip6tables) (count|drop) [0-9]+ [0-9]+' "$1")" = 4 ] && [ "$(wc -l < "$1")" = 4 ]; }
cnt_sum() { awk -v k="$2" '$2 == k {s += $3} END {print s + 0}' "$1"; }   # cnt_sum <file> <count|drop>: packets
# a probe must be seen and dropped by the namespace's rules: counted > 0, dropped = counted
probe_count() { # probe_count <name> <counter file>
  local c d
  cnt_ok "$2" || { say "probe $1: FAIL (counter file missing or malformed: $2)"; return 1; }
  c=$(cnt_sum "$2" count); d=$(cnt_sum "$2" drop)
  if [ "$c" -gt 0 ] && [ "$c" = "$d" ]; then say "probe $1: counted $c, dropped $d"
  else say "probe $1: FAIL (counted $c, dropped $d: expected counted > 0 and dropped = counted)"; return 1; fi
}

do_net() {
  mkdir -p "$NS"
  tools_offline
  [ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$DK_OFF")" = none ] || fail net "the tools container has a network"
  docker stop "$DK_TOOLS" > /dev/null 2>&1 || true   # the online one is not used offline
  local h bad=0 c d sk sks=
  # glibc asks nscd through its socket past nsswitch (and nscd resolves in the host's network): with nscd there the
  # counter would not see a lookup. resolved's socket is only printed: the namespace's nsswitch has no resolve module.
  for sk in /var/run/nscd/socket /run/nscd/socket /run/systemd/resolve/io.systemd.Resolve; do sks="$sks $sk $([ -S "$sk" ] && echo yes || echo no);"; done
  say "name-service sockets on the runner:$sks"
  if [ -S /var/run/nscd/socket ] || [ -S /run/nscd/socket ]; then fail net "nscd socket on the runner: glibc would ask nscd past the namespace's nsswitch, its lookups not counted"; fi
  # control: a command that sends nothing (sleep 20, longer than the first retransmission of anything the kernel would
  # send on its own) -> counted 0, dropped 0; any packet here is the namespace's, not a build's, and the counter of the
  # offline builds would not be strict
  if ! ns_run "$NS/count-idle" sleep 20 || ! cnt_ok "$NS/count-idle"; then say "probe idle: FAIL (namespace or counter file $NS/count-idle)"; bad=1
  else c=$(cnt_sum "$NS/count-idle" count); d=$(cnt_sum "$NS/count-idle" drop)
    if [ "$c" = 0 ] && [ "$d" = 0 ]; then say "probe idle (sleep 20 in the namespace): counted 0, dropped 0"
    else say "probe idle: FAIL (counted $c, dropped $d: the namespace itself sends; $(tr '\n' ' ' < "$NS/count-idle"))"; bad=1; fi
  fi
  say "names: runner nsswitch $(grep -E '^[[:space:]]*hosts:' /etc/nsswitch.conf | tr -s ' \t' ' ' || echo 'hosts: none'); namespace nsswitch $(grep -E '^hosts:' "$NS/nsswitch.conf" 2>/dev/null || echo 'hosts: none'), $(wc -l < "$NS/nsswitch.conf" 2>/dev/null) lines of $(wc -l < /etc/nsswitch.conf); namespace hosts $(tr '\n' ';' < "$NS/hosts" 2>/dev/null)"
  local hs="snapshot.debian.org github.com static.rust-lang.org"
  # gpu: both NVIDIA hosts too (the online part made them 0.0.0.0 in the host's hosts file; the namespace has its own)
  if [ "$V" = gpu ]; then hs="$hs developer.download.nvidia.com nvidia.github.io"; fi
  for h in $hs; do
    if ns_run "$NS/count-dns-$h" PATH="$PATH" timeout 10 getent hosts "$h" > /dev/null 2>&1; then echo "probe DNS $h: resolved (network open)"; bad=1; else echo "probe DNS $h: no answer, as expected"; fi
    probe_count "DNS $h" "$NS/count-dns-$h" || bad=1
    if ns_run "$NS/count-tcp-$h" PATH="$PATH" curl -s -m 10 -o /dev/null "https://$h/" 2>/dev/null; then echo "probe TCP $h: connected (network open)"; bad=1; else echo "probe TCP $h: no connection, as expected"; fi
    probe_count "TCP $h" "$NS/count-tcp-$h" || bad=1
  done
  # positive control: outside the namespace the network is there (the runner keeps its connection; a failure here means
  # the probes above prove nothing)
  if curl -s -m 15 -o /dev/null https://github.com/; then echo "control: outside the namespace https://github.com/ answers"; else echo "control FAIL: no network outside the namespace either"; bad=1; fi
  say "network cut (namespace, counted + dropped): probes $([ $bad = 0 ] && echo 'all refused, counted and dropped, control reachable' || echo FAIL)"
  [ $bad = 0 ] || fail net "a probe reached the network"
}

do_build() {
  mkdir -p "$NS"; rm -f "$NS/count-build"
  NL_BUNDLE_FPR=$(cat "$T/bkey.fpr") NL_BUNDLE_KEYRING=$T/bkeyring.gpg "$top/ci/bundle.sh" verify "$B" --tree "$top" | tee -a "$SUM"
  # the agent first (it needs no tools tree of mkosi): the dist of the probe and of the build below is the one built here
  # (the bundle carries agent-inputs/dist only in the interim, without the agent's offline inputs)
  local dist=$B/agent-inputs/dist
  if [ -x "$top/agent/tools/offline-inputs.sh" ]; then
    "$top/agent/tools/offline-inputs.sh" verify "$B/agent-inputs" || fail build "offline-inputs.sh verify"
    # the agent built offline from the bundle (offline-inputs.sh install prints the environment for build-release.sh), in
    # the agent's container image with no network at all (--network none, read back): the C toolchain is the online one
    docker rm -f "$DK_AOFF" > /dev/null 2>&1 || true
    docker run -d "${DCPU[@]}" --name "$DK_AOFF" --network none -v "$top:$top" -v "$T:$T" -v "$TB:$TB" -w "$top/agent" "$DK_AIMG" sleep infinity > /dev/null ||
      fail build "docker run $DK_AIMG --network none"
    [ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$DK_AOFF")" = none ] || fail build "the agent container $DK_AOFF has a network"
    "$top/ci/agent-toolchain.sh" check docker exec "$DK_AOFF" | tee -a "$SUM" || fail build "the C toolchain of $DK_AOFF is not agent/c-toolchain.pins"
    mkdir -p "$T/agent-home-offline"; agent_env "$T/agent-home-offline"
    rc=0; docker exec -u "$(id -u):$(id -g)" "${AE[@]}" "$DK_AOFF" bash -c "eval \"\$('$top/agent/tools/offline-inputs.sh' install '$B/agent-inputs' '$T/agent-tools')\" && OUT='$T/dist-offline' ./build-release.sh" > "$T/agent-offline.log" 2>&1 || rc=$?
    [ "$rc" = 0 ] || failtail "$T/agent-offline.log" build "agent offline build (offline-inputs.sh install, build-release.sh) rc=$rc"
    "$top/ci/agent-toolchain.sh" comment "$T/dist-offline/foil-agent" docker exec "$DK_AOFF" | tee -a "$SUM" || fail build "agent .comment of the offline dist"
    "$top/ci/agent-toolchain.sh" record "$T/dist-offline/C-TOOLCHAIN" docker exec "$DK_AOFF" || fail build "agent-toolchain.sh record (offline dist)"
    say "agent built offline in $DK_AOFF (network $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$DK_AOFF"))"
    docker rm -f "$DK_AOFF" > /dev/null 2>&1 || true
    dist=$T/dist-offline
  fi
  # the agent built offline is the online one: SHA256SUMS of both dists equal (the binaries and the SBOM of the agent).
  # Only an agent built here is compared; the interim dist is the online one carried in the bundle (a comparison of a
  # copy with itself proves nothing): refused when the counted run requires the offline agent, else named as interim
  local on off
  if [ "$dist" = "$T/dist-offline" ]; then
    on=$(cat "$T/agent-dist-online.sha256" 2>/dev/null); off=$(sha256sum < "$dist/SHA256SUMS" | cut -c1-64)
    [ -n "$on" ] && [ "$on" = "$off" ] || fail build "agent dist online != offline: online ${on:-missing}, offline $off ($dist)"
    say "agent dist online = offline: $off"
  elif [ "${NL_OFFLINE_AGENT_REQUIRED:-0}" = 1 ]; then
    fail build "agent not built offline (NL_OFFLINE_AGENT_REQUIRED=1, the dist is the bundle's carried one: $dist)"
  else
    say "agent dist: interim (online carried), not compared"
  fi
  # probe: after the clean there is no tools tree; an offline build without the bundle's is refused, never rebuilt
  if out=$(env NL_OFFLINE=1 NL_BUNDLE="$B" NL_PKGCACHE="$B/pkgcache" NL_BUNDLE_FPR="$(cat "$T/bkey.fpr")" NL_BUNDLE_KEYRING="$T/bkeyring.gpg" \
      TOOLS_EXEC="$OFFLINE_TOOLS" SOURCE_DATE_EPOCH="$(git -C "$top" log -1 --format=%ct)" "$top/images/debian/tools/build-all.sh" \
      --profile "$top/profiles/k8s-worker" --variant "$V" --version 1 --epoch 1 --min-version 1 --keys "$KEYS" \
      --agent-dist "$dist" --cache "$B/apt-cache" --output-dir "$T/out-offline" --check-inputs 2>&1); then
    fail build "probe t-no-tools-tree: an offline build without a restored tools tree was not refused"
  fi
  grep -q 'no restored tools tree' <<< "$out" || fail build "probe t-no-tools-tree: refused for another reason: $(echo "$out" | tail -n 1)"
  say "probe t-no-tools-tree: refused before any step ($(echo "$out" | tail -n 1))"
  tools_restore
  # regression probe a-host-sqv: the apt chain on the runner host itself, sqv of the restored tools tree through its own
  # loader (the path of a build host without TOOLS_EXEC, build-all.sh's; its "--library-path ..." once read as options
  # of the verify): the intact bundle passes with that sqv, a changed .deb on a hard-link copy is refused
  local tt=$top/profiles/k8s-worker/mkosi.tools hs out db
  hs=("$tt/usr/lib64/ld-linux-x86-64.so.2" --library-path "$tt/usr/lib/x86_64-linux-gnu" "$tt/usr/bin/sqv")
  out=$(python3 "$top/ci/bundle-apt-verify.py" --bundle "$B" --tree "$top" -- "${hs[@]}" 2>&1) || fail build "probe a-host-sqv: the intact bundle refused: $(tail -n 1 <<< "$out")"
  grep -qx 'APT-VERIFY PASS' <<< "$out" && grep -q "^apt-verify: sqv $tt/usr/lib64/ld-linux" <<< "$out" || fail build "probe a-host-sqv: no PASS with the tools tree's sqv"
  say "probe a-host-sqv: intact bundle PASS on the host, $(grep '^apt-verify: sqv' <<< "$out" | sed 's|^apt-verify: sqv .* (|sqv (|')"
  rm -rf "$T/hostprobe"; cp -al "$B" "$T/hostprobe"
  db=pkgcache/cache/apt/archives/$(ls "$B/pkgcache/cache/apt/archives" | grep '\.deb$' | grep -v '^debian-archive-keyring_' | LC_ALL=C sort | sed -n 1p)
  cp -- "$T/hostprobe/$db" "$T/hostprobe/$db.brk" && mv -f -- "$T/hostprobe/$db.brk" "$T/hostprobe/$db" && printf x >> "$T/hostprobe/$db"
  if out=$(python3 "$top/ci/bundle-apt-verify.py" --bundle "$T/hostprobe" --tree "$top" -- "${hs[@]}" 2>&1); then fail build "probe a-host-sqv: a changed .deb accepted"; fi
  grep -q 'differs from its Packages stanza' <<< "$out" || fail build "probe a-host-sqv: a changed .deb refused for another reason: $(tail -n 1 <<< "$out")"
  say "probe a-host-sqv: a changed .deb refused on the host ($(tail -n 1 <<< "$out"))"; rm -rf "$T/hostprobe"
  mkdir -p "$T/offline-mkosi" && tar -xf "$B/mkosi.tar" -C "$T/offline-mkosi"
  say "apt metadata in the package cache: $(find "$B/pkgcache" -name '*InRelease*' | wc -l) InRelease, $(find "$B/pkgcache" -name '*.deb' | wc -l) .deb"
  mkdir -p "$T/out-offline"
  # NL_BUILD (a build host's root wrapper, its quota and thermal guard) reaches the build in the namespace as it reaches
  # the online one; empty (GitHub Actions): mkosi through sudo env, as before
  ns_run "$NS/count-build" PATH="$T/offline-mkosi/mkosi/bin:$PATH" HOME="$HOME" NL_BUILD="${NL_BUILD:-}" NL_OFFLINE=1 NL_PKGCACHE="$B/pkgcache" TOOLS_EXEC="$OFFLINE_TOOLS" \
    NL_BUNDLE="$B" NL_BUNDLE_FPR="$(cat "$T/bkey.fpr")" NL_BUNDLE_KEYRING="$T/bkeyring.gpg" \
    SOURCE_DATE_EPOCH="$(git -C "$top" log -1 --format=%ct)" "$top/images/debian/tools/build-all.sh" \
    --profile "$top/profiles/k8s-worker" --variant "$V" --version 1 --epoch 1 --min-version 1 \
    --keys "$KEYS" --agent-dist "$dist" --cache "$B/apt-cache" --output-dir "$T/out-offline" > "$T/build-offline.log" 2>&1 \
    || { tail -n 40 "$T/build-offline.log"; fail build "build-all.sh offline"; }
  say "offline apt: Get/Hit lines from the network $(grep -c -E '^(Get|Hit):[0-9]+ (https?|ftp)://' "$T/build-offline.log" || true), signature checks $(grep -c -i -E 'signature|InRelease' "$T/build-offline.log" || true)"
  say "network counter during the offline build: $(tr '\n' ' ' < "$NS/count-build" 2>/dev/null || echo 'MISSING')"
  dfp "after the offline build"
}

do_compare() {
  local f p=0 d=0 fs=("$NS/count-build")   # the agent was built offline in a container with --network none (do_build)
  # the counters first: a missing or malformed file means the offline build was not counted, never "0 packets"
  for f in "${fs[@]}"; do
    cnt_ok "$f" || fail compare "network counter $f missing or malformed: the offline build was not counted"
    p=$((p + $(cnt_sum "$f" count))); d=$((d + $(cnt_sum "$f" drop)))
  done
  [ "$p" = "$d" ] || fail compare "network counters disagree: counted $p, dropped $d"
  python3 "$top/images/debian/tools/build-manifest.py" compare "$T/manifest-online.txt" "$T/out-offline/build-manifest.txt" | tee "$T/compare.txt" | tail -n 3
  rc=${PIPESTATUS[0]}
  say "compare online <-> offline: $(tail -n 1 "$T/compare.txt") (rc $rc); network packets during the offline build: $p"
  [ "$rc" = 0 ] || fail compare "the offline image differs from the online one"
  [ "$p" = 0 ] || fail compare "the offline build sent $p packets"
  echo "=== BEGIN build-manifest.txt"; cat "$T/out-offline/build-manifest.txt"; echo "=== END build-manifest.txt"
  f=$top/images/debian/mkosi/apt-pin-inputs.json; [ ! -f "$f" ] || { echo "=== BEGIN apt-pin-inputs.json"; sed '$a\' "$f"; echo "=== END apt-pin-inputs.json"; }
  dfp "end of the stage"
  say "OFFLINE STAGE PASS (variant $V)"
}

case ${1:-} in
  bundle) do_bundle ;; probes) do_probes ;; clean) do_clean ;; net) do_net ;; build) do_build ;; compare) do_compare ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
