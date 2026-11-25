# SPDX-License-Identifier: Apache-2.0
# Steps of the scenarios after ApplyConfig on the node $NODE (sourced after node.sh; bash). Each step is one phase of
# the release test of a Kubernetes node (A/B, rollback, T7, epoch) for one guest without Kubernetes: the same RPCs
# and expectations; refusal codes and record names from lib/codes.sh. Every boot change ends with boot_check (lib/check.sh)
# against the expected version and its usrhash (release 1: IMAGE; the others: the channel's UKI, listed in the signed
# SHA256SUMS), health Pass without exceptions. A step marks the node (node_set_state) only when it ends in the state
# the next step starts from.
# Releases (environment): BASE_VERSION (1, the IMAGE), AB_VERSION (2: same commit, version only), T7_VERSION (3: a
# release whose boot check fails, see tests/README.md), EPOCH_VERSION (4: PCR epoch EPOCH 2, min version 4).

AB_VERSION=${AB_VERSION:-2}; T7_VERSION=${T7_VERSION:-3}; EPOCH_VERSION=${EPOCH_VERSION:-4}; EPOCH=${EPOCH:-2}
BASE_VERSION=${BASE_VERSION:-1}

# step_release_needed <V>: the channel lists release V, else one FAIL line
step_release_needed() { channel_has "$1" && return 0; res "$NODE" "release-$1" FAIL "release $1 not in CHANNEL $CHANNEL"; return 1; }

# A/B: stage AB_VERSION, reboot with --expect-staged; booted AB_VERSION, Confirmed, the agent's audit line
node_step_ab() {
  local v=$AB_VERSION p; step_release_needed "$v" || return 1
  p=$(node_stage "$v")
  [ "$p" = Staged ] || { res "$NODE" stage FAIL "release $v: phase=${p:-none}"; return 1; }
  res "$NODE" stage PASS "Staged $v"
  node_reboot ab controller --expect-staged "$v" --reason "harness: A/B $BASE_VERSION->$v" reboot || return 1
  boot_check "$NODE" ab --version "$v" --usrhash "$(node_want_usrhash "$v")"
  local a; a=$(ctl "$NODE" controller --unit foil-agent.service --limit 2000 journal | audit_confirmed "$v" | cut -c1-200)
  [ -n "$a" ] && res "$NODE" audit PASS "$a" || res "$NODE" audit FAIL "no 'update confirmed version=$v' in the foil-agent journal"
  [ "$(node_booted)" = "$v" ] && node_set_state ab
}

# Rollback AB_VERSION -> BASE_VERSION by the operator RPC; a wrong expect_booted is refused first
node_step_rollback() {
  local neg; neg=$(ctl "$NODE" controller --expect-booted "$BASE_VERSION" --reason "harness: negative" rollback \
    | grep -oE 'code: [A-Za-z]+|message: "[^"]*"' | paste -sd' ')
  echo "$neg" | grep -q -E "$CODE_EXPECT_MISMATCH" && res "$NODE" negative PASS "expect_booted=$BASE_VERSION: $neg" \
    || res "$NODE" negative FAIL "expect_booted=$BASE_VERSION: ${neg:-accepted}"
  node_reboot rollback controller --expect-booted "$AB_VERSION" --reason "harness: rollback $AB_VERSION->$BASE_VERSION" rollback || return 1
  boot_check "$NODE" rollback --version "$BASE_VERSION" --usrhash "$(node_want_usrhash "$BASE_VERSION")"
  local ri; ri=$(rollback_block "$LOGS/rollback_$NODE.us.txt")
  echo "$ri" | grep -q -E "$RB_OPERATOR" && res "$NODE" record PASS "${ri:0:400}" || res "$NODE" record FAIL "no Operator rollback record: ${ri:-none}"
  [ "$(node_booted)" = "$BASE_VERSION" ] && node_set_state rollback
}

# T7: stage the broken release, reboot into it; the node must come back to BASE_VERSION by itself (boot counting: three
# failed boot checks), without a Rollback RPC; staging the abandoned release again is refused
node_step_t7() {
  local v=$T7_VERSION p; step_release_needed "$v" || return 1
  p=$(node_stage "$v")
  [ "$p" = Staged ] || { res "$NODE" stage FAIL "release $v: phase=${p:-none}"; return 1; }
  res "$NODE" stage PASS "Staged $v (broken release)"
  local ser l0 t0 seen="" b c i; ser=$(vm_serial "$NODE"); l0=$(wc -l < "$ser"); t0=$(date +%s)
  ctl "$NODE" controller --expect-staged "$v" --reason "harness: T7 broken release" reboot > "$LOGS/t7.rpc.txt"
  for i in $(seq 1 $(( ${T7_TIMEOUT:-1800} / 10 ))); do
    sleep 10
    b=$(node_booted 2>/dev/null); c=$(CTL_T=10 node_us 2>/dev/null | grep -m1 -o 'confirmation: [A-Za-z]*' | cut -d' ' -f2)
    [ "$b$c" != "$seen" ] && { log "T7 +$(( $(date +%s) - t0 ))s booted=${b:-?} ${c:-?}"; seen="$b$c"; }
    [ "$b" = "$BASE_VERSION" ] && [ "$c" = Confirmed ] && [ $(( $(date +%s) - t0 )) -gt 120 ] && break
  done
  local dt=$(( $(date +%s) - t0 )) tries ri
  tail -n +"$((l0 + 1))" "$ser" > "$LOGS/t7.serial.log"
  tries=$(grep -a -c 'boot-check FAIL' "$LOGS/t7.serial.log")
  node_us > "$LOGS/t7_us.txt"; ri=$(rollback_block "$LOGS/t7_us.txt")
  # Expected path: the gate's timeout, not a fail-fast. The T7 overlay fails foil-config, which is not a hard failure of the
  # gate (hard: usr-verity, var-mounted, kubelet-crashloop, gpu; agent main.rs), and there is no kubelet without a join,
  # so each of the three tries waits the gate's 300 s (foil-agent boot-check --timeout). The node is back on BASE_VERSION
  # within [3 x 300, 3 x (300 + T7_BOOT_MAX)] s of the reboot, T7_BOOT_MAX (default 60) for shutdown + boot + API per try
  # (seen: about 10 s); faster is a fail-fast that must not happen here, slower is a FAIL too.
  local lo=900 hi=$(( 3 * (300 + ${T7_BOOT_MAX:-60}) )) at; at=$(echo "$ri" | grep -oE 'attempts: [0-9]+' | head -1 | cut -d' ' -f2)
  if [ "$b" = "$BASE_VERSION" ] && [ "$c" = Confirmed ] && echo "$ri" | grep -q -E "$RB_EXHAUSTED" && [ "${at:-}" = 3 ] &&
     [ "$dt" -ge $lo ] && [ "$dt" -le $hi ]; then
    res "$NODE" rollback PASS "back to $BASE_VERSION by itself in ${dt}s (window ${lo}-${hi}s: 3 gate timeouts), boot-check FAIL on serial: $tries; $(echo "$ri" | grep -oE 'reason_code: [A-Za-z]+|attempts: [0-9]+' | paste -sd' ')"
  else
    res "$NODE" rollback FAIL "booted=${b:-?} ${c:-?} after ${dt}s (window ${lo}-${hi}s), attempts=${at:-?}, boot-check FAIL on serial: $tries; ${ri:-no rollback record}"
    return 1
  fi
  boot_check "$NODE" t7_after --prev failed --version "$BASE_VERSION" --usrhash "$(node_want_usrhash "$BASE_VERSION")"
  local re rp
  re=$(ctl "$NODE" controller --target "$v" stage | grep -oE 'code: [A-Za-z]+|message: "[^"]*"' | paste -sd' ')
  sleep 5; rp=$(node_us | sed -n '/stage: Some/,/boot: Some/p' | grep -oE 'phase: [A-Za-z]+|error: [A-Za-z_]+|STAGE_ERROR_[A-Z_]+' | paste -sd' ')
  echo "$re $rp" | grep -q -E "$CODE_ROLLED_BACK" && res "$NODE" restage PASS "release $v refused: $re $rp" \
    || res "$NODE" restage FAIL "release $v: $re $rp"
  [ "$(node_booted)" = "$BASE_VERSION" ] && node_set_state t7
}

# var-epoch: release EPOCH_VERSION raises the PCR epoch (enroll before the reboot); RaiseMinVersion is operator-only
# and bound to the booted release; afterwards an older release is refused and /var still opens after a reboot
node_step_epoch() {
  local v=$EPOCH_VERSION p; step_release_needed "$v" || return 1
  p=$(node_stage "$v")
  [ "$p" = Staged ] || { res "$NODE" stage FAIL "release $v: phase=${p:-none}"; return 1; }
  ctl "$NODE" controller --limit 300 --unit "foil-var-epoch@enroll-$EPOCH.service" journal > "$LOGS/epoch_enroll.txt"
  res "$NODE" stage PASS "Staged $v (enroll epoch $EPOCH)"
  node_reboot epoch controller --expect-staged "$v" --reason "harness: var-epoch $EPOCH" reboot || return 1
  boot_check "$NODE" epoch --version "$v" --usrhash "$(node_want_usrhash "$v")"
  local d1 d0 d2 r mv
  # code and message: CODE_DENIED matches both ("... is not allowed for role R; allowed: operator")
  d1=$(ctl "$NODE" reader --expect-booted "$v" raise | grep -oE 'code: [A-Za-z]+|message: "[^"]*"' | paste -sd' ')
  d0=$(ctl "$NODE" controller --expect-booted "$v" raise | grep -oE 'code: [A-Za-z]+|message: "[^"]*"' | paste -sd' ')
  d2=$(ctl "$NODE" operator --expect-booted "$BASE_VERSION" raise | grep -oE 'code: [A-Za-z]+|message: "[^"]*"' | paste -sd' ')
  if echo "$d1" | grep -q -E "$CODE_DENIED" && echo "$d0" | grep -q -E "$CODE_DENIED" && echo "$d2" | grep -q -E "$CODE_EXPECT_MISMATCH"; then
    res "$NODE" raise-negative PASS "reader: $d1; controller: $d0; operator expect_booted=$BASE_VERSION: $d2"
  else
    res "$NODE" raise-negative FAIL "reader: ${d1:-accepted}; controller: ${d0:-accepted}; operator expect_booted=$BASE_VERSION: ${d2:-accepted}"
  fi
  r=$(ctl "$NODE" operator --expect-booted "$v" raise | tr -s ' \n' ' ' | cut -c1-200)
  mv=$(node_us | sed -n '/min_version: Some/,/}/p' | grep -o 'image_version: "[^"]*"' | cut -d'"' -f2)
  [ "$mv" = "$v" ] && res "$NODE" raise PASS "floor $v" || res "$NODE" raise FAIL "floor=${mv:-none} ($r)"
  local s1 s1p
  s1=$(ctl "$NODE" controller --target "$BASE_VERSION" stage | grep -oE 'code: [A-Za-z]+|message: "[^"]*"' | paste -sd' ')
  sleep 5; s1p=$(node_us | sed -n '/stage: Some/,/boot: Some/p' | grep -oE 'BELOW_MIN_VERSION|BelowMinVersion' | head -1)
  echo "$s1 $s1p" | grep -q -E "$CODE_BELOW_MIN" && res "$NODE" old-refused PASS "release $BASE_VERSION: $s1 $s1p" \
    || res "$NODE" old-refused FAIL "release $BASE_VERSION: $s1 $s1p"
  node_reboot epoch_reboot controller --reason "harness: var-epoch floor kept" reboot || return 1
  boot_check "$NODE" epoch_reboot --version "$v" --usrhash "$(node_want_usrhash "$v")"
  mv=$(node_us | sed -n '/min_version: Some/,/}/p' | grep -o 'image_version: "[^"]*"' | cut -d'"' -f2)
  [ "$mv" = "$v" ] && res "$NODE" floor-kept PASS "floor $v after a reboot, /var opened (boot_check var_protection)" \
    || res "$NODE" floor-kept FAIL "floor=${mv:-none} after a reboot"
  [ "$(node_booted)" = "$v" ] && node_set_state epoch
}
