# SPDX-License-Identifier: Apache-2.0
# One configured node across the scenarios after ApplyConfig (sourced after vm.sh, check.sh, channel.sh; bash).
# Phases and checks follow the release test of a Kubernetes node (boot check, rollback, stage), for one guest
# without Kubernetes. The node $NODE (default n2) is installed and configured once by node_ensure and then kept
# between scenarios; each scenario states the release it starts from and runs the earlier ones when the node is not
# there yet, so a scenario can also run alone (tests/run.sh rollback).
#
#   node_ensure <step>         the node is up and went through the steps up to <step> (config ab rollback t7 epoch,
#                              lib/steps.sh); otherwise it runs the missing steps first (a fresh install for config)
#   node_booted                booted image version (GetInfo)
#   node_us                    GetUpdateStatus
#   node_stage <V>             StageUpdate V, wait for Staged|Failed; prints the phase
#   node_reboot <label> <role> <foilctl args...>
#                              a reboot-like RPC (reboot, rollback, ...); waits for the new boot; one result line
#                              "shutdown" with request -> "reboot: Restarting system" on the stamped serial <= MAXSHUT
#   NTP (default 0.debian.pool.ntp.org,1.debian.pool.ntp.org, Debian's pool): NodeConfig.time, so health is Pass
#   (time-synced) after ApplyConfig, without exceptions.

NODE=${NODE:-n2}
NTP=${NTP:-0.debian.pool.ntp.org,1.debian.pool.ntp.org}
MAXSHUT=${MAXSHUT:-65}

node_booted() { CTL_T=10 ctl "$NODE" reader info | grep -m1 -o 'image_version: "[^"]*"' | cut -d'"' -f2; }
node_us() { ctl "$NODE" reader update-status; }
node_gen() { ctl "$NODE" reader config | awk '/generation:/ { gsub(/[^0-9]/, "", $2); print $2; exit }'; }
# phase of the stage block of GetUpdateStatus (empty: nothing staged)
node_stage_phase() { node_us | sed -n '/stage: Some/,/boot: Some/p' | grep -o 'phase: [A-Za-z]*' | head -1 | cut -d' ' -f2; }

node_stage() {
  local t0; t0=$(date +%s)
  ctl "$NODE" controller --target "$1" stage | grep -E 'operation_id|code|message' | tr -s ' ' | paste -sd' ' >&2
  local p="" i
  for i in $(seq 1 300); do p=$(node_stage_phase); case $p in Staged|Failed) break ;; esac; sleep 3; done
  echo "stage $1: phase=${p:-none} after $(( $(date +%s) - t0 ))s" >&2
  # a stage that did not reach Staged: keep the update status and the agent's journal, and print the stage block
  # (phase, error, message) and the journal's tail on stderr, so the reason is in the run log (a CI job keeps nothing else)
  if [ "$p" != Staged ]; then
    node_us > "${LOGS:?}/stage_$1.us.txt" 2>&1
    ctl "$NODE" controller --unit foil-agent.service --limit 300 journal > "$LOGS/stage_$1.agent.txt" 2>&1
    # the service manager's side: the installer unit, the ESP mount and its automount, and PID 1 (jobs, stops, idle)
    local u; for u in "foil-install@$1.service" boot.mount boot.automount init.scope; do
      ctl "$NODE" controller --unit "$u" --limit 300 journal > "$LOGS/stage_$1.$u.txt" 2>&1; done
    local blk er dt cl ni
    blk=$(sed -n '/stage: Some/,/boot: Some/p' "$LOGS/stage_$1.us.txt" | tr -s ' \n' ' ')
    er=$(echo "$blk" | grep -oE 'error: [A-Za-z]+' | head -1 | cut -d' ' -f2); dt=$(echo "$blk" | grep -oE 'detail: "[^"]*"' | head -1)
    # the agent's class of a download error (agent update.rs): "(after N retries)" = retries exhausted (stalls, 5xx,
    # resets); otherwise a fatal error without retry, its source named in the detail (TLS: ..., HTTP 4xx, bytes limit, io)
    case "$dt" in *"retries)"*) cl=retry-exhausted ;; *"TLS: "*) cl=fatal:tls ;; *"HTTP "*) cl=fatal:http ;; *limit*) cl=fatal:size ;;
      *) cl=$([ "$er" = Download ] && echo fatal:other || echo "not-a-download") ;; esac
    ni=$(grep -a -c 'download interrupted' "$LOGS/stage_$1.agent.txt" 2>/dev/null || true)
    echo "stage $1 not staged: error=${er:-?} class=$cl retries-logged=${ni:-0} ${dt:-no detail}" >&2
    echo "stage $1 block: ${blk:0:1500}" >&2
    echo "--- foil-agent journal (last 40 lines) during stage $1" >&2; tail -n 40 "$LOGS/stage_$1.agent.txt" | cut -c1-300 >&2
    for u in "foil-install@$1.service" boot.mount boot.automount; do
      echo "--- journal of $u (last 30 lines)" >&2; tail -n 30 "$LOGS/stage_$1.$u.txt" | cut -c1-300 >&2; done
    echo "--- PID 1: jobs, stops and mounts of the stage (last 60 matching lines)" >&2
    grep -a -E 'foil-install|boot\.(mount|automount)|[Jj]ob |cancel|[Ee]xpir|[Uu]nmount|idle|Stopp|Mount' "$LOGS/stage_$1.init.scope.txt" | tail -n 60 | cut -c1-300 >&2
  fi
  echo "$p"
}

node_reboot() {
  local lb=$1 role=$2; shift 2
  local ser; ser=$(vm_serial "$NODE"); local b0 l0 t0s t0
  b0=$(vm_boot_id "$NODE"); l0=$(wc -l < "$ser"); t0s=$(date -u +%H:%M:%S.%3N); t0=$(date +%s)
  log "$lb: $NODE $role $* (boot $b0)"
  ctl "$NODE" "$role" "$@" | grep -E 'code|message|from|to|boot' | tr -s ' ' | paste -sd' ' > "$LOGS/${lb}.rpc.txt"
  if ! vm_wait_new_boot "$NODE" "$b0" "${API_TIMEOUT:-600}"; then
    res "$NODE" "shutdown:$lb" FAIL "no new boot in ${API_TIMEOUT:-600}s ($(cat "$LOGS/${lb}.rpc.txt"))"; return 1
  fi
  tail -n +"$((l0 + 1))" "$ser" > "$LOGS/${lb}.serial.log"
  local tr d w
  tr=$(grep -a -m1 -E 'reboot: Restarting system' "$LOGS/${lb}.serial.log" | cut -c1-12)
  d=$(python3 -I -c 'import sys, datetime as d
f = lambda s: d.datetime.strptime(s, "%H:%M:%S.%f")
x = (f(sys.argv[2]) - f(sys.argv[1])).total_seconds()
print("%.1f" % (x + 86400 if x < 0 else x))' "$t0s" "$tr" 2>/dev/null)
  w="timed-out=$(grep -a -c -i 'timed out' "$LOGS/${lb}.serial.log") FAILED=$(grep -a -c 'FAILED' "$LOGS/${lb}.serial.log")"
  if [ -n "$d" ] && awk -v d="$d" -v m="$MAXSHUT" 'BEGIN { exit !(d <= m) }'; then
    res "$NODE" "shutdown:$lb" PASS "request->Restarting ${d}s (<= ${MAXSHUT}s) $w; new boot after $(( $(date +%s) - t0 ))s"
  else
    res "$NODE" "shutdown:$lb" FAIL "request->Restarting ${d:-none}s (> ${MAXSHUT}s or missing) $w"
  fi
}

# usrhash the boot of version V must run with: release 1 from IMAGE (its UKI is on the ESP of the disk image), the
# others from the channel's UKI (listed in the signed SHA256SUMS)
node_want_usrhash() {
  if [ "$1" = "${BASE_VERSION:-1}" ]; then grep -a -o -m1 'usrhash=[0-9a-f]*' "$IMAGE" | head -1 | cut -d= -f2
  else channel_usrhash "$1"; fi
}

# node_config: fresh install of $NODE from IMAGE, then ApplyConfig with network (DHCP on the user-net NIC, matched by
# MAC), NTP and the channel; health must be Pass (no exception) on the same boot
node_config() {
  local n=$NODE t0
  vm_stop "$n" --wipe
  t0=$(date +%s.%N)
  vm_start "$n" "$IMAGE" --sb on --enroll "${ENROLL:-auto}"
  vm_wait_api "$n" "${API_TIMEOUT:-600}" || { res "$n" api FAIL "no answer in ${API_TIMEOUT:-600}s"; return 1; }
  res "$n" api PASS "agent answers after $(since "$t0")s"
  local g; g=$(node_gen)
  ctl "$n" controller --hostname "harness-$n" --mac "$(vm_mac "$n")" --dhcp --ntp "$NTP" $(channel_args) \
    --expected-generation "${g:-1}" apply > "$LOGS/apply_$n.txt"
  local ng rr; ng=$(grep -m1 -o 'generation: [0-9]*' "$LOGS/apply_$n.txt" | cut -d' ' -f2)
  rr=$(grep -m1 -o 'reboot_required: [a-z]*' "$LOGS/apply_$n.txt" | cut -d' ' -f2)
  if [ -n "$ng" ] && [ "$ng" -gt "${g:-0}" ] 2>/dev/null; then
    res "$n" apply PASS "generation ${g:-?} -> $ng, reboot_required=${rr:-?}, ntp=$NTP, channel 10.0.2.2:$CHANNEL_PORT/"
  else
    res "$n" apply FAIL "$(tr -s ' \n' ' ' < "$LOGS/apply_$n.txt" | cut -c1-300)"; return 1
  fi
  [ "$rr" = true ] && node_reboot config_reboot controller --reason "harness: reboot_required after ApplyConfig" reboot
  boot_check "$n" config --sb on --version "${BASE_VERSION:-1}" --usrhash "$(node_want_usrhash "${BASE_VERSION:-1}")"
}

# state of the node between scenarios: the last step done on it (config, ab, rollback, t7, epoch)
node_state() { cat "$(vm_dir "$NODE")/state" 2>/dev/null; }
node_set_state() { echo "$1" > "$(vm_dir "$NODE")/state"; }

# node_ensure <step>: the node has gone through the steps up to <step> (config < ab < rollback < t7 < epoch); runs the
# missing ones in order, each with its own result lines (under its own scenario name). A step returns non-zero when the
# node is not in the state the next step needs; node_ensure then returns 1 and the scenario writes no checks of its own.
NODE_STEPS="config ab rollback t7 epoch"
node_step_index() { local i=0 s; for s in $NODE_STEPS; do i=$((i + 1)); [ "$s" = "$1" ] && { echo $i; return; }; done; echo 0; }
# node_failed <step>: remember a step that failed in this run (node_ensure does not repeat it)
node_failed() { echo "$1" >> "${WORK:?}/node_failed_steps"; return 1; }

node_ensure() {
  local want have hi wi s i=0
  have=$(node_state)
  { [ -e "$(vm_dir "$NODE")/qemu.pid" ] && kill -0 "$(cat "$(vm_dir "$NODE")/qemu.pid")" 2>/dev/null; } || have=""
  hi=$(node_step_index "$have"); wi=$(node_step_index "$1")
  [ "$hi" -le "$wi" ] || hi=0          # the node went past the wanted step: start over from a fresh install
  for s in $NODE_STEPS; do
    i=$((i + 1)); [ "$i" -gt "$hi" ] && [ "$i" -le "$wi" ] || continue
    # a step that failed in this run is not repeated: the node is in an unknown state, and repeating may test
    # something else (a repeated t7 would stage the release the node has rolled back from -> refused)
    if grep -qx "$s" "${WORK:?}/node_failed_steps" 2>/dev/null; then
      res "$NODE" "needs:$s" FAIL "step $s failed earlier in this run; not repeated (fix it and rerun)"; return 1
    fi
    log "node $NODE: step $s first (needed before $SCENARIO)"
    local sc=$SCENARIO; SCENARIO=$s; "node_step_$s"; local rc=$?; SCENARIO=$sc
    [ $rc = 0 ] || { node_failed "$s"; return 1; }
  done
  return 0
}
node_step_config() { channel_need || return 1; node_config && node_set_state config; }

# the scenarios after ApplyConfig need the channel: without CHANNEL they are skipped (one SKIP line), never PASS
channel_need() {
  if [ -z "${CHANNEL:-}" ]; then res "$NODE" channel SKIP "CHANNEL not set (releases ${AB_VERSION:-2} ${T7_VERSION:-3} ${EPOCH_VERSION:-4})"; return 1; fi
  [ -n "${CHANNEL_PORT:-}" ] || channel_up
}
