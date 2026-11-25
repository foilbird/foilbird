#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Offline samples of the health rules of lib/check.sh (health_summary, health_verdict, clock_pending); no guest, no
# image. Samples are in the format of `foilctl reader health`. Run: bash tests/lib/check_selftest.sh (exit 0 = all PASS).
set -u
here=$(cd "$(dirname "$0")" && pwd)
die() { echo "selftest: $*" >&2; exit 2; }
. "$here/check.sh"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
NTP0='ntp system=[] link=[] current=-'
NTP1='ntp system=[0.debian.pool.ntp.org, 1.debian.pool.ntp.org] link=[] current=-'

# health <file> <overall> <name:status:detail>...
health() {
  local f=$1 o=$2 c n s t; shift 2
  { echo "GetHealthResponse {"; echo "    overall: $o,"; echo "    checks: ["
    for c in "$@"; do n=${c%%:*}; t=${c#*:}; s=${t%%:*}; t=${t#*:}
      echo "        HealthCheck {"; echo "            name: \"$n\","; echo "            status: $s,"
      echo "            detail: \"$t\","; echo "        },"; done
    echo "    ],"; echo "}"; } > "$f"
}
BASE=("usr-verity:Pass:/dev/mapper/usr dm-verity" "containerd:Pass:containerd.service: ActiveState=active Result=success"
      "nvidia-cdi:Skipped:foil-nvidia-cdi.service: ActiveState=inactive Result=success ConditionResult=no" "no-failed-units:Pass:0 failed units"
      "kubelet-healthy:Skipped:node not joined yet: kubelet not required")
# a k8s-worker image without the CDI unit (cp): systemd's LoadState=not-found, not applicable
BASE_CP=("${BASE[@]/#nvidia-cdi:*/nvidia-cdi:Skipped:foil-nvidia-cdi.service: not in this image (LoadState=not-found)}")
total=0 failed=0
# case <label> <file> <nontp> <want verdict: accept[:allowance]|reject> <want clock_pending: wait|nowait>
case_() {
  local lb=$1 f=$2 nt=$3 want=$4 wc=$5 hs a rc=0 cp=nowait got
  hs=$(health_summary "$f"); a=$(health_verdict "$hs" "$nt") || rc=1
  clock_pending "$f" && cp=wait
  if [ $rc = 0 ]; then got=accept${a:+:${a# allowed=}}; else got=reject; fi
  total=$((total + 1))
  if [ "$got" = "$want" ] && [ "$cp" = "$wc" ]; then echo "PASS $lb: $got $cp ($hs)"
  else failed=$((failed + 1)); echo "FAIL $lb: got $got $cp, want $want $wc ($hs)"; fi
}

health $d/pass Pass "${BASE[@]}" "time-synced:Pass:clock synchronized; $NTP1"
case_ "all Pass" $d/pass 0 accept nowait

health $d/cp Pass "${BASE_CP[@]}" "time-synced:Pass:clock synchronized; $NTP1"
grep -q 'not in this image (LoadState=not-found)' $d/cp || die "BASE_CP: the nvidia-cdi sample was not replaced"
case_ "cp image without the CDI unit (LoadState=not-found)" $d/cp 0 accept nowait

health $d/k8s_install Pending "${BASE[@]}" "time-synced:Pending:first join waits for time sync; $NTP0"
case_ "k8s-worker install, Pending ntp=[], --no-ntp-ok" $d/k8s_install 1 accept:time-synced:pending-first-join nowait
case_ "k8s-worker install, Pending ntp=[], without --no-ntp-ok" $d/k8s_install 0 reject nowait

health $d/k8s_ntp Pending "${BASE[@]}" "time-synced:Pending:first join waits for time sync; $NTP1"
case_ "Pending with NTP configured (still after the wait)" $d/k8s_ntp 0 reject wait
case_ "Pending with NTP configured, even with --no-ntp-ok" $d/k8s_ntp 1 reject wait

health $d/base_install Warn "${BASE[@]}" "time-synced:Warn:clock not synchronized; $NTP0"
case_ "base install, Warn ntp=[], --no-ntp-ok" $d/base_install 1 accept:time-synced:no-ntp-configured nowait

health $d/base_ntp Warn "${BASE[@]}" "time-synced:Warn:clock not synchronized; $NTP1"
case_ "Warn with NTP configured (still after the wait)" $d/base_ntp 0 reject wait

health $d/pend_warn Pending "${BASE[@]}" "time-synced:Pending:first join waits for time sync; $NTP0" "esp-writable:Warn:read-only"
case_ "time-synced Pending ntp=[] + another Warn" $d/pend_warn 1 reject nowait

health $d/pend_fail Pending "${BASE[@]}" "time-synced:Pending:first join waits for time sync; $NTP0" "var-key-slots:Fail:unknown LUKS key slot 3"
case_ "time-synced Pending ntp=[] + a Fail" $d/pend_fail 1 reject nowait

health $d/other_pend Pending "usr-verity:Pass:/dev/mapper/usr dm-verity" "containerd:Pending:containerd.service: ActiveState=activating" \
  "time-synced:Pass:clock synchronized; $NTP0"
case_ "another check Pending, time-synced Pass" $d/other_pend 1 reject nowait

health $d/two_pend Pending "${BASE[@]}" "time-synced:Pending:first join waits for time sync; $NTP0" "containerd:Pending:activating"
case_ "time-synced Pending ntp=[] + another Pending" $d/two_pend 1 reject nowait

health $d/blocked Fail "${BASE[@]}" "time-synced:Fail:first join blocked: clock not synchronized (180s); $NTP0"
case_ "time-synced Fail (wait timed out), --no-ntp-ok" $d/blocked 1 reject nowait

# prev_failed_starts: only PID 1 counts (_PID, printed as [N]); the agent's rollback record and any other process
# writing "Failed to start" do not; an ambiguous line (identifier forging "[1]: ") counts (fail-closed)
pc() { total=$((total + 1)); printf '%s\n' "${@:3}" > $d/$1; local g; g=$(prev_failed_starts $d/$1)
  if [ "$g" = "$2" ]; then echo "PASS prev_failed_starts $1: $g"; else failed=$((failed + 1)); echo "FAIL prev_failed_starts $1: $g, want $2"; fi; }
J1='2026-11-22T03:01:10Z <3> systemd[1]: Failed to start foil-config.service - Render node configuration (foilbird).'
JA='2026-11-22T03:17:03Z <6> foil-agent[542]:  WARN rolled back from=3 to="1" reason=3: 3 boot attempts failed; Failed to start foil-config.service - Render node configuration (foilbird). | ERROR boot-check FAIL foil-config'
JO='2026-11-22T03:05:00Z <3> systemd[777]: Failed to start foo.service'
JF='2026-11-22T03:05:01Z <3> systemd[1]: Failed to start x[777]: forged identifier'
pc pid1 1 "$J1"
pc agent_quote 0 "$JA"
pc not_pid1 0 "$JO"
pc mixed 1 "$J1" "$JA" "$JO"
pc forged_ident 1 "$JF"
pc dep_failed 1 '2026-11-22T03:01:11Z <3> systemd[1]: Dependency failed for foil-boot-check.service - Health gate.'
total=$((total + 1)); printf '%s\n' "$J1" "$JA" "$JO" > $d/full; g=$(prev_excluded $d/full $d/mixed)
if [ "$g" = 2 ]; then echo "PASS prev_excluded: $g"; else failed=$((failed + 1)); echo "FAIL prev_excluded: $g, want 2"; fi

echo "CHECK SELFTEST $([ $failed = 0 ] && echo PASS || echo FAIL) $((total - failed))/$total"
[ $failed = 0 ]
