# SPDX-License-Identifier: Apache-2.0
# Checks of one boot of a guest through the agent API (sourced after vm.sh; bash).
#
#   boot_check <name> <label> [--version V] [--sb on|off] [--prev clean|failed] [--usrhash HEX] [--settle S] [--no-ntp-ok]
#     Waits for the API, lets the boot settle (S seconds, default $SETTLE or 60: boot check, boot commit), then saves
#     info, update-status, health, failed units, kernel log and journals to $LOGS/<label>_<name>.* and writes ONE
#     result line "boot <name> <label> PASS|FAIL <facts> [| <what failed>]". FAIL if any of:
#       booted version != V (when given); Secure Boot state != --sb (default on); no TPM; /var not LUKS2 + TPM2;
#       a failed unit in this boot; a failed start of PID 1 in the journal of the boot that ended (--prev clean, the default;
#       --prev failed: the previous boot was expected to fail, e.g. a broken release that the node rolled back from);
#       boot noise (60-tpm-udev.rules "Unknown user/group 'tss'", drm_vram_helper.ko) at priority err in this boot
#       or in the previous one; health overall != Pass or any check Fail; boot not Confirmed, or the boot entry is not
#       foilbird-deb_V (when V is given); usrhash= of the kernel command line != HEX (when given).
#     --no-ntp-ok: only for a boot before any ApplyConfig (no NTP servers configured yet; 10-install). Allows exactly
#       one non-Pass, non-Skipped check, "time-synced" with "ntp system=[]" in its detail, in one of two forms:
#         Warn (base image; overall=Warn)                                   -> allowed=time-synced:no-ntp-configured
#         Pending "first join waits for time sync" (k8s-worker before the first join, the agent's time_check;
#         overall=Pending)                                                  -> allowed=time-synced:pending-first-join
#       Any other Warn/Pending, a Fail, a failed unit, or time-synced with servers configured is still FAIL. Boots after
#       ApplyConfig pass --ntp in the config and call boot_check without it (overall must be Pass).
#     Clock: with NTP servers configured, a time-synced Warn "clock not synchronized" or Pending "first join waits for
#       time sync" after the settle time is waited for (health read every 10 s, up to TIME_SYNC_WAIT, default 180 s):
#       NTP through user-mode networking can take longer than the settle time (seen: still
#       unsynchronized after 60 s). Not an exception: if time-synced is still Warn or Pending after the wait, health is
#       not Pass and the boot FAILs. The result line says tsync=<s>.

# clock_pending <health file>: time-synced waits for the clock with NTP servers configured: Warn "clock not
# synchronized" or Pending "first join waits for time sync" (k8s-worker before the first join)
clock_pending() {
  awk '/^            name:/ { nm=$2; gsub(/[",]/, "", nm) }
       /^            status:/ { st=$2; sub(/,$/, "", st) }
       /^            detail:/ { if (nm == "time-synced" && !index($0, "ntp system=[]") &&
                                    ((st == "Warn" && index($0, "clock not synchronized")) ||
                                     (st == "Pending" && index($0, "first join waits for time sync")))) p=1 }
       END { exit !p }' "$1"
}

# health_summary <file>: "overall=O fail=F warn=W pending=P other=X nontp=N npend=M" from `foilctl reader health`;
# X = checks neither Pass, Skipped, Fail, Warn nor Pending; N = Warn checks that are exactly time-synced with no NTP
# servers configured (detail "ntp system=[]"); M = Pending checks that are exactly time-synced "first join waits for
# time sync" with no NTP servers configured.
health_summary() {
  awk '/^    overall:/ { o=$2; sub(/,$/, "", o) }
       /^            name:/ { nm=$2; gsub(/[",]/, "", nm) }
       /^            status:/ { st=$2; sub(/,$/, "", st) }
       /^            detail:/ { ts = (nm == "time-synced" && index($0, "ntp system=[]"))
                                if (st == "Fail") f++
                                else if (st == "Warn") { w++; if (ts) t++ }
                                else if (st == "Pending") { p++; if (ts && index($0, "first join waits for time sync")) q++ }
                                else if (st != "Pass" && st != "Skipped") x++
                                st = "" }
       END { printf "overall=%s fail=%d warn=%d pending=%d other=%d nontp=%d npend=%d", o, f+0, w+0, p+0, x+0, t+0, q+0 }' "$1"
}

# Failed starts of the boot that ended are counted from the service manager's entries only, selected by fields journald
# sets itself (a client cannot forge them), not by the text of a line: the agent's rollback record quotes the failed
# starts of the broken release ("WARN rolled back from=3 to=\"1\" reason=3: ... Failed to start foil-config.service ..."),
# and any unit may write "Failed to start ...".
#   on the node: ReadJournal --unit init.scope (agent journal.rs: _SYSTEMD_UNIT=init.scope, or _PID=1 about the unit,
#                or OBJECT_SYSTEMD_UNIT=init.scope) -> $o.prev1.txt; foilctl prints "<ts> <prio> <ident>[<_PID>]: <msg>"
#   here:        a line counts only with _PID 1. <ident> is SYSLOG_IDENTIFIER (client-set): a line with more than one
#                "[N]: " is ambiguous and counts when it matches (fail-closed: a forged line can add a FAIL, never hide one).
# _TRANSPORT is not in the agent's JournalEntry (api: unit, identifier, pid, message), so it is not checked.
FAILED_START_RE='Failed to start|Dependency failed|: Failed with result|entered failed state'
# prev_failed_starts <prev1 file>: failed starts of PID 1 (see above)
prev_failed_starts() {
  awk -v re="$FAILED_START_RE" '$0 ~ re { n = gsub(/\[[0-9]+\]: /, "&"); if (n != 1 || index($0, "[1]: ")) c++ }
       END { print c+0 }' "$1"
}
# prev_excluded <full prev journal> <prev1 file>: lines of the full journal that match the failed-start patterns but are
# not counted (not PID 1: e.g. the agent's rollback record); reported as prevx=
prev_excluded() {
  local a b; a=$(grep -a -c -E "$FAILED_START_RE" "$1" || true); b=$(prev_failed_starts "$2"); echo $((a > b ? a - b : 0))
}

# health_verdict <summary> <nontp 0|1>: exit 0 if the health summary is accepted; prints the allowance (or nothing)
health_verdict() {
  case "$1" in
    "overall=Pass fail=0 warn=0 pending=0 other=0 nontp=0 npend=0") return 0 ;;
    "overall=Warn fail=0 warn=1 pending=0 other=0 nontp=1 npend=0") [ "$2" = 1 ] && { echo " allowed=time-synced:no-ntp-configured"; return 0; } ;;
    "overall=Pending fail=0 warn=0 pending=1 other=0 nontp=0 npend=1") [ "$2" = 1 ] && { echo " allowed=time-synced:pending-first-join"; return 0; } ;;
  esac
  return 1
}

boot_check() {
  local n=$1 lb=$2; shift 2
  local v="" sb=on prev=clean want_uh="" settle=${SETTLE:-60} nontp=0
  while [ $# -gt 0 ]; do
    case $1 in
      --version) v=$2; shift 2 ;; --sb) sb=$2; shift 2 ;; --prev) prev=$2; shift 2 ;;
      --usrhash) want_uh=$2; shift 2 ;; --settle) settle=$2; shift 2 ;; --no-ntp-ok) nontp=1; shift ;;
      *) die "boot_check: unknown option $1" ;;
    esac
  done
  local o=${LOGS:?}/${lb}_$n bad=""
  vm_wait_api "$n" "${API_TIMEOUT:-600}" || { res "$n" "boot:$lb" FAIL "agent API not up in ${API_TIMEOUT:-600}s"; return 1; }
  sleep "$settle"
  local tw=0
  while ctl "$n" reader health > "$o.health.txt" && clock_pending "$o.health.txt" && [ "$tw" -lt "${TIME_SYNC_WAIT:-180}" ]; do
    sleep 10; tw=$((tw + 10))
  done
  ctl "$n" reader info > "$o.info.txt"; ctl "$n" reader update-status > "$o.us.txt"; ctl "$n" reader health > "$o.health.txt"
  ctl "$n" reader --failed units > "$o.failed.txt"; ctl "$n" controller --limit 5000 dmesg > "$o.dmesg.txt"
  ctl "$n" controller --priority 3 --limit 1000 journal > "$o.err.txt"
  local prc=0; ctl "$n" controller --boot -1 --limit 20000 journal > "$o.prev.txt" || prc=$?
  local p1rc=0; ctl "$n" controller --boot -1 --unit init.scope --limit 2000 journal > "$o.prev1.txt" || p1rc=$?
  ctl "$n" controller --limit 3000 journal | grep -a -E 'Startup finished in' | tail -1 > "$o.startup.txt"

  local gv; gv=$(grep -m1 -o 'image_version: "[^"]*"' "$o.info.txt" | cut -d'"' -f2)
  [ -z "$v" ] || [ "$gv" = "$v" ] || bad="$bad booted=$gv/expected=$v"
  local want_sb=true; [ "$sb" = off ] && want_sb=false
  grep -q "secure_boot: $want_sb" "$o.info.txt" || bad="$bad secure_boot!=$want_sb"
  grep -q 'tpm_present: true' "$o.info.txt" || bad="$bad tpm"
  grep -q 'var_protection: Luks2Tpm2' "$o.info.txt" || bad="$bad var_protection"
  local nf; nf=$(grep -c -v -E '^\s*$' "$o.failed.txt" || true); grep -q '^Error' "$o.failed.txt" && nf=err
  [ "$nf" = 0 ] || bad="$bad failed_units=$nf"
  # the boot that ended: none on the very first boot of a machine (the agent answers with an error, or no lines)
  local pf=none px=-
  if [ "$prc" = 0 ] && grep -a -q -v -E '^\s*$' "$o.prev.txt" && ! grep -q '^Error' "$o.prev.txt"; then
    if [ "$p1rc" != 0 ] || grep -q '^Error' "$o.prev1.txt"; then pf=err; bad="$bad prev_pid1_journal"
    else
      pf=$(prev_failed_starts "$o.prev1.txt"); px=$(prev_excluded "$o.prev.txt" "$o.prev1.txt")
      # the agent returns at most 2000 entries: a full answer may have cut the start of the boot. foilctl's summary
      # "-- N entries, ..." is in the same file (ctl merges stderr); no summary = the count is unknown, FAIL too
      local p1n; p1n=$(sed -n 's/^-- \([0-9]*\) entries.*/\1/p' "$o.prev1.txt" | tail -1)
      case $p1n in ''|2000) bad="$bad prev_pid1_journal_cut(${p1n:-no summary})" ;; esac
      [ "$prev" = failed ] || [ "$pf" = 0 ] || bad="$bad prev_boot_failed=$pf"
    fi
  fi
  local noise; noise=$(cat "$o.err.txt" "$o.prev.txt" | grep -a -c -E "60-tpm-udev.rules.*Unknown (user|group) 'tss'|drm_vram_helper\.ko" || true)
  [ "$noise" = 0 ] || bad="$bad boot_noise=$noise"
  local hs; hs=$(health_summary "$o.health.txt")
  local allowed=""
  allowed=$(health_verdict "$hs" "$nontp") || bad="$bad health($hs)"
  local conf ent
  conf=$(grep -m1 -o 'confirmation: [A-Za-z]*' "$o.us.txt" | cut -d' ' -f2); ent=$(grep -m1 -o 'entry: "[^"]*"' "$o.us.txt" | cut -d'"' -f2)
  [ "$conf" = Confirmed ] || bad="$bad confirmation=${conf:-?}"
  [ -z "$v" ] || [[ "$ent" == foilbird-deb_$v* ]] || bad="$bad entry=${ent:-?}"
  local uh; uh=$(grep -a -o 'usrhash=[0-9a-f]*' "$o.dmesg.txt" | head -1 | cut -d= -f2)
  [ -z "$want_uh" ] || [ "$uh" = "$want_uh" ] || bad="$bad usrhash=${uh:0:12}/expected=${want_uh:0:12}"
  local st; st=$(grep -o 'Startup finished in .*= \([0-9.]*min \)\?[0-9.]*s' "$o.startup.txt" | tail -1)
  local det="v=${gv:-?} sb=$want_sb usrhash=${uh:0:16} failed=$nf prev=$pf prevx=$px noise=$noise tsync=${tw}s $hs$allowed $conf ${ent:-?} startup=[${st:-?}]"
  if [ -z "$bad" ]; then res "$n" "boot:$lb" PASS "$det"; else res "$n" "boot:$lb" FAIL "$det |$bad"; fi
}
