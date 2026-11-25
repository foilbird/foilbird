# SPDX-License-Identifier: Apache-2.0
# T5 (nothing to log in with or to run a script with) on the /usr the configured node runs, and its agent binary.
# The node has no shell, so the check runs on the host over the /usr partition of IMAGE (unpacked with fsck.erofs),
# and binds that tree to the node: the rootHash in the image's verity signature = usrhash= of the node's kernel command
# line (dm-verity makes the node's /usr exactly that tree). Rules: images/debian/tools/t5-check (gated=0).
# Checks: usr-bound (rootHash = node usrhash), t5 (gated=0), agent (sha256 of usr/bin/foil-agent = the dist's
# SHA256SUMS: AGENT_SUMS, default SHA256SUMS next to FOILCTL; SKIP without it).
# Inputs: IMAGE, FOILCTL, CHANNEL (the node is configured with it; lib/node.sh), AGENT_SUMS.

USR_TYPE=8484680c-9521-48c6-9c11-b0720656f69e        # usr x86-64 (Discoverable Partitions)
USR_SIG_TYPE=e7bb33fb-06cf-4e81-8273-e543b413e2e2    # usr x86-64 verity signature

scenario_t5() {
  channel_need || return 0
  node_ensure config || return 0
  local w=$WORK/t5 rh uh
  rm -rf "$w"; mkdir -p "$w/root"
  python3 -I "$TESTS_DIR/lib/gpt_part.py" "$IMAGE" "$USR_SIG_TYPE" "$w/usr-sig.raw" > "$LOGS/parts.txt" \
    && python3 -I "$TESTS_DIR/lib/gpt_part.py" "$IMAGE" "$USR_TYPE" "$w/usr.raw" >> "$LOGS/parts.txt" \
    || { res "$NODE" usr-bound FAIL "no usr / usr-verity-sig partition in IMAGE"; return 0; }
  rh=$(tr -d '\0' < "$w/usr-sig.raw" | grep -o '"rootHash":"[0-9a-f]*"' | cut -d'"' -f4)
  uh=$(ctl "$NODE" controller --limit 5000 dmesg | grep -a -o -m1 'usrhash=[0-9a-f]*' | head -1 | cut -d= -f2)
  [ -n "$rh" ] && [ "$rh" = "$uh" ] && res "$NODE" usr-bound PASS "rootHash ${rh:0:16} = node usrhash" \
    || res "$NODE" usr-bound FAIL "rootHash ${rh:0:16} / node usrhash ${uh:0:16}"
  fsck.erofs --extract="$w/root/usr" "$w/usr.raw" > "$LOGS/extract.txt" 2>&1 \
    || { res "$NODE" t5 FAIL "fsck.erofs --extract failed ($LOGS/extract.txt)"; return 0; }
  sh "$REPO_DIR/images/debian/tools/t5-check" "$w/root" > "$LOGS/t5.txt" 2>&1
  local last; last=$(grep '^T5 ' "$LOGS/t5.txt" | tail -1)
  echo "$last" | grep -q ' gated=0$' && res "$NODE" t5 PASS "$last" || res "$NODE" t5 FAIL "${last:-no T5 line} ($LOGS/t5.txt)"
  local sums=${AGENT_SUMS:-$(dirname "$FOILCTL")/SHA256SUMS} ag want
  ag=$(sha256sum < "$w/root/usr/bin/foil-agent" 2>/dev/null | cut -c1-64)
  if [ -s "$sums" ]; then
    want=$(awk '$2 ~ /(^|\/|\*)foil-agent$/ { print $1; exit }' "$sums")
    [ -n "$ag" ] && [ "$ag" = "$want" ] && res "$NODE" agent PASS "foil-agent ${ag:0:16} = dist" \
      || res "$NODE" agent FAIL "foil-agent ${ag:0:16} / dist ${want:0:16}"
  else
    res "$NODE" agent SKIP "foil-agent ${ag:0:16}; no dist SHA256SUMS (AGENT_SUMS)"
  fi
  rm -rf "$w"
}
