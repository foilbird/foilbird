# SPDX-License-Identifier: Apache-2.0
# T7: a release whose boot check fails (T7_VERSION) is staged and booted; the node returns to BASE_VERSION by itself
# (boot counting, three tries), with no Rollback RPC. Checks: stage, rollback (back to BASE_VERSION, Confirmed, record
# BootAttemptsExhausted, time and the boot-check FAIL lines on the serial), boot_check --prev failed (the broken tries
# are expected in the journal of the boot that ended), restage (staging T7_VERSION again is refused: ROLLED_BACK).
# Starts after 50-rollback. The T7 phase of the release test; T7_TIMEOUT (1800 s).

scenario_t7() {
  channel_need || return 0
  node_ensure rollback || return 0
  node_step_t7 || node_failed t7
}
