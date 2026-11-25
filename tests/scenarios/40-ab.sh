# SPDX-License-Identifier: Apache-2.0
# A/B update BASE_VERSION -> AB_VERSION through the agent (StageUpdate from the channel, Reboot --expect-staged).
# Checks: stage (Staged), shutdown (request -> "reboot: Restarting system" <= MAXSHUT s), boot_check (booted
# AB_VERSION, Confirmed foilbird-deb_AB_VERSION, usrhash of the channel's UKI), audit ("update confirmed version=V").
# Starts from the configured node (runs 20-config first when needed). The A/B phase of the release test.

scenario_ab() {
  channel_need || return 0
  node_ensure config || return 0
  node_step_ab || node_failed ab
}
