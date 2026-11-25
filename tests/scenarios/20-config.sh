# SPDX-License-Identifier: Apache-2.0
# ApplyConfig on a fresh install, the product way the later scenarios rely on: network (DHCP on the user-net NIC,
# matched by MAC), NTP servers (NTP, default Debian's pool) and the release channel (NodeConfig.update_channel:
# CHANNEL served over https with the TEST CA, lib/channel.sh). The node NODE (n2) stays up for the next scenarios.
# Checks: api, apply (generation raised), boot_check on the configured node (health Pass without exceptions, version
# BASE_VERSION, usrhash of IMAGE). Without CHANNEL: one SKIP line (this and every later scenario).
# Inputs: IMAGE (release BASE_VERSION=1), FOILCTL, CHANNEL, NTP, ENROLL.

scenario_config() {
  channel_need || return 0
  { node_step_config && node_set_state config; } || node_failed config
}
