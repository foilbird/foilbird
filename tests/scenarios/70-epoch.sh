# SPDX-License-Identifier: Apache-2.0
# var-epoch: EPOCH_VERSION is a release of PCR epoch EPOCH (2, min version EPOCH_VERSION). Checks: stage (with the
# enroll of the new epoch), shutdown, boot_check (booted EPOCH_VERSION, /var opened), raise-negative (RaiseMinVersion:
# reader and controller PermissionDenied, operator with a wrong expect_booted refused), raise (floor EPOCH_VERSION),
# old-refused (StageUpdate BASE_VERSION: BELOW_MIN_VERSION), after a reboot boot_check and floor-kept.
# Starts after 60-t7. The epoch phase of the release test.

scenario_epoch() {
  channel_need || return 0
  node_ensure t7 || return 0
  node_step_epoch || node_failed epoch
}
