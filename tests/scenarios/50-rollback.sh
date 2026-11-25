# SPDX-License-Identifier: Apache-2.0
# Operator Rollback AB_VERSION -> BASE_VERSION. Checks: negative (Rollback with a wrong expect_booted refused:
# FailedPrecondition or InvalidArgument), shutdown, boot_check (booted BASE_VERSION, Confirmed), record (rollback
# record with reason Operator). Starts after 40-ab (runs it first when needed). The rollback phase of the release test.

scenario_rollback() {
  channel_need || return 0
  node_ensure ab || return 0
  node_step_rollback || node_failed rollback
}
