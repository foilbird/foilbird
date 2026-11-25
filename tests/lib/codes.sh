# SPDX-License-Identifier: Apache-2.0
# The agent's refusal codes and record names as foilctl prints them: ONE place for every script that reads them
# (lib/steps.sh of this harness and any other test chain), so all read the answers the same way. ERE patterns over
# foilctl output (an RPC error prints as `Error: Status { code: <Code>, message: "<text>", ... }`, GetUpdateStatus as
# `{:#?}` of the reply). The comma after the code is optional: lib/steps.sh extracts `code: X` and `message: "..."` and
# joins them with a space (a required comma would fail a negative probe although the agent answered as expected).
# Source: agent/src/server.rs and api/proto/foilbird/agent/v1alpha1/agent.proto. Status per pattern: "source" = read from the
# code, "run" = also seen verbatim from a node in a run of this harness (scenarios 20-70). Change a pattern only
# together with its status.

# Rollback / RaiseMinVersion with an expect_booted that is not the booted release (server.rs: rollback refuse(),
# raise_min_version map_err -> failed_precondition). run:
#   code: FailedPrecondition, message: "booted version is 2, expected 1"   (Rollback; also "is 1, expected 2")
#   code: FailedPrecondition, message: "booted version is 1, expected 2"   (RaiseMinVersion as operator)
# InvalidArgument is not produced for this case (not seen in a run either)
CODE_EXPECT_MISMATCH='code: FailedPrecondition,? message: "booted version is [0-9]+, expected [0-9]+"'
# a role the RPC does not allow (authz.rs decide -> permission_denied). run:
#   code: PermissionDenied, message: "/foilbird.agent.v1alpha1.NodeAgent/RaiseMinVersion (ACCESS_LEVEL_DESTRUCTIVE) is not allowed for role reader; allowed: operator"
#   (the same with "role controller")
CODE_DENIED='code: PermissionDenied,? message: "[^"]* is not allowed for role [a-z_-]+; allowed: [a-z_, -]+"'
# StageUpdate of a release rolled back on this node: refused at once, a synchronous RPC error, not a Failed phase
# (server.rs stage_update). run after an Operator rollback:
#   code: FailedPrecondition, message: "STAGE_ERROR_ROLLED_BACK: 2 was rolled back on this node (operator rollback by <CN>: <reason>); stage a newer release"
# after T7 (BootAttemptsExhausted): run, the same code (scenario 60-t7, restage of release 3).
# RolledBack = the stage status variant (StageError ROLLED_BACK = 10), source
CODE_ROLLED_BACK='STAGE_ERROR_ROLLED_BACK: [0-9]+ was rolled back on this node|RolledBack'
# StageUpdate below the floor: update::Refusal::Policy -> "STAGE_ERROR_BELOW_MIN_VERSION: <m>" at once, or the stage
# status error BelowMinVersion (StageError BELOW_MIN_VERSION = 5). run (scenario 70-epoch, release 1 after the floor 4)
CODE_BELOW_MIN='STAGE_ERROR_BELOW_MIN_VERSION|BelowMinVersion'
# rollback record of GetUpdateStatus: RollbackInfo.reason_code (enum RollbackReason: OPERATOR = 4, BOOT_ATTEMPTS_EXHAUSTED
# = 1); prost's Debug prints the variant name, the number is accepted too. The block from "rollback: Some" to
# "detected_unix" holds the whole record (from/to are multi-line: a fixed -A<n> cuts reason_code off).
# RB_OPERATOR: run (reason_code: Operator, reason: "operator rollback by <CN>: <reason>", attempts: 0)
RB_OPERATOR='reason_code: (Operator|4),'
# RB_EXHAUSTED: run (scenario 60-t7: reason_code: BootAttemptsExhausted, attempts: 3)
RB_EXHAUSTED='reason_code: (BootAttemptsExhausted|1),'
# rollback_block <update-status file>: the whole rollback record on one line. Match on all of it, shorten only for
# display (a T7 reason of several hundred characters would push reason_code past a fixed cut = a false FAIL)
rollback_block() { sed -n '/rollback: Some/,/detected_unix/p' "$1" | tr -s ' \n' ' '; }
# audit line of a confirmed update in the foil-agent journal (agent/src/rollback.rs: tracing field version = <str>, printed
# quoted: `INFO update confirmed version="2"`). run (scenario 40-ab)
audit_confirmed() { grep -a -m1 -E "update confirmed version=\"?$1\"?( |$)"; }
