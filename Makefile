# SPDX-License-Identifier: Apache-2.0
# Entry points of the test harness (tests/README.md). Building images is not done here: IMAGE and FOILCTL are inputs.
#
#   make test IMAGE=<out>/foilbird-deb_1.raw FOILCTL=<dist>/foilctl [SCENARIOS="install"] [VERSION=1] [ENROLL=auto|vars]
#             [KEYS=<key set the images were built with> CHANNEL=<published releases 2 3 4>] [STRICT=1]
#   make test-container IMAGE=... FOILCTL=...    the same inside debian:trixie (tests/container.sh)
#   make test-keys KEYS=<new dir on tmpfs>      ephemeral TEST key set (for a build with --enroll vars, or KEYS=)
#   make test-list
#   make test-selfcheck / test-selfcheck-container   the harness's own tools (no image)
#   make oss-gate [OWN=<owner/repo>]             publication rules without a word list (tests/compliance/oss-gate.py)
#   make test-ci                                  errexit invariant of ci/run-stage.sh (tests/ci/run-stage-errexit.sh; network)
export IMAGE FOILCTL VERSION KEYS ENROLL WORK KEEP API_TIMEOUT SETTLE DISK_SIZE VM_MEM VM_SMP VM_CPUS ACCEL
export CHANNEL AGENT_SUMS STRICT NODE NTP MAXSHUT BASE_VERSION AB_VERSION T7_VERSION EPOCH_VERSION EPOCH T7_TIMEOUT T7_BOOT_MAX

.PHONY: test test-container test-keys test-list test-selfcheck test-selfcheck-container oss-gate test-ci
test:
	tests/run.sh $(SCENARIOS)
test-container:
	tests/container.sh $(SCENARIOS)
test-keys:
	@test -n "$(KEYS)" || { echo "KEYS=<new directory, preferably on tmpfs>"; exit 2; }
	tests/lib/keys.sh gen $(KEYS)
test-list:
	@tests/run.sh --list
test-selfcheck:
	tests/run.sh --selfcheck
test-selfcheck-container:
	tests/container.sh --selfcheck
oss-gate:
	python3 -I tests/compliance/oss-gate.py --selftest --history $(if $(OWN),--own $(OWN))
test-ci:
	bash tests/ci/run-stage-errexit.sh
