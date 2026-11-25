# SPDX-License-Identifier: Apache-2.0
# Fresh install under Secure Boot and TPM: an empty machine (new disk from the image, new UEFI variables, new TPM)
# boots the image, the image enrolls its db certificate (setup mode, --enroll auto) or boots with PK/KEK/db already
# enrolled (--enroll vars), repartitions, sets up /var with LUKS2 bound to the TPM, and the agent answers.
# Checks: the API comes up within API_TIMEOUT; the kernel reports Secure Boot enabled; boot_check (Secure Boot on, TPM,
# /var LUKS2+TPM2, failed units 0, health Pass, boot Confirmed, version VERSION when given). No ApplyConfig yet, so
# no NTP servers: --no-ntp-ok allows only time-synced with "ntp system=[]": Warn (base image) or Pending
# "first join waits for time sync" (k8s-worker before the first join) (lib/check.sh).
# Inputs: IMAGE (foilbird-deb_N.raw of a product build), FOILCTL, KEYS (run.sh), VERSION (optional), ENROLL (auto|vars).

scenario_install() {
  local n=n1 t0
  vm_stop "$n" --wipe
  t0=$(date +%s.%N)
  vm_start "$n" "${IMAGE:?IMAGE=<foilbird-deb_N.raw>}" --sb on --enroll "${ENROLL:-auto}"
  if vm_wait_api "$n" "${API_TIMEOUT:-600}"; then
    res "$n" api PASS "agent answers after $(since "$t0")s"
  else
    res "$n" api FAIL "no answer in ${API_TIMEOUT:-600}s (serial: $(vm_serial "$n"))"
    tail -n 40 "$(vm_serial "$n")" > "$LOGS/install_${n}.serial_tail.txt" 2>/dev/null
    vm_stop "$n"; return
  fi
  if grep -a -q -E 'Secure boot enabled' "$(vm_serial "$n")"; then
    res "$n" kernel-sb PASS "kernel: $(grep -a -m1 -o -E 'secureboot: Secure boot enabled' "$(vm_serial "$n")")"
  else
    res "$n" kernel-sb FAIL "no 'Secure boot enabled' on the serial console"
  fi
  boot_check "$n" install --sb on --no-ntp-ok ${VERSION:+--version "$VERSION"}
  cp "$(vm_serial "$n")" "$LOGS/install_${n}.serial.log"
  if [ "${KEEP:-0}" = 1 ]; then vm_stop "$n"; else vm_stop "$n" --wipe; fi
}
