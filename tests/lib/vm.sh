# SPDX-License-Identifier: Apache-2.0
# QEMU guests of the test harness (sourced after common.sh; bash). One guest = one directory $WORK/vm/<name>/:
#   disk.raw (copy of the image, grown to DISK_SIZE), vars.fd (UEFI variables), tpm/ (swtpm state), serial.log
#   (stamped, serial_stamp.py), qemu.log, port (host port of the agent API), qemu.pid, swtpm.pid, stamp.pid.
# The guest reboots inside the same QEMU process (no -no-reboot): updates, rollbacks and automatic boot assessment
# need it. Removing the directory (vm_stop --wipe) is a fresh machine: new disk, new UEFI variables, new TPM.
#
#   vm_start <name> <image.raw> [--sb on|off] [--enroll auto|vars] [--mem M] [--smp N]
#       --sb on (default): OVMF with Secure Boot (SMM); --enroll auto: empty variables, setup mode, the image enrolls
#       its own db certificate on the first boot (SecureBootAutoEnroll); --enroll vars: PK, KEK and db of $KEYS
#       enrolled with virt-fw-vars before the first boot, Secure Boot on (the image must be signed with $KEYS/sb/db).
#       --sb off: OVMF without Secure Boot support.
#       The agent's TLS material comes as SMBIOS type 11 credentials from $KEYS/smbios; the API (guest :7443) is
#       forwarded to 127.0.0.1:<free port>. Environment: DISK_SIZE (16G), VM_MEM (4G), VM_SMP (2), VM_CPUS (taskset
#       list, unset = no pinning), ACCEL (kvm if /dev/kvm is usable, else tcg), OVMF_CODE_SB, OVMF_CODE, OVMF_VARS.
#   vm_stop <name> [--wipe]
#   vm_serial <name>                          path of the stamped serial log
#   vm_mac <name>                             MAC of the guest's NIC (fixed per name)
#   vm_wait_serial <name> <ERE> <seconds> [line]   wait for a serial line after line number <line> (default 0)
#   ctl <name> <role> <foilctl args...>        foilctl against the guest with the client certificate of <role>
#   vm_wait_api <name> <seconds>              until GetInfo answers
#   vm_boot_id <name>; vm_wait_new_boot <name> <old boot id> <seconds>

OVMF_CODE_SB=${OVMF_CODE_SB:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
SERVER_NAME=${SERVER_NAME:-agent.test}

vm_dir() { echo "${WORK:?}/vm/$1"; }
vm_serial() { echo "$(vm_dir "$1")/serial.log"; }
vm_port() { cat "$(vm_dir "$1")/port"; }
# MAC of the guest's NIC: fixed per name (ApplyConfig matches the interface by MAC)
vm_mac() { printf '52:54:00:%s\n' "$(printf '%s' "$1" | sha256sum | sed 's/^\(..\)\(..\)\(..\).*/\1:\2:\3/')"; }

vm_accel() {
  if [ -n "${ACCEL:-}" ]; then echo "$ACCEL"; return; fi
  if [ -w /dev/kvm ] && [ -r /dev/kvm ]; then echo kvm; else echo tcg; fi
}

vm_start() {
  local name=$1 image=$2; shift 2
  local sb=on enroll=auto mem=${VM_MEM:-4G} smp=${VM_SMP:-2}
  while [ $# -gt 0 ]; do
    case $1 in
      --sb) sb=$2; shift 2 ;; --enroll) enroll=$2; shift 2 ;; --mem) mem=$2; shift 2 ;; --smp) smp=$2; shift 2 ;;
      *) die "vm_start: unknown option $1" ;;
    esac
  done
  local d; d=$(vm_dir "$name")
  [ -s "$image" ] || die "vm_start: image $image missing"
  [ -e "$d/qemu.pid" ] && kill -0 "$(cat "$d/qemu.pid")" 2>/dev/null && die "vm_start: $name already running"
  mkdir -p "$d/tpm"
  if [ ! -s "$d/disk.raw" ]; then                  # a fresh machine
    cp --sparse=always "$image" "$d/disk.raw"; truncate -s "${DISK_SIZE:-16G}" "$d/disk.raw"
    echo "$image $(sha256sum < "$image" | cut -c1-64)" > "$d/image.txt"
    case $sb/$enroll in
      on/auto|off/*) cp "$OVMF_VARS" "$d/vars.fd" ;;
      on/vars)
        local g; g=$(cat "${KEYS:?}/sb/owner.guid")
        virt-fw-vars --input "$OVMF_VARS" --output "$d/vars.fd" --set-pk "$g" "$KEYS/sb/PK.crt" \
          --add-kek "$g" "$KEYS/sb/KEK.crt" --add-db "$g" "$KEYS/sb/db.crt" --secure-boot > "$d/enroll.log" 2>&1 \
          || { cat "$d/enroll.log" >&2; die "vm_start: virt-fw-vars failed"; } ;;
      *) die "vm_start: --sb on|off, --enroll auto|vars" ;;
    esac
    echo "sb=$sb enroll=$enroll" > "$d/firmware.txt"
  fi
  local code=$OVMF_CODE_SB secure=on
  [ "$sb" = off ] && { code=$OVMF_CODE; secure=off; }
  swtpm socket --tpm2 --tpmstate dir="$d/tpm" --ctrl type=unixio,path="$d/swtpm.sock" \
    --log file="$d/swtpm.log" --pid file="$d/swtpm.pid" --daemon || die "vm_start: swtpm failed"
  local i
  for i in $(seq 50); do [ -S "$d/swtpm.sock" ] && break; sleep 0.1; done
  python3 -I "$TESTS_DIR/lib/serial_stamp.py" "$d/serial.sock" "$d/serial.log" > "$d/stamp.log" 2>&1 < /dev/null &
  echo $! > "$d/stamp.pid"
  for i in $(seq 50); do [ -S "$d/serial.sock" ] && break; sleep 0.1; done
  local port; port=$(free_port); echo "$port" > "$d/port"
  local accel cpu=host pin=()
  accel=$(vm_accel); [ "$accel" = tcg ] && cpu=max
  [ -n "${VM_CPUS:-}" ] && pin=(taskset -c "$VM_CPUS")
  "${pin[@]}" qemu-system-x86_64 -name "harness-$name" -machine q35,smm=on -accel "$accel" -cpu "$cpu" -m "$mem" -smp "$smp" \
    -global driver=cfi.pflash01,property=secure,value=$secure \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$code" -drive if=pflash,format=raw,unit=1,file="$d/vars.fd" \
    -chardev socket,id=chrtpm,path="$d/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
    -drive if=virtio,format=raw,file="$d/disk.raw" \
    -smbios type=11,path="$KEYS/smbios/agent.tls-cert" -smbios type=11,path="$KEYS/smbios/agent.tls-key" \
    -smbios type=11,path="$KEYS/smbios/agent.tls-ca" \
    -netdev user,id=n1,ipv6=off,hostfwd=tcp:127.0.0.1:"$port"-:7443 -device virtio-net-pci,netdev=n1,mac="$(vm_mac "$name")" \
    -chardev socket,id=ser0,path="$d/serial.sock",server=off -serial chardev:ser0 \
    -display none -monitor none -pidfile "$d/qemu.pid" -daemonize > "$d/qemu.log" 2>&1 \
    || { cat "$d/qemu.log" >&2; die "vm_start: qemu failed"; }
  log "vm $name: started (sb=$(cut -d' ' -f1 "$d/firmware.txt" | cut -d= -f2), accel=$accel, api 127.0.0.1:$port, pid $(cat "$d/qemu.pid"))"
}

# kill a pid only if its command line names this guest's directory (never someone else's process)
vm_kill() { local p; p=$(cat "$2" 2>/dev/null) || return 0; [ -n "$p" ] || return 0
  tr '\0' ' ' 2>/dev/null < "/proc/$p/cmdline" | grep -q -F "$1" && kill "$p" 2>/dev/null; return 0; }

vm_stop() {
  local name=$1 d; d=$(vm_dir "$1")
  [ -d "$d" ] || return 0
  # the guest's journal before QEMU is killed: read through the agent (ReadJournal reads journald's files, the runtime
  # and the persistent journal); best effort, never blocks the stop. Limit: the agent has no RPC to make journald flush
  # (no SIGUSR1/`journalctl --sync`; the agent cannot signal other services), so messages still queued in journald's
  # sockets and not yet written to a file are missed; journald appends to its files as it processes each message, so
  # what it has processed is in them. The text is ReadJournal's: redacted like every DIAG read (journal::redact), and the
  # harness's material is TEST only.
  if [ -e "/proc/$(cat "$d/qemu.pid" 2>/dev/null)" ] && [ -n "${KEYS:-}" ]; then
    local o=${LOGS:-${WORK:?}}/${name}.final
    CTL_T=20 ctl "$name" controller --limit 2000 journal > "$o.journal.txt" 2>&1 || true
    CTL_T=20 ctl "$name" controller --limit 500 dmesg > "$o.dmesg.txt" 2>&1 || true
  fi
  vm_kill "$d" "$d/qemu.pid"
  local i; for i in $(seq 30); do [ -e "/proc/$(cat "$d/qemu.pid" 2>/dev/null)" ] || break; sleep 0.5; done
  vm_kill "$d" "$d/swtpm.pid"; vm_kill "$d" "$d/stamp.pid"
  rm -f "$d/qemu.pid"
  [ "${2:-}" = --wipe ] && rm -rf "$d"
  log "vm $name: stopped${2:+ ($2)}"
}

vm_wait_serial() {
  local f; f=$(vm_serial "$1"); local re=$2 limit=$3 from=${4:-0} t0; t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt "$limit" ]; do
    tail -n +"$((from + 1))" "$f" 2>/dev/null | grep -a -q -E "$re" && return 0
    sleep 1
  done
  return 1
}

ctl() {
  local name=$1 role=$2; shift 2
  timeout "${CTL_T:-60}" "${FOILCTL:?}" --addr "https://127.0.0.1:$(vm_port "$name")" --server-name "$SERVER_NAME" \
    --tls-dir "$KEYS/pki/$role" "$@" 2>&1
}

vm_wait_api() {
  local t0; t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt "$2" ]; do
    CTL_T=10 ctl "$1" reader info | grep -q boot_id && return 0
    sleep 5
  done
  return 1
}

vm_boot_id() { CTL_T=10 ctl "$1" reader info | awk '/boot_id:/ { gsub(/[",]/, "", $2); print $2; exit }'; }

vm_wait_new_boot() {
  local t0 b; t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt "$3" ]; do
    b=$(vm_boot_id "$1"); [ -n "$b" ] && [ "$b" != "$2" ] && return 0
    sleep 5
  done
  return 1
}
