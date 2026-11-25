#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run the harness inside Debian 13 (debian:trixie, pinned by digest) with docker or podman: the same command as
# `make test`, with the tools of tests/deps.txt from Debian instead of the host's.
#
#   IMAGE=... FOILCTL=... tests/container.sh [scenario...]
#   tests/container.sh --selfcheck       the harness's own tools inside the container (no image)
# The repository is mounted read-only at /src; the image, foilctl and, when set, KEYS, CHANNEL and AGENT_SUMS read-only
# under /in; the work directory at /work (WORK on the host, default a new directory under ${TMPDIR:-/var/tmp}).
# /dev/kvm is passed when it exists; the container needs no privileges for QEMU. Without KEYS the keys are generated
# inside the container on its tmpfs (/dev/shm); a run with CHANNEL needs the KEYS the releases were built with.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
DEBIAN_IMAGE=${DEBIAN_IMAGE:-debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6}
eng=${ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$eng" ] || { echo "container.sh: neither podman nor docker" >&2; exit 2; }
inputs=()
if [ "${1:-}" != --selfcheck ]; then
  img=$(readlink -f "${IMAGE:?IMAGE=<foilbird-deb_N.raw>}"); ctl=$(readlink -f "${FOILCTL:?FOILCTL=<foilctl>}")
  inputs=(-v "$img:/in/image.raw:ro" -v "$ctl:/in/foilctl:ro" -e IMAGE=/in/image.raw -e FOILCTL=/in/foilctl)
  [ -z "${KEYS:-}" ] || inputs+=(-v "$(readlink -f "$KEYS"):/in/keys:ro" -e KEYS=/in/keys)
  [ -z "${CHANNEL:-}" ] || inputs+=(-v "$(readlink -f "$CHANNEL"):/in/channel:ro" -e CHANNEL=/in/channel)
  [ -z "${AGENT_SUMS:-}" ] || inputs+=(-v "$(readlink -f "$AGENT_SUMS"):/in/agent.sums:ro" -e AGENT_SUMS=/in/agent.sums)
fi
work=${WORK:-$(mktemp -d "${TMPDIR:-/var/tmp}/harness.XXXXXX")}; mkdir -p "$work"; work=$(readlink -f "$work")
dev=(); [ -e /dev/kvm ] && dev=(--device /dev/kvm)
envs=(); for v in VERSION ENROLL KEEP STRICT API_TIMEOUT SETTLE DISK_SIZE VM_MEM VM_SMP VM_CPUS ACCEL NODE NTP MAXSHUT \
  BASE_VERSION AB_VERSION T7_VERSION EPOCH_VERSION EPOCH T7_TIMEOUT T7_BOOT_MAX; do
  [ -n "${!v:-}" ] && envs+=(-e "$v=${!v}"); done
exec "$eng" run --rm "${dev[@]}" --shm-size=64m \
  -v "$repo:/src:ro" -v "$work:/work" "${inputs[@]}" -e WORK=/work "${envs[@]}" \
  "$DEBIAN_IMAGE" bash -c '
    set -e; export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends $(cat /src/tests/deps.txt) >/dev/null
    exec /src/tests/run.sh "$@"' harness "$@"
