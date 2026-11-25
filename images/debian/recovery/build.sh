#!/bin/bash
# Build the recovery UKI and stage it for the main image: build.sh [mkosi options]
#   -> out/EFI/Linux/foilbird-recovery.efi (copied onto the ESP by images/debian/mkosi/mkosi.conf.d/60-recovery.conf).
# Build before the main image; without it the main image has no recovery entry.
set -euo pipefail
cd "$(dirname "$0")"
# Reproducible build (docs/reproducible-build.md): the Debian snapshot must agree with the sandbox updates source; mtimes from the commit
sh ../tools/snapshot check >/dev/null
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
. "$(dirname "$0")/../tools/mkosi-offline.sh"   # NL_PKGCACHE / NL_OFFLINE -> mkosi options
mkosi -f --output-directory=mkosi.output "${mkosi_offline[@]}" "$@" build
mkdir -p out/EFI/Linux
cp mkosi.output/foilbird-recovery.efi out/EFI/Linux/foilbird-recovery.efi
ls -la out/EFI/Linux/foilbird-recovery.efi
