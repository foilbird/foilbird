#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build the slot initrd and stage it for the main image: build.sh [mkosi options]
#   -> out/initrd.cpio.zst (taken by images/debian/mkosi/mkosi.conf.d/40-initrd.conf).
# Build before the main image (and before a profile); without it the main image build fails (Initrds= file missing).
set -euo pipefail
cd "$(dirname "$0")"
# Reproducible build (docs/reproducible-build.md): the Debian snapshot must agree with the sandbox updates source; mtimes from the commit
sh ../tools/snapshot check >/dev/null
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
mkosi -f --output-directory=mkosi.output "$@" build
mkdir -p out
cp mkosi.output/initrd.cpio.zst out/initrd.cpio.zst
ls -la out/initrd.cpio.zst
