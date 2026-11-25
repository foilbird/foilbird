#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Stage the agent into an mkosi extra tree: out/ (gitignored), consumed by
# images/debian/mkosi/mkosi.conf.d/50-agent.conf (ExtraTrees=).
#   stage-image-tree.sh <dist-dir>   (dist from build-release.sh, with SHA256SUMS)
# Units are enabled by symlinks in /usr (the image has an empty /etc).
set -eu
cd "$(dirname "$0")"
dist=${1:?dist dir}
(cd "$dist" && sha256sum -c --quiet SHA256SUMS) || { echo "dist: sha256 mismatch" >&2; exit 1; }
rm -rf out && mkdir out && : > out/.keep
u=out/usr/lib/systemd/system
install -D -m 0755 "$dist/foil-agent" out/usr/bin/foil-agent
for f in foil-config.service foil-agent.service foil-boot-check.service; do
    install -D -m 0644 "systemd/$f" "$u/$f"
done
install -D -m 0644 systemd/foil-agent.tmpfiles out/usr/lib/tmpfiles.d/foil-agent.conf
mkdir -p "$u/sysinit.target.wants" "$u/multi-user.target.wants" "$u/boot-complete.target.requires"
ln -s ../foil-config.service "$u/sysinit.target.wants/foil-config.service"
ln -s ../foil-agent.service "$u/multi-user.target.wants/foil-agent.service"
ln -s ../foil-boot-check.service "$u/multi-user.target.wants/foil-boot-check.service"
ln -s ../foil-boot-check.service "$u/boot-complete.target.requires/foil-boot-check.service"
install -D -m 0644 "$dist/foil-agent.cdx.json" out/usr/share/foil-agent/sbom.cdx.json
grep ' foil-agent$' "$dist/SHA256SUMS" > out/usr/share/foil-agent/SHA256SUMS
echo "staged: $(sha256sum out/usr/bin/foil-agent)"
