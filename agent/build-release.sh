#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Reproducible static build of foil-agent and foilctl (musl), with the crate
# list embedded (cargo-auditable) and a CycloneDX SBOM next to the binary.
#   needs: rustup (the toolchain and the musl target come from rust-toolchain.toml), musl-gcc,
#          cargo-auditable and cargo-cyclonedx of the versions below, at ONE absolute path on every build machine:
#          /opt/foilbird-build-tools/auditable-<V>_cyclonedx-<V>_rust-<V> (docs/reproducible-build.md, "Build tools of
#          the agent": cargo puts the path of cargo-auditable, the rustc wrapper, into the hash of every crate it builds)
#   build-release.sh --install-tools: cargo install --locked of those versions into that directory
#   build-release.sh --print-tools-root: print that directory and exit (no toolchain needed; CI cleans exactly it)
#   TOOLS_ROOT: may be set only to that directory (anything else is refused); its bin/ goes first in PATH
#   out:   $OUT (default ./dist): foil-agent, foilctl, foil-agent.cdx.json, SHA256SUMS
#   FEATURES: cargo features; empty = product build. Lab images that still take
#          the agent's TLS material from the ESP: FEATURES=esp-bridge-tls
#   Offline (no rustup, no network): tools/offline-inputs.sh install installs the tools with --install-tools (crates.io
#          replaced by the vendored crates: the same crates, the same command, the same path) and prints the environment
#          (PATH with the toolchain, CARGO_HOME with the vendored crates at the registry path of an online build,
#          VENDOR_DIR, CARGO_NET_OFFLINE); the RUSTFLAGS are the same as online. VENDOR_DIR: only checked to be absent
#          from the SBOM
set -eu
cd "$(dirname "$0")"
OUT=${OUT:-$PWD/dist}
TARGET=x86_64-unknown-linux-musl
# Commit time of the tree; falls back to a fixed value outside git.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 1767225600)}
export SOURCE_DATE_EPOCH
CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
# Build tools pinned like the compiler: they write the embedded crate list and the SBOM of the release.
CARGO_AUDITABLE_VERSION=0.7.7
CARGO_CYCLONEDX_VERSION=0.5.10
want_rust=$(sed -n 's/^channel *= *"\([0-9.]*\)".*/\1/p' rust-toolchain.toml)
# The build tools at one absolute path, the same on every build machine (the wrapper's path is in the crates' hashes).
TOOLS_BASE=/opt/foilbird-build-tools
TOOLS_SET=$TOOLS_BASE/auditable-${CARGO_AUDITABLE_VERSION}_cyclonedx-${CARGO_CYCLONEDX_VERSION}_rust-$want_rust
[ "${1:-}" = --print-tools-root ] && { echo "$TOOLS_SET"; exit 0; }
# the compiler of rust-toolchain.toml, also when cargo is not rustup's proxy (an offline toolchain in PATH)
case $(rustc --version 2>/dev/null) in
    "rustc $want_rust "*) ;;
    *) echo "build-release: rustc is '$(rustc --version 2>/dev/null)', rust-toolchain.toml wants $want_rust" >&2; exit 1 ;;
esac
if [ -n "${TOOLS_ROOT:-}" ] && [ "$TOOLS_ROOT" != "$TOOLS_SET" ]; then
    echo "build-release: TOOLS_ROOT=$TOOLS_ROOT, but the build tools must be at $TOOLS_SET (docs/reproducible-build.md)" >&2; exit 1
fi
TOOLS_ROOT=$TOOLS_SET
# the caller may be a uid with no passwd entry (CI runs the agent build as docker exec -u <uid>:<gid>): `id -un` fails
# there and set -e would end the script without a line; the number names the owner just as well
who=$(id -un 2>/dev/null || id -u); grp=$(id -gn 2>/dev/null || id -g)
mk="create it once: sudo install -d -o $who -g $grp $TOOLS_BASE"
[ -d "$TOOLS_BASE" ] || { echo "build-release: $TOOLS_BASE missing; $mk" >&2; exit 1; }
PATH=$TOOLS_ROOT/bin:$PATH
if [ "${1:-}" = --install-tools ]; then
    { [ -w "$TOOLS_BASE" ] || [ -w "$TOOLS_ROOT" ]; } || { echo "build-release: $TOOLS_BASE not writable for $who; $mk" >&2; exit 1; }
    mkdir -p "$TOOLS_ROOT"
    # a fixed build directory and the same path mapping online and offline: the tools' binaries do not depend on
    # CARGO_HOME or on cargo install's temporary directory
    b=$TOOLS_ROOT/.build; rm -rf "$b"
    for t in "cargo-auditable $CARGO_AUDITABLE_VERSION" "cargo-cyclonedx $CARGO_CYCLONEDX_VERSION"; do
        RUSTFLAGS="--remap-path-prefix=$CARGO_HOME=/cargo --remap-path-prefix=$b=/build" CARGO_INCREMENTAL=0 \
            cargo install --locked --root "$TOOLS_ROOT" --target-dir "$b" "${t% *}" --version "=${t#* }"
    done
    rm -rf "$b"
    exit 0
fi
# cargo-auditable has no --version of its own (it forwards to cargo): its version is read from cargo install's record.
grep -q -F "\"cargo-auditable $CARGO_AUDITABLE_VERSION " "$TOOLS_ROOT/.crates.toml" 2>/dev/null ||
    { echo "build-release: need cargo-auditable $CARGO_AUDITABLE_VERSION in $TOOLS_ROOT: ./build-release.sh --install-tools" >&2; exit 1; }
case $(cargo cyclonedx --version 2>/dev/null) in
    *" $CARGO_CYCLONEDX_VERSION") ;;
    *) echo "build-release: need cargo-cyclonedx $CARGO_CYCLONEDX_VERSION in $TOOLS_ROOT: ./build-release.sh --install-tools" >&2; exit 1 ;;
esac
export RUSTFLAGS="-C target-feature=+crt-static --remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME=/cargo"
export CARGO_INCREMENTAL=0
FEATURES=${FEATURES:-}
cargo auditable build --release --locked --target "$TARGET" --bins ${FEATURES:+--features "$FEATURES"}
mkdir -p "$OUT"
for b in foil-agent foilctl; do
    install -m 0755 "target/$TARGET/release/$b" "$OUT/$b"
done
cargo cyclonedx --format json --target "$TARGET" --override-filename foil-agent.cdx >/dev/null
# cargo-cyclonedx names the crate by its manifest path (bom-ref, purl, bin targets): path+file://<build dir>. The binaries
# carry /src for that directory (--remap-path-prefix), so does the SBOM; no path of the build machine may reach the image.
sed "s|path+file://$PWD|path+file:///src|g" foil-agent.cdx.json > "$OUT/foil-agent.cdx.json" && rm foil-agent.cdx.json
if grep -q -F -e "$PWD" -e "$CARGO_HOME" ${VENDOR_DIR:+-e "$VENDOR_DIR"} "$OUT/foil-agent.cdx.json"; then
    echo "build-release: a build path is left in foil-agent.cdx.json" >&2; exit 1
fi
echo "features: ${FEATURES:--}" > "$OUT/FEATURES"
(cd "$OUT" && sha256sum foil-agent foilctl > SHA256SUMS && cat SHA256SUMS FEATURES)
