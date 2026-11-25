#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Offline inputs of the agent build: the Rust toolchain of rust-toolchain.toml, the crates of Cargo.lock and the two build
# tools of build-release.sh, as one directory that is fetched where there is network and verified and installed where
# there is none. The agent is then built by the same build-release.sh, without rustup and without network.
#
#   offline-inputs.sh fetch   <dir>            network: download, verify, vendor; writes <dir>/MANIFEST.sha256
#   offline-inputs.sh verify  <dir>            no network: every file against MANIFEST.sha256, the toolchain signatures
#                                              against the pinned Rust release key, every .crate against its checksum
#   offline-inputs.sh install <dir> <prefix>   no network: verify, then the toolchain into <prefix>, CARGO_HOME
#                                              <prefix>/cargo-home with the vendored crates, the two tools by
#                                              `build-release.sh --install-tools` into /opt/foilbird-build-tools/<set> (the
#                                              same command and path as online); prints the environment (eval it)
#
# <dir> after fetch:
#   rust/       rust-<V>-x86_64-unknown-linux-gnu.tar.xz, rust-std-<V>-x86_64-unknown-linux-musl.tar.xz, each with .sha256
#               and .asc (static.rust-lang.org); rust-key.gpg.ascii (the release key, checked against RUST_KEY_FPR)
#   tools-src/  cargo-auditable-<V>, cargo-cyclonedx-<V>: the .crate files (static.crates.io) with the sha256 of the
#               crates.io index entry, unpacked (their own Cargo.lock)
#   vendor/     `cargo vendor --versioned-dirs` of agent/Cargo.lock and both tools' Cargo.lock (cargo checks each crate
#               against its .cargo-checksum.json at build time), plus the two tool crates themselves as crates.io crates
#               (unpacked .crate + .cargo-checksum.json, package = the sha256 checked against the crates.io index), so
#               that they are installed offline from the same source (crates.io, replaced) as online
#   PROVENANCE  every download: URL, sha256, and how it was verified;  MANIFEST.sha256  sha256 of every file
# Versions come from the tree: rust-toolchain.toml (channel, targets) and build-release.sh (CARGO_*_VERSION). A different
# toolchain or tool version in the tree than in <dir> is refused.
# Reproducibility: install puts the vendored crates where an online build extracts them, $CARGO_HOME/registry/src/
# index.crates.io-<hash>/<name>-<version>, so the existing --remap-path-prefix=$CARGO_HOME=/cargo of build-release.sh
# covers them and the RUSTFLAGS of both builds are the same (cargo hashes RUSTFLAGS into the unit metadata: one more
# flag offline changed every symbol hash of the binaries).
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)   # agent/
die() { echo "offline-inputs.sh: $*" >&2; exit 2; }
# Rust release signing key ("Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>"); a different key
# stops fetch and verify. The key file is https://static.rust-lang.org/rust-key.gpg.ascii; this is its primary
# fingerprint (signatures are made by its subkey 29D57CE15D76E78CD57D326A8E9AA3F7AB3F5826; VALIDSIG names the primary).
RUST_KEY_FPR=108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE # gitleaks:allow (public fingerprint of the Rust release key, published at rust-lang.org)
DIST=https://static.rust-lang.org/dist
RUST_VERSION=$(sed -n 's/^channel *= *"\([0-9.]*\)".*/\1/p' "$here/rust-toolchain.toml")
grep -q 'x86_64-unknown-linux-musl' "$here/rust-toolchain.toml" || die "rust-toolchain.toml: no musl target"
AUD=$(sed -n 's/^CARGO_AUDITABLE_VERSION=//p' "$here/build-release.sh"); CDX=$(sed -n 's/^CARGO_CYCLONEDX_VERSION=//p' "$here/build-release.sh")
[ -n "$RUST_VERSION" ] && [ -n "$AUD" ] && [ -n "$CDX" ] || die "versions not found in rust-toolchain.toml / build-release.sh"
TARBALLS="rust-$RUST_VERSION-x86_64-unknown-linux-gnu.tar.xz rust-std-$RUST_VERSION-x86_64-unknown-linux-musl.tar.xz"
TOOLS="cargo-auditable:$AUD cargo-cyclonedx:$CDX"

gpgcheck() { # gpgcheck <dir>: the key file has exactly the pinned primary key; every .asc verifies with it
  local d=$1 g; g=$(mktemp -d)
  local fprs; fprs=$(gpg --homedir "$g" --batch --with-colons --show-keys "$d/rust/rust-key.gpg.ascii" 2>/dev/null | awk -F: '$1=="pub"{p=1;next} p&&$1=="fpr"{print $10; p=0}')
  [ "$fprs" = "$RUST_KEY_FPR" ] || { rm -rf "$g"; die "rust-key.gpg.ascii: primary key [$fprs], pinned $RUST_KEY_FPR"; }
  gpg --homedir "$g" --batch -q --import "$d/rust/rust-key.gpg.ascii" 2>/dev/null
  local t; for t in $TARBALLS; do
    gpg --homedir "$g" --batch --status-fd 1 --verify "$d/rust/$t.asc" "$d/rust/$t" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG .* $RUST_KEY_FPR\$" ||
      { rm -rf "$g"; die "$t: no valid signature of $RUST_KEY_FPR"; }
    (cd "$d/rust" && sha256sum -c --quiet "$t.sha256") || { rm -rf "$g"; die "$t: sha256 differs from $t.sha256"; }
  done
  rm -rf "$g"
}

cratecheck() { # cratecheck <dir>: every tool .crate = the sha256 recorded from the crates.io index at fetch
  local d=$1 nv n v want
  for nv in $TOOLS; do n=${nv%%:*}; v=${nv#*:}
    want=$(sed -n "s/^crate $n $v sha256 \([0-9a-f]*\) .*/\1/p" "$d/PROVENANCE")
    [ -n "$want" ] && [ "$(sha256sum < "$d/tools-src/$n-$v.crate" | cut -c1-64)" = "$want" ] || die "$n-$v.crate: checksum"
  done
}

verify() { # verify <dir>
  local d=$1
  [ -s "$d/MANIFEST.sha256" ] || die "$d: no MANIFEST.sha256 (fetch first)"
  grep -qx "rust $RUST_VERSION" "$d/VERSIONS" && grep -qx "cargo-auditable $AUD" "$d/VERSIONS" && grep -qx "cargo-cyclonedx $CDX" "$d/VERSIONS" ||
    die "$d holds other versions than the tree ($(paste -sd, "$d/VERSIONS")): fetch again"
  (cd "$d" && sha256sum -c --quiet MANIFEST.sha256) || die "$d: a file differs from MANIFEST.sha256"
  local extra; extra=$(cd "$d" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort | LC_ALL=C comm -23 - <(cut -c67- MANIFEST.sha256 | LC_ALL=C sort))
  [ -z "$extra" ] || die "$d: files not in MANIFEST.sha256: $(echo "$extra" | head -n 3 | paste -sd' ')"
  gpgcheck "$d"; cratecheck "$d"
  echo "offline-inputs: verified $d (rust $RUST_VERSION, cargo-auditable $AUD, cargo-cyclonedx $CDX, $(grep -c . "$d/MANIFEST.sha256") files, MANIFEST $(sha256sum < "$d/MANIFEST.sha256" | cut -c1-16))"
}

fetch() { # fetch <dir>
  local d=$1; [ -e "$d" ] && die "$d exists: fetch into a new directory"
  mkdir -p "$d/rust" "$d/tools-src"; d=$(cd "$d" && pwd)
  local P=$d/PROVENANCE; : > "$P"
  get() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; echo "get $1 sha256 $(sha256sum < "$2" | cut -c1-64)" >> "$P"; }
  get "https://static.rust-lang.org/rust-key.gpg.ascii" "$d/rust/rust-key.gpg.ascii"
  local t; for t in $TARBALLS; do
    get "$DIST/$t" "$d/rust/$t"; get "$DIST/$t.sha256" "$d/rust/$t.sha256"; get "$DIST/$t.asc" "$d/rust/$t.asc"
    # the .sha256 file names the tarball without a directory; keep only that line form
    awk -v t="$t" '{print $1"  "t}' "$d/rust/$t.sha256" > "$d/rust/$t.sha256.tmp" && mv "$d/rust/$t.sha256.tmp" "$d/rust/$t.sha256"
  done
  gpgcheck "$d"; echo "verified rust: signatures of $RUST_KEY_FPR, sha256 of the .sha256 files" >> "$P"
  local nv n v idx sum
  for nv in $TOOLS; do n=${nv%%:*}; v=${nv#*:}
    # crates.io sparse index path of a name of 4 or more characters: <first two>/<next two>/<name>
    idx="https://index.crates.io/${n:0:2}/${n:2:2}/$n"
    sum=$(curl -fsSL --proto '=https' --retry 3 "$idx" | python3 -I -c 'import json,sys
v=sys.argv[1]
for l in sys.stdin:
    e=json.loads(l)
    if e["vers"]==v and not e.get("yanked"): print(e["cksum"]); break' "$v")
    [ -n "$sum" ] || die "$n $v: not in the crates.io index (or yanked)"
    get "https://static.crates.io/crates/$n/$n-$v.crate" "$d/tools-src/$n-$v.crate"
    [ "$(sha256sum < "$d/tools-src/$n-$v.crate" | cut -c1-64)" = "$sum" ] || die "$n-$v.crate: sha256 differs from the index"
    echo "crate $n $v sha256 $sum (crates.io index $idx)" >> "$P"
    tar -xzf "$d/tools-src/$n-$v.crate" -C "$d/tools-src"
    [ -s "$d/tools-src/$n-$v/Cargo.lock" ] || die "$n-$v: the crate ships no Cargo.lock (cargo install --locked needs it)"
  done
  # one vendor directory for the agent and both tools; --locked: exactly the versions of the three Cargo.lock files
  (cd "$here" && cargo vendor --locked --versioned-dirs \
     --sync "$d/tools-src/cargo-auditable-$AUD/Cargo.toml" --sync "$d/tools-src/cargo-cyclonedx-$CDX/Cargo.toml" \
     "$d/vendor" > /dev/null)
  echo "vendor: cargo vendor --locked --versioned-dirs of agent/Cargo.lock ($(sha256sum < "$here/Cargo.lock" | cut -c1-16)) and both tools; $(ls "$d/vendor" | wc -l) crates" >> "$P"
  # the tool crates themselves as directory-source entries of crates.io (cargo install <tool> --version, crates.io replaced)
  for nv in $TOOLS; do n=${nv%%:*}; v=${nv#*:}
    [ -e "$d/vendor/$n-$v" ] && die "vendor/$n-$v exists: a tool is also a dependency"
    cp -a "$d/tools-src/$n-$v" "$d/vendor/$n-$v"
    python3 -I - "$d/vendor/$n-$v" "$(sha256sum < "$d/tools-src/$n-$v.crate" | cut -c1-64)" <<'PY'
import hashlib, json, os, sys
root, pkg = sys.argv[1], sys.argv[2]; files = {}
for dp, _, fn in os.walk(root):
    for f in fn:
        p = os.path.join(dp, f); r = os.path.relpath(p, root)
        if r != ".cargo-checksum.json":
            files[r] = hashlib.sha256(open(p, "rb").read()).hexdigest()
json.dump({"files": files, "package": pkg}, open(os.path.join(root, ".cargo-checksum.json"), "w"), sort_keys=True)
PY
    echo "vendor: + $n $v as a crates.io crate (package sha256 = the index entry above)" >> "$P"
  done
  printf 'rust %s\ncargo-auditable %s\ncargo-cyclonedx %s\n' "$RUST_VERSION" "$AUD" "$CDX" > "$d/VERSIONS"
  (cd "$d" && find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed 's|  \./|  |') > "$d/MANIFEST.sha256"
  echo "offline-inputs: fetched $d ($(du -sh "$d" | cut -f1)); MANIFEST $(sha256sum < "$d/MANIFEST.sha256" | cut -c1-16)"
  verify "$d"
}

install_() { # install <dir> <prefix>
  local d; d=$(cd "${1:?dir}" && pwd); local p=${2:?prefix}; [ -e "$p" ] && die "$p exists: install into a new directory"
  verify "$d" >&2
  mkdir -p "$p"; p=$(cd "$p" && pwd); local w; w=$(mktemp -d)
  local t; for t in $TARBALLS; do
    tar -xJf "$d/rust/$t" -C "$w"; (cd "$w/${t%.tar.xz}" && ./install.sh --prefix="$p" --disable-ldconfig > /dev/null)
  done
  rm -rf "$w"
  "$p/bin/rustc" --version | grep -q "^rustc $RUST_VERSION " || die "installed rustc is not $RUST_VERSION"
  # CARGO_HOME of the offline build: crates.io replaced by the vendored crates, copied to the registry path an online
  # build extracts crates.io crates to (cargo >= 1.85: index.crates.io-1949cf8c6b5b557f), no network
  local vdir="$p/cargo-home/registry/src/index.crates.io-1949cf8c6b5b557f"; mkdir -p "$vdir"; cp -a "$d/vendor/." "$vdir/"
  printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n\n[net]\noffline = true\n' \
    "$vdir" > "$p/cargo-home/config.toml"
  # the two tools: the same command, source (crates.io, replaced by the vendored crates) and path as online
  (cd "$here" && PATH="$p/bin:$PATH" CARGO_HOME="$p/cargo-home" CARGO_NET_OFFLINE=true ./build-release.sh --install-tools) >&2 ||
    die "build-release.sh --install-tools failed"
  echo "export PATH='$p/bin':\"\$PATH\" CARGO_HOME='$p/cargo-home' VENDOR_DIR='$vdir' CARGO_NET_OFFLINE=true"
}

case ${1:-} in
  fetch) fetch "${2:?dir}" ;;
  verify) verify "${2:?dir}" ;;
  install) install_ "${2:?dir}" "${3:?prefix}" ;;
  *) sed -n '2,24p' "$0"; exit 2 ;;
esac
