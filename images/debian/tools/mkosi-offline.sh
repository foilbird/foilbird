# SPDX-License-Identifier: Apache-2.0
# Sourced by the three mkosi entries (foilbird-initrd/build.sh, recovery/build.sh, build-image.sh): the offline inputs of
# docs/ci-gitlab.md as mkosi options, from the environment the caller lists explicitly (build-all.sh, never sudo -E).
#   NL_PKGCACHE  absolute directory: mkosi's package cache (PackageCacheDirectory=, multiversal: the image and the tools
#                tree) and, under mkosi-cache/, its repository metadata (CacheDirectory=, the image only), filled by an
#                online build of the same revision and carried in the input bundle
#   NL_OFFLINE   1: mkosi installs from that cache only (CacheOnly=always: "the package manager is instructed not to
#                contact the network"); requires NL_PKGCACHE
# Sets the array mkosi_offline (empty without them).
mkosi_offline=()
case ${NL_OFFLINE:-0} in 0|1) ;; *) echo "NL_OFFLINE must be 0 or 1" >&2; exit 2 ;; esac
if [ -n "${NL_PKGCACHE:-}" ]; then
  case $NL_PKGCACHE in /*) ;; *) echo "NL_PKGCACHE must be an absolute path" >&2; exit 2 ;; esac
  [ -d "$NL_PKGCACHE" ] || { echo "NL_PKGCACHE $NL_PKGCACHE: no such directory" >&2; exit 2; }
  # mkosi keeps the repository metadata (apt lists: InRelease, Packages) in CacheDirectory/<key>.metadata.cache, not in
  # the package cache; without a CacheDirectory it is a temporary directory and an offline build finds no package.
  # Incremental is off, so CacheDirectory holds nothing of the image itself (mkosi v26: have_cache()).
  mkosi_offline+=(--package-cache-dir="$NL_PKGCACHE" --cache-directory="$NL_PKGCACHE/mkosi-cache")
fi
if [ "${NL_OFFLINE:-0}" = 1 ]; then
  [ -n "${NL_PKGCACHE:-}" ] || { echo "NL_OFFLINE=1 needs NL_PKGCACHE (the bundle's package cache)" >&2; exit 2; }
  mkosi_offline+=(--cache-only=always)
fi
