#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Regenerate the release-channel fixtures (needs gpg). Throw-away keys: only
# the public release key and the signatures are kept; secret keys are deleted.
#   channel/          versions 2 (complete), 3 (no verity-sig), 4 (usr does not match SHA256SUMS)
#   release.pgp       public key that signed channel/SHA256SUMS.gpg
#   SHA256SUMS.other.gpg  the same manifest signed by an unrelated key (T10)
set -eu
cd "$(dirname "$0")"
G=$(mktemp -d); O=$(mktemp -d); trap 'rm -rf "$G" "$O"' EXIT
gpg --homedir "$G" --batch --passphrase '' --quick-gen-key 'foilbird test release <release@example.invalid>' ed25519 sign never 2>/dev/null
gpg --homedir "$O" --batch --passphrase '' --quick-gen-key 'unrelated <other@example.invalid>' ed25519 sign never 2>/dev/null
rm -rf channel; mkdir channel; cd channel
for v in 2 3 4; do
    printf 'uki %s\n' $v > foilbird_$v.efi
    printf 'usr %s\n' $v > foilbird_$v.usr-x86-64.0f0f.raw.zst
    printf 'verity %s\n' $v > foilbird_$v.usr-x86-64-verity.1e1e.raw.zst
    printf 'sig %s\n' $v > foilbird_$v.usr-x86-64-verity-sig.2d2d.raw.zst
done
rm foilbird_3.usr-x86-64-verity-sig.2d2d.raw.zst
sha256sum -- * > SHA256SUMS
printf 'tampered\n' > foilbird_4.usr-x86-64.0f0f.raw.zst
gpg --homedir "$G" --batch --yes --detach-sign -o SHA256SUMS.gpg SHA256SUMS
gpg --homedir "$O" --batch --yes --detach-sign -o ../SHA256SUMS.other.gpg SHA256SUMS
gpg --homedir "$G" --export > ../release.pgp
ls -la . ..
