#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Ephemeral TEST keys for one harness run. Every certificate and key name says TEST; nothing here may sign anything
# outside a test, and the directory lives on tmpfs (removed by run.sh unless KEEP=1).
#
#   keys.sh gen <dir>      create the set below in <dir> (must not exist or be empty); prints fingerprints only
#   keys.sh check <dir>    verify that <dir> holds a complete set
#
# <dir>/
#   sb/PK.{key,crt} sb/KEK.{key,crt}   platform and key-exchange keys (enrolled by vm.sh with --enroll vars)
#   sb/db.{key,crt}                    Secure Boot db key: build-image.sh --sb-key/--sb-cert (signs UKI, verity, modules)
#   sb/owner.guid                      owner GUID of the enrolled certificates
#   pcr/pcr-e1.{key,crt,pem}           PCR 11 policy key of epoch 1 (build-image.sh --pcr-key/--pcr-cert; .pem = public)
#   pcr/pcr-e2.{key,crt,pem}           the same for epoch 2 (a release that raises the epoch)
#   gpg/ + release.pgp                 release key of the channel (build-image.sh --release-keyring; signs SHA256SUMS)
#   pki/ca.{crt,key}                   client and server CA of the agent
#   pki/agent.{crt,key}                agent server certificate, SAN DNS:$SERVER_NAME (serverAuth)
#   pki/channel.{crt,key}              release channel server (lib/channel.sh), SAN IP:10.0.2.2 (the host as a QEMU
#                                      user-net guest sees it) and IP:127.0.0.1 (serverAuth)
#   pki/<role>/{ca.crt,client.crt,client.key}   foilctl --tls-dir per role: reader diag controller operator (clientAuth,
#                                      role in OU)
#   smbios/agent.tls-{cert,key,ca}     the agent's TLS material as systemd credentials for QEMU -smbios type=11
#   keys.txt                           SHA-256 fingerprints
set -euo pipefail
umask 077
SERVER_NAME=${SERVER_NAME:-agent.test}
ROLES="reader diag controller operator"
DAYS=${KEY_DAYS:-7}

gen() {
  local d=$1
  if [ -e "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then echo "keys.sh: $d is not empty" >&2; exit 2; fi
  mkdir -p "$d"/{sb,pcr,gpg,pki,smbios}; chmod 700 "$d" "$d"/*
  local x
  for x in PK KEK db; do
    openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -subj "/CN=TEST ephemeral Secure Boot $x" \
      -keyout "$d/sb/$x.key" -out "$d/sb/$x.crt" 2>/dev/null
  done
  python3 -I -c 'import uuid; print(uuid.uuid4())' > "$d/sb/owner.guid"
  for x in e1 e2; do
    openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -subj "/CN=TEST ephemeral PCR policy $x" \
      -keyout "$d/pcr/pcr-$x.key" -out "$d/pcr/pcr-$x.crt" 2>/dev/null
    openssl pkey -in "$d/pcr/pcr-$x.key" -pubout -out "$d/pcr/pcr-$x.pem"
  done
  gpg --homedir "$d/gpg" --batch --passphrase '' --quick-gen-key 'TEST ephemeral release <release@example.invalid>' \
    ed25519 sign "${DAYS}d" 2>/dev/null
  gpg --homedir "$d/gpg" --batch --export > "$d/release.pgp"

  local p=$d/pki
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days "$DAYS" -subj "/CN=TEST ephemeral agent CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$p/ca.key" -out "$p/ca.crt" 2>/dev/null
  sign() { # sign <name> <subject> <extensions>
    printf '%b' "$3" > "$p/$1.ext"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "$2" -keyout "$p/$1.key" -out "$p/$1.csr" 2>/dev/null
    openssl x509 -req -in "$p/$1.csr" -CA "$p/ca.crt" -CAkey "$p/ca.key" -CAcreateserial -days "$DAYS" \
      -extfile "$p/$1.ext" -out "$p/$1.crt" 2>/dev/null
    rm -f "$p/$1.csr" "$p/$1.ext"
  }
  sign agent "/CN=TEST agent" "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:$SERVER_NAME\n"
  sign channel "/CN=TEST channel" "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:10.0.2.2,IP:127.0.0.1\n"
  local r
  for r in $ROLES; do
    sign "cli-$r" "/CN=TEST $r/OU=$r" "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n"
    mkdir -p "$p/$r"; cp "$p/ca.crt" "$p/$r/ca.crt"; mv "$p/cli-$r.crt" "$p/$r/client.crt"; mv "$p/cli-$r.key" "$p/$r/client.key"
  done
  rm -f "$p/ca.srl"
  cred() { printf 'io.systemd.credential.binary:%s=%s' "$1" "$(base64 -w0 < "$2")" > "$d/smbios/$1"; }
  cred agent.tls-cert "$p/agent.crt"; cred agent.tls-key "$p/agent.key"; cred agent.tls-ca "$p/ca.crt"

  {
    for x in sb/PK.crt sb/KEK.crt sb/db.crt pcr/pcr-e1.crt pcr/pcr-e2.crt pki/ca.crt pki/agent.crt pki/channel.crt; do
      printf '%-16s %s\n' "$x" "$(openssl x509 -in "$d/$x" -noout -fingerprint -sha256 | cut -d= -f2)"
    done
    printf '%-16s %s\n' release.pgp "$(gpg --homedir "$d/gpg" --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')"
  } > "$d/keys.txt"
  cat "$d/keys.txt"
}

check() {
  local d=$1 f miss=""
  for f in sb/PK.crt sb/KEK.crt sb/db.key sb/db.crt sb/owner.guid pcr/pcr-e1.key pcr/pcr-e1.crt pcr/pcr-e2.key \
           pcr/pcr-e2.crt release.pgp pki/ca.crt pki/agent.crt pki/channel.crt pki/channel.key smbios/agent.tls-cert smbios/agent.tls-key smbios/agent.tls-ca; do
    [ -s "$d/$f" ] || miss="$miss $f"
  done
  for f in $ROLES; do [ -s "$d/pki/$f/client.crt" ] || miss="$miss pki/$f"; done
  [ -z "$miss" ] || { echo "keys.sh: $d incomplete:$miss" >&2; exit 1; }
}

case ${1:-} in
  gen) gen "${2:?keys.sh gen <dir>}" ;;
  check) check "${2:?keys.sh check <dir>}" ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 2 ;;
esac
