# SPDX-License-Identifier: Apache-2.0
# Release channel of the harness (sourced after common.sh; bash): the directory $CHANNEL served over https on
# 127.0.0.1:<free port> with the TEST certificate pki/channel (SAN IP:10.0.2.2), which a QEMU user-net guest reaches
# as https://10.0.2.2:<port>/. The node gets it the product way: NodeConfig.update_channel (foilctl --channel
# 10.0.2.2:<port>/ --channel-ca $KEYS/pki/ca.crt, ApplyConfig); trust comes only from SHA256SUMS signed with the
# image's release key.
#
# $CHANNEL is what the build publishes: SHA256SUMS + SHA256SUMS.gpg (release key of $KEYS, the key the images were
# built with) and per release V the files named there (foilbird-deb_V.efi, the usr / verity / verity-sig partitions,
# compressed or not).
#
#   channel_up                 check the signature and every listed file, start the server; sets CHANNEL_PORT
#   channel_down
#   channel_args               foilctl apply arguments of the channel
#   channel_has <V>            release V is listed (its UKI)
#   channel_usrhash <V>        usrhash= of the UKI of release V (the root hash its kernel command line pins)

channel_up() {
  local d=${CHANNEL:?CHANNEL=<published release channel dir>} w=${WORK:?}/channel
  [ -s "$d/SHA256SUMS" ] && [ -s "$d/SHA256SUMS.gpg" ] || die "channel: $d needs SHA256SUMS and SHA256SUMS.gpg"
  mkdir -p "$w/gpg"; chmod 700 "$w" "$w/gpg"
  gpg --homedir "$w/gpg" --batch -q --import "$KEYS/release.pgp" 2>/dev/null
  gpg --homedir "$w/gpg" --batch --status-fd 1 --verify "$d/SHA256SUMS.gpg" "$d/SHA256SUMS" > "$w/verify.txt" 2>&1
  grep -q '^\[GNUPG:\] VALIDSIG' "$w/verify.txt" || die "channel: SHA256SUMS not signed by the release key of KEYS ($w/verify.txt)"
  (cd "$d" && sha256sum --quiet -c SHA256SUMS) > "$w/sums.txt" 2>&1 || die "channel: a listed file is missing or differs ($w/sums.txt)"
  CHANNEL_PORT=$(free_port)
  python3 -I - "$d" "$CHANNEL_PORT" "$KEYS/pki/channel.crt" "$KEYS/pki/channel.key" > "$w/server.log" 2>&1 < <(cat <<'PY'
import functools, http.server, ssl, sys
d, port, crt, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(crt, key)
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=d)
class S(http.server.ThreadingHTTPServer):
    # TLS per connection in its own thread: accept() stays plain, so one slow or broken handshake never holds the others
    request_queue_size = 64
    def finish_request(self, request, client_address):
        try:
            request = ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            print("tls handshake from %s:%s failed: %s" % (client_address[0], client_address[1], e), file=sys.stderr, flush=True)
            return
        super().finish_request(request, client_address)
s = S(("127.0.0.1", port), h)
print("serving", d, "on", port, flush=True); s.serve_forever()
PY
) &
  echo $! > "$w/server.pid"
  local i; for i in $(seq 50); do grep -q '^serving' "$w/server.log" 2>/dev/null && break; sleep 0.1; done
  grep -q '^serving' "$w/server.log" || die "channel: server did not start ($w/server.log)"
  export CHANNEL_PORT
  log "channel: $d on https://127.0.0.1:$CHANNEL_PORT (guest 10.0.2.2:$CHANNEL_PORT), SHA256SUMS $(sha256sum < "$d/SHA256SUMS" | cut -c1-16) signed"
}

channel_down() { local f=${WORK:?}/channel/server.pid; [ -s "$f" ] && kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; return 0; }

channel_args() { echo --channel "10.0.2.2:${CHANNEL_PORT:?channel_up first}/" --channel-ca "$KEYS/pki/ca.crt"; }

channel_has() { [ -n "${CHANNEL:-}" ] && grep -q -E "[ *]foilbird-deb_$1\.efi\$" "$CHANNEL/SHA256SUMS" 2>/dev/null; }

channel_usrhash() { grep -a -o -m1 'usrhash=[0-9a-f]*' "$CHANNEL/foilbird-deb_$1.efi" 2>/dev/null | head -1 | cut -d= -f2; }
