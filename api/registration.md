# Node registration (draft, stage 5 — not implemented)

Registration and the node CA belong to the gateway/controller (Go).
The agent is the **client** of this service. This document fixes what the agent
sends, what it receives and where it keeps it, so both sides can be built
independently. It becomes `proto/foilbird/registration/v1/` when stage 5 starts.

## Modes of the agent
| Mode | Trigger | Served |
|---|---|---|
| `REGISTRATION` | no node certificate in `/var/lib/foil-agent/identity/` | NodeAgent API is **not** served; the agent runs the registration client and reports progress on the console |
| `OPERATIONAL` | valid node certificate | NodeAgent over mTLS with the node certificate |
| `BRIDGE` | TEST only, lab build (`--features esp-bridge-tls`): `agent.tls-*` and the bridge configuration (`node.*`, `k8s.*`) in `/boot/loader/foilbird` | as today; goes away with registration. A product build ignores the ESP (TLS material and configuration) and refuses to start without credentials |

## Exchange (agent → registration service, server-authenticated TLS)
The registration endpoint and its CA certificate come from the image (or, in
TEST, the bridge), never from a caller.

1. `Begin(ek_cert, ek_pub, ak_pub, ak_name, csr, image_version, machine_serial)`
   - `ek_cert`: from TPM NV (`0x01c00002` RSA / `0x01c0000a` ECC); swtpm has a
     self-signed one, accepted only when the service runs with `lab` (config of
     the service, not of the node);
   - `ak`: restricted signing key created by the agent under the endorsement hierarchy;
   - `csr`: PKCS#10 for the mTLS key (subject = machine-id; key in the TPM or,
     for the PoC, on `/var` under LUKS);
   - returns `request_id`, `nonce`, `credential_blob`, `encrypted_secret`
     (TPM2_MakeCredential to EK + AK name).
2. `Complete(request_id, secret, quote)`
   - `secret`: TPM2_ActivateCredential result — proves the AK lives in this TPM;
   - `quote`: TPM2_Quote by AK over PCR 7 and 11 with `nonce` — the service
     compares with the expected values of `image_version`;
   - returns `PENDING_APPROVAL`.
3. Operator approval in the gateway (EK fingerprint and serial checked against
   inventory/BMC). Without it no certificate is issued (T11).
4. `Status(request_id)` → `PENDING_APPROVAL | REJECTED(reason) | ISSUED(cert_chain, ca_bundle, not_after)`;
   the agent polls with back-off.

## Stored on the node (`/var/lib/foil-agent/identity/`, 0700, noexec)
`node.crt`, `node.key` (or a TPM handle), `ca.pem` (client CA for the gateway and
operator certificates), `request.json` (request id while pending). Nothing of
it is on the ESP.

## After registration
- Client roles stay as today (Subject OU `controller` / `operator`).
- EMERGENCY RPCs `Reset`, `RotateIdentity` only for `operator` (T12).
- Short-lived node certificate (days); renewal by a new CSR with the same key.
- Lost trust → re-registration through the BMC console.

## Open decisions (stage 5)
- TPM library: `tss-esapi` with libtss2 (glibc build for Debian 13) — preferred;
  own TPM2 client only for a strong reason.
- mTLS key in the TPM (custom rustls signer) or on `/var`.
