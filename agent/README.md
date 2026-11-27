# foil-agent

Node agent (Rust): the typed gRPC API of `../api/proto` over mutual TLS. No
command execution, no shell; diagnostics only through the API.

| Command | Unit | Purpose |
|---|---|---|
| `foil-agent apply-boot` | `foil-config.service` (before networkd) | render configuration: the one applied through the API (persisted in `/var/lib/foil-agent`) or, if none, the temporary bridge credentials from `/run/credentials/@system/` |
| `foil-agent serve` | `foil-agent.service` | API on `:7443`, TLS material from `ImportCredential=agent.tls-*` (`agent.tls-cert`, `agent.tls-key`, `agent.tls-ca`) |
| `foil-agent boot-check` | `foil-boot-check.service` | health gate before `boot-complete.target` (decision 0003); failure → reboot |
| `foil-agent wait-time-sync` | `ExecStartPre=` of `foil-kubeadm-join.service` | first join only: wait (120 s) for a synchronized clock, else fail with the reason in `GetHealth` |
| `foilctl … info\|health\|config\|update-status\|apply\|reboot\|collect` | — | client for diagnostics and lab tests; `collect --out FILE` writes the `EMERGENCY` dump to a 0600 file only |

## Authorization
Client certificates must chain to the CA in `agent.tls-ca`. The role is the
Subject OU: `controller` may call `READ`, `OPERATE`, `DESTRUCTIVE`; `operator`
may call everything, including `EMERGENCY`; `reader` only `READ`. Any other certificate is denied.
`EMERGENCY` is `CollectDiagnostics` (the unredacted journal of one boot, at most 20000 entries
and 3 MiB, truncation reported); every call is logged on the node with the caller's CN and the
size returned (`audit`), a denied call only as `denied`, before anything is read.
The RPC → level table is generated at build time from the `.proto` options.

## Boot confirmation
`foil-boot-check` waits (default 300 s) until every required check passes and exits 0, letting
`boot-complete.target` and `systemd-bless-boot` commit the entry. Required are only checks a broken
image fails: `/usr` on dm-verity, `/var` mounted (unlocked), `foil-config` active, `foil-agent` active and listening on its API (`127.0.0.1:7443`), the
interfaces of `NodeConfig` applied by networkd without an error and their static addresses on the host
(`network-config`; networkd's AdministrativeState over D-Bus `org.freedesktop.network1`, carrier and a DHCP address
only `WARN`, as Talos: an unplugged cable or a DHCP outage does not roll back; static interfaces are rendered with
`ConfigureWithoutCarrier=yes`/`IgnoreCarrierLoss=yes`, so their addresses and routes stay without a carrier), and on `k8s-worker` `containerd` and
`foil-nvidia-cdi` where the image has it (systemd's `LoadState` over D-Bus: `not-found` = not applicable, `SKIPPED` at
once; skipped by its condition without a GPU; a GPU driven by the `nvidia` module in an image without the unit, or
with it masked, is `FAIL`; its state not readable over D-Bus 120 s after boot is `FAIL`) plus, once the node has joined, kubelet healthy (local
`127.0.0.1:10248/healthz`) and not crash-looping; every NVIDIA GPU on PCI must be driven by the loaded
`nvidia` module (no NVIDIA on PCI: skipped). No required check talks to the API server. Reported only
(`WARN` in `GetHealth`, never a rollback): default route (`network-online`), failed units
(`no-failed-units`) and the clock (below). Unknown or foreign key material on the LUKS2 `/var` (`var-key-slots`, from
the image's report `/run/foilbird/var-epoch/slots`: TPM2 slots of an unknown epoch, slots without or with a foreign
token, broken or duplicate TPM2 tokens, epoch key files that do not fit) is `FAIL` with `CRITICAL:` in `GetHealth` and in the audit log, but is
never gated either: it is an incident on the node, not a broken release. The same holds for the ESP (`esp-writable`): the check opens `/boot/loader` (which mounts the idle automount) and reads `/proc/self/mountinfo`; a read-only ESP (super block options, e.g. FAT remounted `ro` after errors; per-mount flags are `ro` anyway in the agent's `ProtectSystem=strict` namespace) or one the automount fails to mount is `FAIL` with `CRITICAL:`, as the node can then neither bless a boot nor stage an update or roll back; not mounted at rest is normal. An ESP at rest is probed at most every 10 minutes (Linux marks a mounted read-write FAT dirty, so probing on every `GetHealth` would keep it mounted); in between, the last result is reported, and a mounted ESP is read from `mountinfo` without an access. The boot counter in `BootState.tries_left` (report only: no decision uses it) is read from the ESP at most every 10 minutes per mount of the ESP: a listing of a mounted ESP is an access too and restarts its idle timeout, so a controller polling `GetHealth` would keep the FAT mounted for good. A new mount (bless, sysupdate or `foil-rollback@` mounting the idle ESP) is read again; in between the last value is reported, so it can lag a rename by up to 10 minutes; the agent's own StageUpdate and Rollback drop it at once. Hard failures end the wait at once: verity, `/var`, a
crash-looping kubelet of a joined node, an NVIDIA GPU without its driver once `foil-nvidia-cdi`
has finished (at once where the image has no such unit). Clock synchronization is reported by `GetHealth` (`time-synced`) and never gates the boot: it
depends on the environment (NTP reachability), not on the image, and must not roll back nodes while
an NTP server is down. Owner policy: the first Kubernetes join needs a synchronized clock —
`foil-kubeadm-join.service` runs `foil-agent wait-time-sync` first, `time-synced` is `PENDING` while it
waits and `FAIL` after its 120 s (the join retries every 30 s); while the first join is blocked this
way the gate does not wait for kubelet either (rebooting does not fix NTP). Once joined, an
unsynchronized clock is `WARN` only. Failures of `/usr`
verity or `/var` fail the gate at once; other checks are retried until the
timeout. A committed entry stays `<v>.efi` without a counter (no re-arm, decision
0003 amendment): the counter only lives between an A/B switch and the commit. The ESP is
written by the image's units, not by the agent; the agent only reads it.

## Time
`NodeConfig.time.servers` (up to 8 IPv4/IPv6 addresses or lower-case DNS names, no port) is
rendered to `/run/systemd/timesyncd.conf.d/50-foil.conf` (`NTP=`), and the agent restarts
`systemd-timesyncd` when it changes (at boot `foil-config` runs before timesyncd). No servers →
no drop-in: the image default has none (`10-foil.conf` empties `NTP=` and `FallbackNTP=`).
NTP servers announced by DHCP are used too: timesyncd tries the `NTP=` servers first and
falls back to the DHCP ones (seen in tests: about 52 s after a dead configured server,
including timesyncd's pause after exhausting its servers); with a working configured server
DHCP servers are not queried.

Before the node's clock is synchronized (a fresh node before `ApplyConfig` sets its NTP servers, or a node whose
servers do not answer), mTLS judges certificate validity by that clock. A client certificate issued moments ago can be
refused with the TLS alert `CertificateExpired` instead of the error of its real cause (seen: a certificate of a foreign
CA with a fresh `notBefore` on a node whose clock was slightly behind; the same certificate with a `notBefore` in the past
gave `UnknownCA`): rustls checks the validity period before the chain. Either way the call is refused; read an
"expired" right after issuing as "the node's clock", check `health` (`time-synced`) before anything else.

## Diagnostics with foilctl
- `journal --unit` takes the full unit name, `NAME.TYPE` (`foil-agent.service`, `foil-kubeadm-init.service`,
  `kubelet.service`); a short name (`foil-agent`) is refused with InvalidArgument "unit: name.type, e.g. kubelet.service".
- `journal` and `dmesg` are `DIAG` (roles diag, controller, operator, `api/README.md`); `reader` gets PermissionDenied.
- The agent's lines carry the syslog priority of their level when its output is the journal (`<N>` prefix,
  sd-daemon(3); `agent/src/logfmt.rs`): ERROR 3, WARN 4, INFO 6. The audit lines (`WARN … denied`,
  `WARN call … DESTRUCTIVE`, rollback, reboot, raise) are priority 4: `journal --unit foil-agent.service --priority 4`
  shows them. (Before v1-alpha3 every line of the agent was priority 6 and `--priority 4` hid them.)

## Updates (decision 0002)
`StageUpdate(version)` downloads the whole release from the channel fixed in
the image into `/var/lib/foil-agent/staging/`. The channel file
`/usr/lib/foil-agent/channel` holds one line: an absolute directory path, an
`https://` URL (CA in `/usr/lib/foil-agent/channel-ca.pem`, else the system
bundle) or an `http://` URL — **lab builds only**. Downloads: no exec, connect
timeout 10 s, 30 s without data aborts an attempt, up to 3 retries (resumed
with `Range` when the server supports it), size limit per file; 404 is final.
Retried are only an interrupted transport (refused, reset or aborted connection, end of stream before the handshake or
the response, a connect or handshake timeout); whatever the TLS layer reports (certificate, alert, protocol) and any
unknown error is final at once. An attacker who resets connections gains only the delay up to the retry limit: a
denial of service, never a way around the certificate check.
Trust comes only from the signature; the URL and its scheme decide nothing.
The release
and verifies it there: detached OpenPGP signature of `SHA256SUMS` against
`/usr/lib/systemd/import-pubring.gpg` (or `.pgp`; T10), every file hash, completeness
(UKI, `/usr`, verity, verity signature), version policy (`FOILBIRD_MIN_VERSION` in
os-release or `/var/lib/foil-agent/min-version`, T3; the TPM NV counter in the
product), and that the current boot is confirmed and nothing else is staged.
Only then `staging/current` is pointed at the release and the platform
installer writes the inactive slot (the image's `staged` sysupdate component
reads from there). Refusals are
audited and returned as `FAILED_PRECONDITION`; they do not replace the status
of a staged release. `Reboot(expect_staged)` refuses if another version is
staged. The slot is written by the image's installer unit
`foil-install@<version>.service` (oneshot, `systemd-sysupdate
--component=staged update %i`), which the agent starts through systemd over
D-Bus and waits for; the agent's own sandbox gets no disk or ESP access. An
image without that unit reports `STAGE_ERROR_INSTALL`.

`agent/out/` is empty in git, so image builds without the agent still work.

## Operator operations and dropped calls

`Rollback` and `RaiseMinVersion` run in a task of their own once their checks passed: a caller whose connection drops
(client timeout, reset) only stops waiting, the operation goes on to its end (the image unit, the rollback record, the
reboot; the raise's result). One such operation runs at a time: the same call (same operation and `expect_booted`)
meanwhile waits for it and gets the same answer; during a Rollback or RaiseMinVersion the other mutations (another
operation, `StageUpdate`, `Reboot`) are refused, which never lasts longer than the operation's unit may run
(`TimeoutStartSec`: `foil-rollback@` 2 min, `foil-var-epoch@` 5 min). An operation that may run longer must keep
`Reboot` available. In the release build (`panic = "abort"`) a panic aborts the agent; systemd restarts it (`foil-agent.service`:
`Restart=always`, `RestartSec=2`, `RestartSteps=5`, `RestartMaxDelaySec=60`, `StartLimitIntervalSec=0`: it never
gives up, the delay between restarts grows from 2 s to 60 s) and the operation state is recovered from the ESP (below). In an unwinding build (the
tests) a panic in the operation's task ends it as `FAILED` ("operation task panicked") and frees the slot.
`GetUpdateStatus.operation` shows the running or last one (`RUNNING`, `DONE`, `FAILED`, `REBOOT_PENDING`). A rollback whose
unit finished without a record (an agent restart in the middle): the booted entry is `<id>_<N>+0.efi` and
`<id>_<N>.efi` is gone; `GetUpdateStatus.operation` reports `REBOOT_PENDING`, and `Rollback` with the same
`expect_booted` (every check passes again) records it and reboots without running the unit; a counted name
(`+0-k`, the boot counter's own rollback) is never taken for it. `ApplyConfig` has no point where a dropped call stops
it halfway (render, persist and activation run without waiting); after a dropped call `GetConfig.generation` says whether
it was applied. `StageUpdate` always runs in its own task (`operation_id`, `GetUpdateStatus.stage`).

## Build
Only on a build host: `./build-release.sh` — static musl binaries,
`--locked`, `SOURCE_DATE_EPOCH`, path prefixes remapped, crate list embedded
with `cargo-auditable`, CycloneDX SBOM in `dist/`. Two builds from different
directories produce identical binaries. The compiler is pinned in
`rust-toolchain.toml` (rustup installs it on first use), `cargo-auditable` and
`cargo-cyclonedx` by version in `build-release.sh`: `./build-release.sh
--install-tools` installs them into `/opt/foilbird-build-tools/<set>`, one absolute
path on every build machine (docs/reproducible-build.md, "Build tools of the
agent"); a build with other versions or another path refuses to start. Tests: `cargo test --release --locked`
(includes an mTLS end-to-end test against a throw-away CA).

Without network (a build host with no access to crates.io or static.rust-lang.org):
`tools/offline-inputs.sh fetch <dir>` where there is network downloads the toolchain of `rust-toolchain.toml`
(checked against the Rust release key, pinned by fingerprint, and the published sha256), the two build tools
(checked against the crates.io index) and `cargo vendor` of `Cargo.lock` and the tools' lock files, with a
`MANIFEST.sha256` of every file. After the transfer, `tools/offline-inputs.sh install <dir> <prefix>` verifies all of
it again, installs the two tools by `./build-release.sh --install-tools` from the vendored crates, and prints the
environment for `./build-release.sh` (no rustup; `CARGO_HOME` with the vendored source, offline).
The vendored crates are installed where an online build extracts crates.io crates (`$CARGO_HOME/registry/src/...`), so
both builds run with the same compiler flags and the binaries do not depend on where the inputs were unpacked.

`FEATURES=esp-bridge-tls ./build-release.sh` builds the **lab** agent: it also
takes its TLS material and, with no persisted configuration, the bridge
configuration (`node.hostname`, `node.network`, `k8s.join`, `k8s.node-labels`,
`k8s.node-taints`) from `/boot/loader/foilbird` on the ESP (PoC bridge,
`../api/registration.md`). The default build is the product one: it ignores
TLS material on the ESP and does not start without `ImportCredential=agent.tls-*`
or `--tls-dir`, saying so in the journal; `apply-boot` reads the bridge
configuration from systemd credentials only and logs bridge files found on the
ESP as ignored (whoever writes the unauthenticated ESP before the first boot
would otherwise choose the network and the k8s join). `foil-agent version` and `dist/FEATURES`
show which one a binary is. Until registration exists, images for real nodes
(Secure Boot + TPM, where stub credentials are refused) need the lab build.

Units in `systemd/`; the image installs them to `/usr/lib/systemd/system`,
`foil-agent.tmpfiles` to `/usr/lib/tmpfiles.d/foil-agent.conf`, the preset to
`/usr/lib/systemd/system-preset/`.
