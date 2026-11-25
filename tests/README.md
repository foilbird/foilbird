# Test harness

Boots a built node image in QEMU with OVMF (Secure Boot) and a software TPM (swtpm) and checks it through the agent
API with `foilctl`. One command, the same on a workstation and in a `debian:trixie` container. Building the image is
not part of the harness: the image and the `foilctl` of the same agent dist are inputs.

```sh
make test IMAGE=out/foilbird-deb_1.raw FOILCTL=dist/foilctl                  # all scenarios
make test IMAGE=... FOILCTL=... SCENARIOS=install VERSION=1                 # one scenario, expected version
make test-container IMAGE=... FOILCTL=...                                   # inside debian:trixie (docker or podman)
make test-list
make test-selfcheck            # the harness's own tools, no image (also test-selfcheck-container)
```

Requirements: the packages of [`deps.txt`](deps.txt) (Debian 13 names) and a usable `/dev/kvm` (without it the
guests run under TCG, many times slower; raise `API_TIMEOUT`). No root is needed: guests use user-mode networking.

## Keys

Every run uses **ephemeral TEST keys** made by [`lib/keys.sh`](lib/keys.sh) on tmpfs and removed at the end
(`KEEP=1` keeps them): Secure Boot PK/KEK/db, two PCR policy keys (epochs 1 and 2), the release key of the channel
(GPG), the agent PKI (CA, server certificate for `agent.test`, client certificates per role: reader, diag,
controller, operator) and the agent's TLS material as SMBIOS type 11 credentials. The image needs none of them for
`ENROLL=auto` (default): the guest starts in Secure Boot setup mode and the image enrolls its own db certificate.
With `ENROLL=vars` PK, KEK and db are enrolled before the first boot, closer to a real machine; the image must then
be built with the same db key:

```sh
make test-keys KEYS=/dev/shm/k                        # once
images/debian/build-image.sh ... --sb-key /dev/shm/k/sb/db.key --sb-cert /dev/shm/k/sb/db.crt \
    --pcr-key /dev/shm/k/pcr/pcr-e1.key --pcr-cert /dev/shm/k/pcr/pcr-e1.crt --release-keyring /dev/shm/k/release.pgp
make test IMAGE=... FOILCTL=... KEYS=/dev/shm/k ENROLL=vars
```

## Results

Every check prints one line and appends it to `$WORK/results.txt`:

    TEST <scenario> <node> <check> PASS|FAIL|SKIP <facts> [| <what failed>]

and the run ends with `HARNESS PASS|FAIL <passed>/<checks> checks, <skipped> skipped, <seconds>s, work <dir>`; the
exit code is 0 only when no check failed and at least one passed (`STRICT=1`: and none was skipped). Logs: `$WORK/logs/<scenario>/` (agent answers, journals, serial console with UTC
millisecond stamps), `$WORK/inputs.txt` (sha256 of the image and foilctl, revision, QEMU and swtpm versions).

## Scenarios

| file | what |
|---|---|
| `scenarios/10-install.sh` | fresh install under Secure Boot + TPM: API up, kernel Secure Boot enabled, boot check |
| `scenarios/20-config.sh` | fresh install of node `n2` + ApplyConfig (DHCP, NTP, release channel), boot check with health `Pass` |
| `scenarios/30-t5.sh` | T5 (`images/debian/tools/t5-check`, gated=0) on the image's `/usr`, bound to the node by rootHash = usrhash; agent binary = dist |
| `scenarios/40-ab.sh` | A/B 1 → 2: StageUpdate, Reboot `--expect-staged`, shutdown ≤ `MAXSHUT` s, boot check, audit line |
| `scenarios/50-rollback.sh` | wrong `expect_booted` refused, then Rollback 2 → 1 (record `Operator`) |
| `scenarios/60-t7.sh` | broken release 3: the node returns to 1 by itself (`BootAttemptsExhausted`), staging 3 again refused |
| `scenarios/70-epoch.sh` | release 4 of PCR epoch 2: RaiseMinVersion (operator only, bound to the booted release), floor 4, release 1 refused, floor kept after a reboot |

Scenarios 20–70 share one node, `n2`, kept between them ([`lib/node.sh`](lib/node.sh)): each one starts from the
state the previous one leaves (config → ab → rollback → t7 → epoch) and runs the missing earlier steps first, so
`tests/run.sh rollback` also works alone. The steps ([`lib/steps.sh`](lib/steps.sh)) are the phases of the release test of a
Kubernetes node, for one guest without Kubernetes: the same RPCs, expectations and refusal codes.

### Releases and the channel

Scenarios 20–70 need `CHANNEL`: a directory as the build publishes it, `SHA256SUMS` + `SHA256SUMS.gpg` signed with
the release key of `KEYS`, and the files of releases 2, 3 and 4 listed there. The harness checks the signature and
every listed file, serves the directory over https (TEST certificate `pki/channel`, SAN `10.0.2.2`) and gives it to
the node the product way, NodeConfig.update_channel in ApplyConfig. So the images and the releases must be built with
the same `KEYS` (release key, Secure Boot db for `ENROLL=vars`, PCR keys `pcr-e1` and `pcr-e2`):

| release | build | used by |
|---|---|---|
| 1 (`IMAGE`) | epoch 1, min 1, `pcr-e1` | install, config, t5 |
| 2 (`AB_VERSION`) | the same commit, version only | ab, rollback |
| 3 (`T7_VERSION`) | as 2 plus the extra tree [`overlays/t7-broken-foil-config`](overlays/t7-broken-foil-config) (`ExecStart=/usr/bin/false` for foil-config), given only to this build inside the harness, in no profile, never published | t7 |
| 4 (`EPOCH_VERSION`) | PCR epoch 2 (`EPOCH`), min version 4, `pcr-e2`; epoch table of all four releases `1:1,2:4` | epoch |

T7 in the harness fails the boot gate through foil-config (the gated `foil-config` check is Fail; not a hard failure,
so each try waits the gate's 300 s; the rollback is expected within [900, 1080] s of the reboot with 3 attempts,
`T7_BOOT_MAX` 60 s per try for shutdown, boot and API; `T7_TIMEOUT` 1800 s bounds the wait); the release test of a Kubernetes
node breaks the kubelet of a joined worker instead. Both check the same outcome: the node returns to the previous release by itself, record
`BootAttemptsExhausted`, no Rollback RPC.

The agent's refusal codes and record names (`FailedPrecondition`, `PermissionDenied`, `STAGE_ERROR_ROLLED_BACK`,
`STAGE_ERROR_BELOW_MIN_VERSION`, rollback `reason_code`) are read in one place, [`lib/codes.sh`](lib/codes.sh), shared
with any other test chain; each pattern says whether it was read from the source or seen in a run.

Without `CHANNEL` scenarios 20–70 write one `SKIP` line each; `STRICT=1` turns a SKIP into a failed run. The harness gate
runs with `STRICT=1`. `AGENT_SUMS` (default `SHA256SUMS` next to `FOILCTL`) is the agent dist's checksum list for the agent
check of `30-t5`.
The boot check ([`lib/check.sh`](lib/check.sh), `boot_check`) of every boot: booted version, Secure Boot state, TPM,
`/var` on LUKS2 bound to the TPM, no failed unit in this boot, no failed start of PID 1 in the boot that ended (selected
by journald's own fields `_SYSTEMD_UNIT=init.scope`/`_PID=1`, not by text; other matching lines are reported as `prevx=`), no known boot
noise at priority err, health `Pass` with no failed check, boot `Confirmed`, optionally the `usrhash=` of the kernel
command line. One narrow exception, for a boot before any ApplyConfig only (`--no-ntp-ok`, used by `10-install`):
the only non-Pass, non-Skipped check may be `time-synced` with no NTP servers configured (`ntp system=[]`), either `Warn`
(base image; `allowed=time-synced:no-ntp-configured`) or `Pending` "first join waits for time sync" (k8s-worker before
the first join; `allowed=time-synced:pending-first-join`). Scenarios after ApplyConfig pass `--ntp` in the config (the
product path, as the k8s runs do) and require health `Pass` without exceptions; a clock not yet synchronized (`Warn` or
that `Pending`) is waited for up to `TIME_SYNC_WAIT` (180 s) and FAILs after it. Offline samples of these rules:
`tests/lib/check_selftest.sh`.

## Writing a scenario

A scenario is `scenarios/NN-<name>.sh` defining `scenario_<name>` (dashes become underscores). It uses
[`lib/vm.sh`](lib/vm.sh) (`vm_start`, `vm_stop`, `vm_wait_api`, `vm_wait_serial`, `vm_boot_id`, `vm_wait_new_boot`,
`ctl <node> <role> <foilctl args>`), `boot_check` and `res <node> <check> PASS|FAIL|SKIP <detail>`. A scenario on the
configured node calls `channel_need` and `node_ensure <previous step>` first ([`lib/node.sh`](lib/node.sh)). A guest reboots inside
the same QEMU process, so updates, rollbacks and boot assessment run as on hardware; `vm_stop --wipe` makes the next
`vm_start` a new machine.

## CI

[`.github/workflows/test.yml`](../.github/workflows/test.yml) runs `make test-container` on a hosted runner with KVM.
It starts only on a push to a `ci/t-*` branch, made on purpose for one run; the run's inputs (URL and sha256 of the
image and of foilctl, `VERSION`, `ENROLL`, `SCENARIOS`) are the `env` block of the workflow in that branch's commit.
Without an image it runs the self-check. No secrets and no third-party actions; the read-only job token only fetches
the commit.

Before anything else every CI job runs the publication gates that need no word list: `tests/compliance/oss-gate.py`
(addresses, domains against [`docs/compliance/named-domains.md`](../docs/compliance/named-domains.md), own names, process
ids, test ids, old hashes) and `tests/compliance/gitleaks-gate.sh` (secrets in the files of the commit). The secrets scan
uses gitleaks 8.16.0 from the Debian package at the build's `Snapshot=`, pinned by sha256 (package and binary); it first
proves it sees a generated test private key in a copy of the tree. **gitleaks 8.16.0 is old: rules for token formats
introduced after it may be missing.** The package is updated together with the next change of `Snapshot=`. A known false
positive is marked on its one line with `gitleaks:allow` and the reason; there is no allowlist by rule or path.

The harness gate (`make test` green on a clean runner) is the `harness` stage of
[`.github/workflows/build.yml`](../.github/workflows/build.yml) (`STAGE=harness`): a push to a `ci/harness-try-*` branch whose commit carries a
`harness-try-*` tag. One job builds the agent dist and releases 1-4 of the k8s-worker profile without NVIDIA userspace
(`images/debian/tools/build-all.sh`; 2-4 with `--image-only`, 3 with the T7 overlay, 4 with `--pcr pcr-e2`) with TEST
keys generated in the job, checks them and makes the channel of 2 3 4 offline ([`ci/release-channel.sh`](ci/release-channel.sh)),
then runs `make test-container` with `STRICT=1` over every scenario. Images, keys and the channel never leave the job.
Its result lines (ci/run-stage.sh): `HARNESS RELEASE 1 PASS|FAIL`, `HARNESS RELEASES PASS|FAIL`, `HARNESS GATE PASS|FAIL`.

## Test ids

Test ids name what a scenario, a unit test or a build check proves; the harness and CI print them. Every id used in
the tree is defined here (`tests/compliance/oss-gate.py`, rule test-ids, fails on an id used but not listed).

| id | what is checked |
|---|---|
| T3 | `StageUpdate` to a signed release below the anti-rollback floor (`min_version`) is refused; a slot written by hand with such a release does not open `/var` |
| T5 | nothing on the host to log in with or to run a script with: no shell, interpreter, network client or package manager beyond what the image policy allows (`images/debian/tools/t5-check`) |
| T6 | an executable placed in `/var/lib/kubelet` or `/var/tmp` does not run after a reboot (noexec) |
| T7 | an update to a release whose kubelet is broken fails the boot gate on every try; the boot counter returns to the previous release and the rollback is reported |
| T8 | static check of the `.proto`: no RPC takes an arbitrary command, script or path to a binary (`api/tools/check_proto.py`) |
| T9 | kernel module signature enforcement: an unsigned module is refused |
| T9a | an unsigned module is refused |
| T9b | a module signed with a foreign key is refused |
| T9c | a module signed with the image's db key loads |
| T10 | an update to a release not signed by the release key is refused and the refusal is audited |
| T11 | a registration without operator approval gets no certificate, and no workload configuration is accepted |
| T12 | an EMERGENCY RPC called with a gateway certificate is denied by authorization |
| T13 | a vulnerability scanner (Trivy, Grype) recognizes the OS and its version in the image and matches its packages |
| T14 | a kubelet minor upgrade on a node that ran workloads and a GPU device plugin keeps the node's kubelet state usable |
| T16 | an unsigned `.raw` in `/var/lib/extensions` or `/var/lib/confexts` and a `.crt` in `/run/verity.d` are not merged after a reboot |
| T17 | a failing live apply leaves the previous configuration generation on disk; `TRY` with a configuration that cuts the network returns to the previous one after its timeout |
| T20 | `Rollback` of a committed release boots the previous release, reported with `reason_code = OPERATOR` |
| T20b | `Rollback` to a previous release below the anti-rollback floor is refused (it would not open `/var`) |
