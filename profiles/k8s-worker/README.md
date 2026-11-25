# Profile `k8s-worker`

A Kubernetes worker node image built on top of `images/debian/mkosi` (Debian 13, signed UKI, `/usr` on signed
dm-verity, `root=tmpfs`). The profile is chosen at install time; a node never changes its profile in place.

## Contents

| Component | Version | Source | Verification at build time |
|---|---|---|---|
| containerd | 2.3.7 (upstream LTS line) | GitHub release tarball | sha256 from the release `.sha256sum` = file = `apt-pin.lock`; at fetch also = GitHub asset digest, listed as subject in the release provenance (`attestation.intoto.jsonl`; envelope signature not yet verified) |
| runc | the version containerd pins for that tag (`script/setup/runc-version`), 1.5.2 | GitHub release binary | GPG signature against `runc.keyring` of the same tag, sha256 from the release and `apt-pin.lock` |
| kubelet, kubeadm | 1.34.3-1.1 | `pkgs.k8s.io` (`core:/stable:/v1.34`) | `apt-pin.py` (set `k8s`, `apt-pin.conf`): `InRelease` signed by the Kubernetes release key (fingerprint pinned, no SHA1) → Packages → `.deb` + `apt-pin.lock`; apt checks again in the build |
| cri-tools, kubernetes-cni | 1.34.0-1.1, 1.7.1-1.1 | `pkgs.k8s.io` | same |
| nvidia-container-toolkit-base (`nvidia-ctk`, CDI; GPU variant only, see `images/debian/tools/build-all.sh --variant`) | 1.20.2-1 | `nvidia.github.io/libnvidia-container` | `apt-pin.py` (set `nvidia-container-toolkit`): `InRelease` signature (fingerprint pinned, no SHA1), SHA512 index → `.deb` + `apt-pin.lock` |
| NVIDIA driver (open modules + userspace) | 610.57.04 (`images/debian/apt-pin.conf`) | NVIDIA `debian13` repository; modules built by DKMS in the build overlay and signed with the image db key; **experimental**: not run on GPU hardware since the switch from 580.x | `images/debian/tools/apt-pin.py`: InRelease (sqv, pinned key, no SHA1) → Packages → `.deb` + `apt-pin.lock`, the same check for the network and the local cache |

Every file of the table is pinned twice: by its signed chain and by its line in `apt-pin.lock` (`release` lines:
`tools/fetch-upstream.py lock`, `apt` lines: `apt-pin.py lock`, both from a verified cache; the diff is reviewed). The
third-party APT repositories exist only in the build sandbox (`SandboxTrees=`, verified local copies); the node has no package manager
and no repository configuration. Files that belong to no dpkg package are listed in
`/usr/share/foilbird/sbom/*.json` (versions, URLs, sha256).

## Node layout

- `/var` — from the base image (A/B layout: persistent partition created by `systemd-repart` at first boot).
- `/var/lib/kubelet` — persistent, mounted `noexec,nosuid,nodev`; `/var/lib/containerd` — persistent, exec.
- `/etc/kubernetes` → `/var/lib/kubelet/etc-kubernetes` (kubeadm output survives reboots, the node keeps its identity).
- `/var/tmp` — emptied at every boot.
- No shell (`sh`, `bash`, `dash` and klibc-utils with its `sh` are removed; finalize fails the build if anything named like a shell is left in `/usr`), no SSH, no package manager. The UKI initrd is the base image's `images/debian/foilbird-initrd`: no shell and no interpreter either (`docs/image-policy.md`).
- No console login: `systemd.getty_auto=0` on the kernel command line, every getty unit (`getty@`, `serial-getty@`, `console-getty`,
  `container-getty@`, `autovt@`, `getty-static`, `getty.target`) and `debug-shell.service` masked, `systemd-getty-generator`
  removed; no `agetty`, `getty`, `su`, `sulogin`, `runuser`, `passwd`/`chsh`/`chfn` and the other shadow tools, no PAM stack for
  them. The console still shows the kernel and systemd; emergency and rescue reboot (base image). `mkosi.finalize` fails the build
  if any of this comes back.

## Configuration

Consumers read only `/run/foilbird/config/<name>` (format: `api/README.md`), rendered at boot by `foil-agent apply-boot`
(`foil-config.service`, see `agent/`); the profile's units are ordered after it.

| Unit | Does |
|---|---|
| `foil-k8s-env.service` | `k8s.node-labels`, `k8s.node-taints` → `KUBELET_EXTRA_ARGS` (`/run/foilbird/kubelet.env`); `apiServerEndpoint` of `k8s.join` → `/run/foilbird/apiserver.env`; strict validation |
| `foil-apiserver-proxy.socket` | node-local API endpoint `127.0.0.1:6443` (`systemd-socket-proxyd`, TLS passed through) for clusters whose agents use `localhost:6443` (kubespray) |
| `foil-kubeadm-join.service` | first boot only: `kubeadm join --config /run/foilbird/config/k8s.join` |
| `foil-kubeadm-init.service` | control plane v0, first boot only (`!admin.conf`): operator's CA → `/etc/kubernetes/pki`, `kubeadm init --config /run/foilbird/config/k8s.init --skip-token-print`; stacked etcd in `/var/lib/etcd`; `/usr/libexec/kubernetes/kubelet-plugins/volume/exec` ships empty (controller-manager hostPath on a read-only `/usr`; FlexVolume off, as on Talos) |
| `containerd.service` | config `/usr/lib/foilbird/containerd/config.toml` (CDI on, systemd cgroups); socket local only; bounding set without `CAP_SYS_MODULE` and `CAP_SYS_BOOT` (`containerd.service.d/20-foil-caps.conf`): no container, privileged included, can load a kernel module or reboot the host |
| `logind.conf.d/50-foil-kubelet-shutdown.conf` | `InhibitDelayMaxSec=60` in `/usr/lib/systemd`: logind waits for the kubelet's delay inhibitor on reboot and power-off (graceful node shutdown, below) |
| `foil-nvidia-cdi.service` | GPU variant only (`--variant gpu`, installed and enabled by `mkosi.finalize` from `nvidia/`): `nvidia-ctk cdi generate` into `/var/run/cdi` when an NVIDIA GPU is present, skipped otherwise; `TimeoutStartSec=120s` is a ceiling, not measured on hardware |
| `nvidia-cdi-refresh.{service,path}` | GPU variant only (with the toolkit; set by `mkosi.finalize`), masked (symlinks to `/dev/null`): the toolkit's refresh unit needs `/bin/sh`, which the image does not have; `foil-nvidia-cdi.service` writes the spec on every boot |

## Node role (`NodeConfig.role`)

The role of a node is explicit: `NODE_ROLE_WORKER` (kubeadm join) or `NODE_ROLE_CONTROL_PLANE` (kubeadm init,
control plane v0). The agent checks it in `ValidateConfig` and `ApplyConfig` (`InvalidArgument`, with the field):

| `role` | `k8s` | Result |
|---|---|---|
| `UNSPECIFIED` | absent | valid: a node without Kubernetes has no role |
| `UNSPECIFIED` | set | refused (`role`: required with k8s) |
| `WORKER` / `CONTROL_PLANE` | absent | refused (`role`: needs k8s) |
| `WORKER` | join fields (`api_server_endpoint`, `bootstrap_token`, `ca_cert_hashes`) | valid; `init` or the cluster CA refused |
| `CONTROL_PLANE` | `init` + `cluster_ca_crt` + `cluster_ca_key` | valid; missing any of them, or any join field, refused |
| unknown value | any | refused (`role`: unknown value) |

The role is required only together with `k8s`, not always: a profile without Kubernetes stays valid without a role
(the research recommendation "UNSPECIFIED is always refused" would refuse such a node).

**Limitations (v1-alpha):**

- **The role does not change without a reinstall.** `ApplyConfig` on a node with a role refuses a config with another
  role (`CONTROL_PLANE` ↔ `WORKER`) or without `k8s` (`FAILED_PRECONDITION`, "needs a reinstall"); nothing is written,
  the generation stays. kubeadm's state in `/etc/kubernetes` and `/var/lib` belongs to the role the node was set up with.
- **Configs from before the role.** A config persisted by an agent without the field (schema 1, `k8s` set, role
  `UNSPECIFIED`) is loaded at boot with the role inferred the old way (`k8s.init` set = `CONTROL_PLANE`, otherwise
  `WORKER`) and a warning in the journal; `config.pb` is not rewritten (ADR 0005). `GetConfig` returns the inferred
  role; the next `ApplyConfig` must carry the role explicitly.
- `foilctl apply` needs `--role worker|control-plane` with any `--k8s-*` flag.

## Control plane init configuration (`NodeConfig.k8s.init`)

The agent refuses an init configuration (`ApplyConfig`/`ValidateConfig`, field `k8s.init`) unless:

- **join tokens expire:** the `InitConfiguration` has a `bootstrapTokens:` list and every entry exactly one `ttl:`,
  with 0 < ttl ≤ 24h. **Join tokens must expire within 24 h; a ttl of 0 (never expires) is refused; 2 h is
  recommended.** `expires:` is refused too (an absolute time cannot be checked before the node's clock is
  synchronized). Without `bootstrapTokens:` kubeadm would create a 24 h token of its own, so the list is required.
  The list and the ttl must be written in block style (`- token: …` / `  ttl: 2h`); flow style, anchors, aliases,
  tags or merge keys around the ttl are refused rather than guessed. Errors name the rule, never the token;
- **graceful node shutdown:** one `KubeletConfiguration` (`kubelet.config.k8s.io/v1beta1`) with
  `shutdownGracePeriod` > `shutdownGracePeriodCriticalPods` > 0 in whole seconds (e.g. 60s / 20s); `kubeadm init`
  uploads it as the ConfigMap `kube-system/kubelet-config`, which every joining node takes;
- **kube-apiserver audit is on** (see "Control plane audit log"): the `ClusterConfiguration` has `apiServer.extraArgs`
  `audit-policy-file` = `/usr/lib/foilbird/kubernetes/audit-policy.yaml` (the image's policy; another policy file is
  refused) and `audit-log-path` = a file on `/var` (not `-`, stdout), each once, and `apiServer.extraVolumes` that
  mount the policy (the file or its directory) and the log directory into the static pod with hostPath = mountPath
  (without them kube-apiserver does not start). Entries in block style or one simple flow mapping each
  (`- {name: …, value: …}`); anchors, aliases, tags and nested flow are refused rather than guessed. Rotation
  (`audit-log-maxsize`, `-maxbackup`, `-maxage`, `-compress`) stays the operator's choice; the values below are
  recommended.

This checks the configured lifetime only; whether a token is still valid is known to the cluster alone. Tokens
created later with `kubeadm token create` follow the operator's runbook (`--ttl 2h`).

## Graceful node shutdown

A reboot or power-off (the agent's `Reboot`, an A/B update, a rollback) goes through logind. The kubelet holds a
logind delay inhibitor and stops the pods in order: regular pods get `shutdownGracePeriod − shutdownGracePeriodCriticalPods`,
then critical pods (`system-cluster-critical`, `system-node-critical`: the static control plane pods, CNI, kube-proxy) get
`shutdownGracePeriodCriticalPods`. Without it (kubelet default `0s`) systemd sends SIGTERM to every container scope at
once and waits `DefaultTimeoutStopSec` (90 s) for each one that does not exit: in a pre-release a kube-apiserver draining
against an already stopped etcd and a loaded vLLM held 4 of 6 reboots for ~90 s.

The node values are **60 s / 20 s (critical)**. The kubelet takes them from its configuration file, which `kubeadm`
writes from the cluster's ConfigMap `kube-system/kubelet-config`, so:

- **Control plane** (`k8s.init`): the operator's init configuration carries a `KubeletConfiguration` document;
  `kubeadm init` uses it for the control plane node and uploads it as `kubelet-config` (the agent refuses a
  `k8s.init` without it, see above):
  ```yaml
  ---
  apiVersion: kubelet.config.k8s.io/v1beta1
  kind: KubeletConfiguration
  shutdownGracePeriod: 60s
  shutdownGracePeriodCriticalPods: 20s
  ```
- **Workers** (`k8s.join`): `kubeadm join` writes the node's configuration from that ConfigMap, nothing to set on the
  node. A worker joining a cluster that was not installed this way gets whatever its `kubelet-config` says
  (kubespray: `kubelet_shutdown_grace_period`, `kubelet_shutdown_grace_period_critical_pods`).
- **Container scopes**: `cri-containerd-.scope.d/50-foil-stop-timeout.conf` sets `TimeoutStopSec=5s` on every container scope.
  A container that ignores SIGTERM is not always killed by the kubelet: its group timer (here 40 s for regular pods) cancels
  the `StopContainer` call just before containerd's timer of the same length would send SIGKILL, the kubelet moves on and
  releases its inhibitor, and systemd then stops the scope with SIGTERM and `DefaultTimeoutStopSec` (90 s). The drop-in
  replaces those 90 s with 5 s.
- **Kubelet stop delay**: `kubelet.service.d/30-foil-shutdown.conf` (`ExecStop=/usr/bin/sleep 5`) keeps the kubelet alive 5 s
  after systemd asks it to stop, so its exit no longer cancels the in-flight `StopContainer` and containerd kills such a
  container itself (kubernetes/kubernetes#110755); the scope drop-in above stays as the fallback. Measured with a pod that
  ignores SIGTERM, including runs where the kubelet lost that race on purpose: 45.9–46.0 s from the reboot request to the
  reboot, no scope stop timeouts.
- **logind**: `InhibitDelayMaxSec=60` ships in `/usr/lib/systemd/logind.conf.d/` (the kubelet's own drop-in goes to the
  tmpfs `/etc` and exists only once the kubelet has started).

Check on a node: `configz` of the kubelet (`kubectl get --raw /api/v1/nodes/<node>/proxy/configz`) shows
`shutdownGracePeriod: 60s`, `shutdownGracePeriodCriticalPods: 20s`; the journal of the kubelet shows its delay inhibitor
(`Creating node shutdown manager`, `shutdownGracePeriodRequested=1m0s`).

## Control plane audit log

The image ships an audit policy for kube-apiserver, `/usr/lib/foilbird/kubernetes/audit-policy.yaml`: every request at
`Metadata` (user, groups, source IP, verb, resource, name, response code; no bodies), Secrets, ConfigMaps, service
account tokens, TokenReviews and CSRs pinned at `Metadata` even if the default is raised, so the bodies of these objects
(join tokens and other credentials they hold) are not written; health probes and lease renewals are not logged. Checked
with canary Secrets and a structural count of every Secret event in the log; the policy, not a scan of the log, is what
keeps values out, so a raised level for another resource type needs the same review. The log is a file on the persistent
`/var`, rotated by kube-apiserver (100 MB, 5 compressed backups, 7 days). The operator's `ClusterConfiguration`
(`k8s.init`) turns it on, and the agent refuses a control plane `k8s.init` without it (above): the policy file and the
log path are required, the policy must be the image's. The agent checks the operator's configuration and does not
rewrite it: `k8s.init` is the operator's kubeadm text, passed to `kubeadm init` as given. A different audit policy
(another level for some resource) is an image change with the same review as this one, not an operator setting.

```yaml
apiServer:
  extraArgs:
  - {name: audit-policy-file, value: /usr/lib/foilbird/kubernetes/audit-policy.yaml}
  - {name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}
  - {name: audit-log-maxsize, value: "100"}
  - {name: audit-log-maxbackup, value: "5"}
  - {name: audit-log-maxage, value: "7"}
  - {name: audit-log-compress, value: "true"}
  extraVolumes:
  - {name: audit-policy, hostPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, mountPath: /usr/lib/foilbird/kubernetes/audit-policy.yaml, readOnly: true, pathType: File}
  - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}
```

The log is read on the node only (no shell: through a pod with a read-only hostPath, or by shipping it); it holds no
secret values, but it is a record of who did what and stays `0600` root.

## Known gaps (PoC)
- Lab agent only (`FEATURES=esp-bridge-tls`, `agent/README.md`, "Build"): it reads node configuration from the ESP
  (`/loader/foilbird/<name>`), which is unauthenticated: whoever can write the disk can change the join target. Accepted
  for TEST with a 2 h bootstrap token. The product agent ignores it.
- `staticPodPath` (kubelet configuration from the cluster) points into the persistent `/etc/kubernetes/manifests`;
  it should be off or in the generated `/etc` (nothing persistent outside the listed `/var` paths).
- `/etc/machine-id` is stable: the initrd writes it from the SMBIOS system UUID on every boot (`/etc` is tmpfs). A node
  without a usable UUID gets a random id on every boot, which v0 does not support (see `docs/image-policy.md`, machine-id).

## Build

```
C="--conf ../../images/debian/apt-pin.conf --conf apt-pin.conf --cache ../../apt-cache"
../../images/debian/tools/apt-pin.py fetch $C              # NVIDIA driver, toolkit, pkgs.k8s.io: only what is missing
tools/fetch-upstream.py fetch --cache ../../apt-cache      # containerd, runc (and the profile's apt sets)
../../images/debian/tools/apt-pin.py prepare $C --out-dir ../../images/debian/mkosi   # no network from here on
tools/fetch-upstream.py prepare --cache ../../apt-cache --out upstream
../../images/debian/build-image.sh --profile . --version <N> --output-dir <out> <keys and channel, see images/debian> \
  --include ../../images/debian/mkosi/pinned.conf
```
Signing keys (`images/debian/mkosi/mkosi.key`, `mkosi.crt`) are generated locally and never committed.
