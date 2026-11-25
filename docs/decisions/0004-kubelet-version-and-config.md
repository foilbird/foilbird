# 0004. The OS release fixes the kubelet version; the agent owns the kubelet configuration

- Status: accepted (2026-11-15, owner; after the requirements review and a comparison with Talos)
- Scope: profile `k8s-worker`; affects the agent API (`NodeConfig.k8s`), the profile units and the release process.

## Problem

The kubelet binary lives in the signed `/usr` (model A, chosen by the owner), so its version changes and rolls
back together with the image. Its configuration does not: today it is written once and never again.

Facts from the PoC (the GPU test node, kubelet/kubeadm 1.34.3, TEST apiserver 1.34.3; data and raw output in the
PoC logs, not part of this repository):

1. `foil-kubeadm-join.service` runs `kubeadm join` only when `/etc/kubernetes/kubelet.conf` is missing, i.e. on
   the first boot. Nothing calls `kubeadm upgrade node` later.
2. `kubeadm join` writes `/var/lib/kubelet/config.yaml` from the cluster ConfigMap `kube-system/kubelet-config`,
   `/var/lib/kubelet/instance-config.yaml` (kubeadm 1.34 NodeLocalCRISocket) and `/var/lib/kubelet/kubeadm-flags.env`
   (`--pod-infra-container-image=…`). All of it lives on the persistent `/var` and survives A/B and rollback.
3. Consequences:
   - A change of the cluster ConfigMap never reaches an existing node; a new `k8s.join` through `ApplyConfig`
     after the join is never applied (the agent answers `reboot_required`, the join unit is skipped forever).
   - The node runs with whatever the cluster had at join time plus the defaults of the kubelet that runs now.
   - kubelet 1.35 removed `--pod-infra-container-image`. An image with kubelet 1.35 on a node joined with
     kubeadm 1.34 keeps the 1.34 `kubeadm-flags.env` and the kubelet does not start. The boot gate (kubelet-crashloop)
     should roll the node back in ~4 min (not tested across minors: the gate was tested only with a broken kubelet of
     the same minor), but the node can never move to 1.35 — the update is blocked, not the rollback.
   - The reverse case is the dangerous one for rollback: if a newer kubelet (or anything acting for it) ever
     rewrote the persistent configuration with fields or feature gates the older minor does not know, the older
     image would not start the kubelet after a rollback. Hypothesis, not tested: the outcome then depends on the boot
     counter of entry N on the ESP; if N also fails its health check, the node would run out of good entries.
4. We require but do not set: `cgroupDriver: systemd` (must match `SystemdCgroup = true` in containerd) and the
   containerd socket. `staticPodPath` is `/etc/kubernetes/manifests` (the requirements say it must be off).
5. Version skew (kubernetes.io/releases/version-skew-policy): the kubelet must not be newer than the
   kube-apiserver and may be up to three minors older. A release with kubelet 1.35 is invalid for a 1.34 cluster;
   rolling back one minor is always valid.

## Decision

1. **The OS release fixes the kubelet version.** kubelet, kubeadm and their packages are part of the signed
   `/usr`. There is one image stream per Kubernetes minor (`k8s-1.34`, `k8s-1.35`, …); a stream gets only patch
   releases. The release manifest records the kubelet version. A minor upgrade is a separate release type: the
   control plane first, then the nodes; rollback stays inside the previous minor's stream.
   - The agent refuses `StageUpdate` when the release's kubelet minor is newer than the cluster's apiserver minor
     (the agent reads `/version` with the node's kubelet credentials). The fleet controller enforces the same rule.
     The check runs on the node, not only in the client: Talos 1.14 checks the Talos↔Kubernetes skew only in
     `talosctl` ([src], PoC step 2), so a node driven by another client is not protected.
   - A release may not skip a Kubernetes minor: from stream `k8s-1.N` the agent accepts only `k8s-1.N` (patch) or
     `k8s-1.(N+1)`; anything else is refused before staging. Talos refuses a downgrade of Kubernetes through
     `upgrade-k8s` ("unsupported upgrade path 1.37->1.36", seen in a test); our downgrade is an OS rollback to the previous
     stream, which stays allowed (point 7).
   - The skew check is fail-closed for a minor: if the agent cannot read `/version` (apiserver unreachable),
     `StageUpdate` to `k8s-1.(N+1)` is refused with that reason; a patch release inside the booted stream is allowed.

2. **The agent generates the kubelet configuration for the kubelet that is actually booted.**
   - On every boot and on every `ApplyConfig` the agent renders `KubeletConfiguration` and the kubelet flags into
     `/run/foilbird/kubelet/` (tmpfs), from two sources only:
     (a) per-minor defaults shipped in the image (`/usr/lib/foilbird/kubelet/<minor>/`), which also pin the required
         values (`cgroupDriver: systemd`, the containerd socket, `staticPodPath` empty, `resolvConf`, `rootDir`,
     `clientCAFile` at a fixed path — `/etc/kubernetes/pki/ca.crt`, with the image's `ssl → pki` link serving
     kubespray clusters);
     (b) typed, allow-listed overrides from `NodeConfig.k8s.kubelet` (cluster DNS — e.g. nodelocaldns on its link-local address
         in TEST, not the service IP — and domain, eviction, reserved
         resources, CPU/memory/topology manager, feature gates), supplied by the fleet controller.
   - The kubelet drop-in of the profile overrides `KUBELET_CONFIG_ARGS` and `KUBELET_KUBEADM_ARGS` of the package's
     `10-kubeadm.conf`, so `--config` and the flags point at the rendered files — also on the first boot, because
     `kubeadm join` restarts the kubelet itself and waits for `/healthz`. `kubeadm` is used only for the first
     join and TLS bootstrap; the `config.yaml`, `instance-config.yaml` and `kubeadm-flags.env` it writes are not
     used. The cluster ConfigMap `kubelet-config` is not a source of truth for our nodes.
   - Boot order (systemd ordering, enforced by the profile units, not by timing):
     1. the agent starts and renders `/run/foilbird/kubelet/` from the image defaults and the last committed generation;
     2. `kubelet.service` is ordered `After=` and `Requires=` the render step; without rendered files the kubelet does
        not start (it does not fall back to the files under `/var`);
     3. on the first boot only, `foil-kubeadm-join.service` runs after the render step; when `kubeadm join` restarts the
        kubelet, systemd starts it with the same drop-in, so kubeadm cannot switch the running configuration to its
        own files;
     4. the drop-in name sorts after the package's `10-kubeadm.conf`, and an image build check fails if a package
        update changes the variable names the drop-in overrides.
   - Acceptance before implementation is merged: first boot with join; a second join after `/var` was recreated
     (recovery, TPM reset) on the same machine; in both cases `ps`/`configz` show the rendered config and flags.

3. **The configuration is validated before it is applied.** The agent validates the overrides against the
   schema of the booted kubelet minor (field allow-list and value checks; unknown fields and unknown feature gates
   are rejected) and returns an error from `ApplyConfig` instead of writing a file the kubelet would reject.

4. **`ApplyConfig` of the kubelet configuration is transactional.**
   - The new generation is fully validated (point 3) before anything is written.
   - It is written as `pending` next to the last `committed` generation in `/var/lib/foil-agent` (write to a
     temporary file, fsync, atomic rename); the committed generation is never modified in place.
   - The agent renders the pending generation into `/run`, restarts the kubelet and checks it (kubelet healthy,
     node Ready, GPU devices registered on GPU nodes) within a time limit. Success → `pending` becomes
     `committed`, the previous committed generation is kept as the fallback. Failure → the agent re-renders the
     committed generation, restarts the kubelet and reports the failure with the reason.
   - Success is not a single observation: the checks must hold for a stabilization window after the first pass
     (default to be set by the implementation and overridable by the fleet controller). A failure inside the
     window is a failure. Talos has no such window: its OS upgrade succeeds on the first Ready, a broken kubelet
     applied without reboot restarts forever, and `--mode try` reverts on a timer even a working configuration
     (seen in a test).
   - Only local signals can roll back a kubelet configuration: kubelet `/healthz`, crash loop, and on GPU nodes
     the GPU devices seen by the kubelet's local podresources API or the device plugin registration — not
     `Node.status.allocatable`, which is read from the apiserver. An unreachable apiserver is not a failure of the configuration. If the local checks pass but node
     Ready cannot be observed because the apiserver is unreachable, the agent neither rolls back nor commits: it
     keeps the pending generation running, reports it as unverified and waits for the apiserver.
     - `unverified` is never silent: `GetHealth` is WARN with the time the state was entered; the fleet controller
       does not count the node as soaking and pauses the rollout.
     - The stabilization window starts when the apiserver is reachable again and the node is first Ready, not when
       the configuration was applied.
     - A reboot in this state boots the committed generation; the pending generation is not lost silently but
       reported as interrupted, as in the reboot rule below.
     - The state machine (pending → verifying → committed | reverted |
     unverified) and its timeouts are part of the implementation and of its acceptance tests; the tests include:
       apiserver unreachable → local checks pass → `unverified`, WARN, no rollback; apiserver back → window → committed;
       apiserver unreachable → reboot → committed generation running, interrupted pending in the report.
   - A reboot at any point of `ApplyConfig` boots with the last committed generation (`/run` is empty after a
     reboot, and `pending` is never used at boot); the interrupted pending generation is reported, not applied.
   - Applying the same generation again is idempotent: if the rendered files are byte-identical, the kubelet is
     not restarted.
   - Restarting the kubelet does not stop running pods.

5. **Changes that need a drain are not applied automatically.** Fields that invalidate kubelet state or running
   workloads — `cgroupDriver`, CPU/memory/topology manager policies, reserved CPU sets, feature gates, `rootDir` —
   are accepted only with an explicit statement from the fleet controller that the node is cordoned and drained.
   The agent never drains. When such a policy changes on a drained node, the agent removes the stale state files
   (`cpu_manager_state`, `memory_manager_state`) as part of the same operation. This is the only case in which the
   agent removes kubelet state; it never does so on an OS rollback (point 7).

6. **Identity is not changed by `ApplyConfig`.** `nodeName`, the machine
   identity itself, the kubelet certificates and their paths (`/var/lib/kubelet/pki`, bootstrap and client
   kubeconfigs, `clientCAFile`) and `providerID` are outside `NodeConfig.k8s.kubelet`; the agent rejects them.
   Changing them means re-registration or a reset, not configuration. Today `nodeName` is
   `nodeRegistration.name = NodeConfig.hostname`; the machine-id comes from the SMBIOS UUID. Whether `nodeName` should
   be derived from the machine identity instead of the configured hostname is left to the implementation (see
   Consequences). Node labels and taints after registration are set by the controller through the Kubernetes API:
   the kubelet applies `--node-labels`/`--register-with-taints` only at registration (expected kubelet behaviour, not
   verified on the GPU test node), and NodeRestriction additionally forbids it to change taints and restricted label prefixes.

   | Identifier | Where it comes from | Survives A/B and rollback | Reinstall on the same VM (`/var` recreated) | New VM from the same image |
   |---|---|---|---|---|
   | `machine-id` | SMBIOS system UUID, set in initrd; never stored in the image | yes | same (same SMBIOS UUID) | new (new UUID) |
   | `nodeName` | `NodeConfig.hostname` → `nodeRegistration.name` | yes | same if the controller gives the same hostname | new hostname from the controller |
   | `providerID` | not set today | — | — | — |
   | Kubernetes Node UID | the Node object, created at first registration | yes | same if the Node object was not deleted (the new kubelet takes over the object by name); new otherwise | new |
   | kubelet client certificate | TLS bootstrap → `/var/lib/kubelet/pki`, CN `system:node:<nodeName>`, rotated | yes | new certificate, same name | new |

   - The image contains no identity: all of it is created on the first boot from SMBIOS and `NodeConfig`.
   - Cloning a disk after its first boot, or giving two machines the same hostname or the same SMBIOS UUID, clones
     identity: two kubelets would share one Node object. This is forbidden; the agent reports `machine-id` and the
     controller (registration, stage 5) rejects duplicates of `machine-id`, hostname and, later, the TPM EK. Until
     then uniqueness is a provisioning rule (IaC must not copy SMBIOS UUIDs or hostnames).
   - Choosing hostname or machine identity as the source of `nodeName` is a separate decision.

7. **An OS rollback stays possible whatever the newer version wrote.** Everything version-specific is rendered
   into `/run` at boot by the agent of the booted image, so an older image never reads configuration produced for a
   newer kubelet. The persistent kubelet state on `/var` is limited to data the kubelet is expected to read across
   one minor in both directions (certificates, pod and volume directories, device-plugin checkpoint, manager
   state). Every minor release is accepted only after a rollback test from the new minor to the previous one on a
   node that ran workloads and a GPU device plugin on the new minor (T14 below).
   - Configuration in `/run` being correct is not enough: persistent state written by the newer version can still
     stop the older one. Rule: **every component that keeps version-dependent state on `/var` has a documented
     compatibility and rollback policy** — kept as is, migrated, or safe to recreate. Nothing is deleted
     automatically on a rollback until that policy says the data is safe to recreate.
   - Initial inventory (to be completed by T14):

     | State on `/var` | Owner | Policy today |
     |---|---|---|
     | `/var/lib/kubelet/pki`, kubeconfigs | kubelet / kubeadm | keep; format stable across minors |
     | `/var/lib/kubelet/pods`, volumes | kubelet | keep |
     | `device-plugins/kubelet_internal_checkpoint` | kubelet device manager | unknown → T14 |
     | `cpu_manager_state`, `memory_manager_state` | kubelet | keep; removed only on a policy change under drain (point 5) |
     | `dra_manager_state` | kubelet DRA manager (GA, enabled in 1.34) | unknown → T14 |
     | `/var/lib/containerd` | containerd (its version also comes from the image) | unknown across containerd minors → T14 |
     | NVIDIA CDI specs | `foil-nvidia-cdi` | regenerated at boot into `/run` (not persistent) |

## Consequences

- API (agent): `NodeConfig.k8s.kubelet` (typed, allow-listed). `k8s.join` stays first-boot only; changing it after
  the join is rejected with a clear error instead of `reboot_required`. Decide hostname vs machine identity as the
  source of `nodeName` (today: hostname).
- Profile `k8s-worker`: per-minor defaults in `/usr/lib/foilbird/kubelet/<minor>/`; kubelet drop-in uses the rendered
  config and flags from `/run/foilbird/kubelet/`; `staticPodPath` disabled; `kubeadm-flags.env` ignored; the agent renders
  `/run/foilbird/kubelet/`.
- The `--pod-infra-container-image` problem disappears: flags come from the image of the booted minor.
- New acceptance test T14, mandatory for the next stage. It uses a real kubelet minor transition, not a
  broken kubelet of the same minor. The cluster's control plane must be on N+1 for the forward step (skew).

  | Step | Expected |
  |---|---|
  | node on N with GPU workload → release N+1 (A/B) | kubelet N+1 starts with the configuration rendered for N+1 |
  | configuration for N+1 | valid for N+1 (no deprecated or removed fields or flags) |
  | GPU workload | runs again after the planned drain/restart |
  | rollback N+1 → N (forced, e.g. broken N+1 build or controller-driven) | kubelet N starts without manual action |
  | NVIDIA CDI | `nvidia.com/gpu` allocatable again, a GPU pod runs |
  | device-plugin checkpoint, `dra_manager_state`, manager state, containerd content | no incompatible persistent state; the inventory above is filled in with the observed policy |
  | Node UID, `machine-id`, `nodeName` | unchanged |
  | Kubernetes Ready | restored |

  Not yet tested: how strictly each kubelet minor parses the config file, and the cross-minor compatibility of the
  state files above. The PoC results (A/B 2→4→6→8 and T7 on the GPU test node) are all within one kubelet minor and do not
  prove cross-minor compatibility.
- Model B (kubelet as a signed sysext) is not needed now; this decision does not prevent it later, because the
  agent renders for "the kubelet that is booted" whatever delivered it.

## Requirements changed

- API of the node agent
  - new: `NodeConfig.k8s.kubelet` — typed, allow-listed kubelet overrides; drain-requiring fields need a
    controller "drained" statement;
  - new: `ApplyConfig` for the kubelet is transactional (pending/committed generations, automatic restore);
  - new: `StageUpdate` rejects a release whose kubelet minor is newer than the cluster's apiserver minor;
  - changed: `k8s.join` is first-boot only; changing it after the join is an error, not `reboot_required`.
- Profiles (`k8s-worker`)
  - new: the kubelet version is a property of the OS release; one image stream per Kubernetes minor;
  - new: per-minor kubelet defaults in the image; the kubelet runs only on agent-rendered config and flags;
  - new: kubeadm is used only for the first join and TLS bootstrap; the cluster ConfigMap is not a source of truth.
- Update, rollback, persistent state
  - changed: kubelet configuration and flags are not persistent; they are rendered into `/run` at every boot;
  - new: every version-dependent state on `/var` has a documented rollback policy; no automatic deletion on rollback;
  - made concrete: `staticPodPath` is empty (was "off or a generated `/etc`");
  - new: identity table (machine-id, nodeName, providerID, Node UID, kubelet certificate) and the anti-cloning rule.
- Tests
  - new: T14 — rollback across a kubelet minor with a GPU workload (table above);
  - new: boot-order acceptance (first join, re-join after `/var` was recreated).
- Open questions
  - closes PoC backlog items 1 (kubelet version model) and 2 (kubelet configuration after join);
  - opens: hostname vs machine identity as the source of `nodeName`.
