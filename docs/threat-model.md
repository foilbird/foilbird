# Threat model: claims and their evidence

This page maps every security claim the project makes to the decision that states it and the test that checks it. It
adds no claim of its own. The attackers considered, what holds against each and the limits are stated in [decision
0010](decisions/0010-root-on-the-node-and-var-recovery.md); the security contract of the `container-host` profile in
[decision 0014](decisions/0014-product-scope.md), item 4. Where a test is named, its definition is in
[tests/README.md](../tests/README.md), "Test ids"; where none is named, the claim rests on the mechanism only. Where
each test was run for v1-alpha is listed only in the [release notes](release-notes/v1-alpha.md).

## Attackers

As in decision 0010, "Attackers": (A) root on a running node, including a pod with `hostPID` or `hostPath: /`;
(B) an API client with a stolen certificate of some role; (C) physical access to the powered-off disk, ESP included;
(D) a hostile update channel or network. Compromise of the deployment's own keys, firmware, BMC or hypervisor is out of
scope.

## Claims

| Claim | Mechanism | Against | Stated in | Test |
|---|---|---|---|---|
| nothing on the node to log in with or to run a script with | image policy: no shell, interpreter, network client or package manager beyond the allow-list; no SSH, no console login | A, B | [image-policy.md](image-policy.md), decision 0010 | T5 (harness scenario `30-t5`) |
| no RPC executes a command | the `.proto` has no field for a command, script, argument vector, path, binary or URL | B | `api/README.md` | T8 |
| each role gets only its access level | mutual TLS, role = client certificate OU, one level per RPC; calls audited | B | `agent/README.md`, "Authorization" | T12; `RaiseMinVersion` refused for reader and controller (harness scenario `70-epoch`) |
| `/usr` cannot be changed unnoticed | erofs on dm-verity, root hash in the command line of the signed UKI | A, C | decision 0010, "What holds" | — (the harness boot check reads the Secure Boot state and `usrhash=`; no test corrupts `/usr`) |
| changes outside `/var` do not survive a reboot | root and `/etc` are a tmpfs; no system or configuration extensions | A | [decision 0007](decisions/0007-no-system-extensions.md) | — |
| an executable written to the kubelet's or the temporary directory of `/var` does not run after a reboot | `noexec` mounts (`k8s-worker`) | A | `profiles/k8s-worker/README.md` | T6 |
| no unsigned kernel code | `lockdown=integrity module.sig_enforce=1`; containerd's bounding set has no `CAP_SYS_MODULE`, no `CAP_SYS_BOOT` | A | decision 0010, "What holds" | — |
| the channel cannot install what the release key did not sign | signed `SHA256SUMS`, checked by the agent and by the installer | D | [decision 0002](decisions/0002-update-staging.md) | T10 |
| an older release cannot be staged or open `/var` once the floor is raised | anti-rollback floor; PCR key epochs, the raise wipes older epochs' slots | A, D | [disk-encryption.md](disk-encryption.md) | T3, T20b, harness scenario `70-epoch` |
| a broken release does not keep the node | boot counting; the agent confirms a boot only when its health checks pass; the previous release boots after the last try | — | [decision 0003](decisions/0003-boot-loop-recovery.md), [boot-assessment.md](boot-assessment.md) | T7 (harness scenario `60-t7`) |
| `/var` is unreadable on a stolen disk | LUKS2, one TPM2 slot, PCR 7 and a signed PCR 11 policy | C | [disk-encryption.md](disk-encryption.md) | — (the harness boot check reads that `/var` is LUKS2 bound to the TPM; no test reads a stolen disk) |

> **v1-alpha limitation** (fix planned for v1-alpha4): row "no RPC executes a command": a control plane's `k8s.init` is
> passed to `kubeadm init` as given, so on a node without a role `ApplyConfig` with it is equivalent to root
> ([api/README.md](../api/README.md#rules), "Rules").

> **v1-alpha limitation** (fix planned for v1-alpha4): row "`/var` is unreadable on a stolen disk": this holds for a
> disk without its machine; with the node itself (disk and TPM together) a plain `/var` put in its place boots, its
> configuration is applied and the TPM policy of the original `/var` is still met
> ([disk-encryption.md](disk-encryption.md#disks-set-up-before-var-encryption)).

## Container escape

**`container-host` (outside v1-alpha).** A container escape does not give persistence and root control of the node, in
these words and within these limits (decision 0014, item 4):

- the runtime is rootless, so an escape lands as the one unprivileged workload user, not as root; the runtime's API
  socket is reachable only by the agent and that user;
- the system part does not keep changes; the OS, not the runtime, holds it: `/usr` read-only on signed dm-verity,
  measured boot, `/var` bound to the TPM;
- **a kernel exploit from a container gives root on the host whatever the runtime mode** (item 6); unprivileged user
  namespaces, which rootless needs, enlarge the kernel surface reachable without root (item 5);
- what can persist on `/var` is stated in decision 0010, "Limits"; while break-glass access is in use the persistence
  claim does not hold (item 8).

The word is "does not give", not "prevents": the claim is about what an escape yields within these limits, not that an
escape cannot happen.

**`k8s-worker` (v1-alpha).** The contract above does not apply. containerd and kubelet are rootful; a privileged pod or
one with `hostPID` / `hostPath: /` is root on the node, and the cluster's admission policy is the boundary (decision
0010, limit 8). Against such root, `/usr` and the boot chain still hold, but a pod can persist on `/var`, for example as
a static pod manifest (limit 6).

## Limits

Root on a running node can do everything the node can, keep the current `/var` key, and persist on `/var`; first boot
is trust on first use; one client CA issues every role. The full list, and what to do when root on a node is suspected,
is decision 0010, "Limits"; the deferred answers are in [decision 0013](decisions/0013-deferred-in-v1alpha.md).
