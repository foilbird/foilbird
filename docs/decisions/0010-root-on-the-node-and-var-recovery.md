# 0010. Threat model limits: root on a running node, `/var` recovery and TPM reset

- Status: proposed (draft for v1-alpha); records limits of v1-alpha and the direction for v1, implements nothing new
- Scope: image (`images/debian`), `/var` encryption and epochs (`docs/disk-encryption.md`), agent health and audit
  (`agent/`), Kubernetes profile (`profiles/k8s-worker`)

## Problem

The image is built so that the system part of a node cannot be changed unnoticed and that an older release cannot open
`/var` once the floor is raised. Those properties have limits. A user who reads "immutable", "Secure Boot" and "TPM" and
assumes more is protected than it is will be wrong in exactly the cases that matter. This record states the attackers
the design considers, what holds against each of them, and, in the same place, what does not.

## Attackers

| | Attacker | Considered |
|---|---|---|
| A | a workload, or anyone, with root on a running node (including a pod with `hostPID` or `hostPath: /`) | yes |
| B | a client of the agent API with a stolen certificate of some role | yes |
| C | physical access to the powered-off disk, **including the ESP** | yes |
| D | a hostile update channel or network | yes |
| — | compromise of the deployment's release, Secure Boot or PCR keys; attacks on firmware, BMC or the hypervisor | **out of scope** |

## What holds

| Property | Mechanism | Against |
|---|---|---|
| `/usr` cannot be changed unnoticed | erofs on dm-verity, root hash `usrhash=` on the command line of the signed UKI | A, C |
| changes outside `/var` do not survive a reboot | root file system and `/etc` are a tmpfs; no system or configuration extensions (decision 0007) | A |
| no unsigned kernel code | `lockdown=integrity module.sig_enforce=1`; containers have no `CAP_SYS_MODULE` and no `CAP_SYS_BOOT` (k8s-worker: `CapabilityBoundingSet` of `containerd.service`, `profiles/k8s-worker/README.md`, "Configuration") | A |
| no shell, no SSH, no console login, no exec over the API | image policy; API without command execution (`api/README.md`) | A, B |
| the API gives each role only its level | mutual TLS, role in the client certificate's OU (`agent/README.md`, "Authorization"); every call audited | B |
| the update channel cannot install what the release key did not sign | signed `SHA256SUMS`, checked by the agent and again by the installer (decision 0002) | D |
| an older release cannot open `/var` after a raise | PCR key epochs: the raise wipes the older epochs' key slots; raise and enroll decide only on data signed by the release key in `/usr` (`docs/disk-encryption.md`, "Units (image) and files") | A, D |
| `/var` is unreadable on a stolen disk | LUKS2, one TPM2 slot, policy PCR 7 + signed PCR 11 policy | C |
| a written ESP gives no TLS material or configuration to a product build | the product agent ignores TLS material and configuration on the ESP; reading them is a lab-only feature (`agent/README.md`, "Build") | C |

> **v1-alpha limitation** (fix planned for v1-alpha4): "no exec over the API": a control plane's `k8s.init` is passed to
> `kubeadm init` as given, so on a node without a role `ApplyConfig` with it is equivalent to root
> ([api/README.md](../../api/README.md#rules), "Rules").

> **v1-alpha limitation** (fix planned for v1-alpha4): "`/var` is unreadable on a stolen disk": this holds for a disk
> without its machine; with the node itself (disk and TPM together) a plain `/var` put in its place boots, its
> configuration is applied and the TPM policy of the original `/var` is still met
> ([disk-encryption.md](../disk-encryption.md#disks-set-up-before-var-encryption)).

## Limits: what root on a running node can do

These are not bugs to be fixed in v1-alpha. Some have no fix without remote attestation.

1. **Everything the node can.** Root reads `/var` (Kubernetes credentials, workload data), the agent's TLS key in
   `/run/credentials` (`systemd.exec(5)`, "Credentials"), and can answer API calls in the agent's name. On a virtual
   machine the same credentials are SMBIOS type 11 strings (`smbios-type-11(7)`): readable from the SMBIOS table
   (`/sys/firmware/dmi`) by root on the node and from the machine's configuration by root on the hypervisor (assumed
   from how the credentials are passed; not demonstrated by a test).
2. **It keeps the `/var` key.** While the booted release runs, the TPM policy is satisfied: root can unseal the key of the
   current slot and later open `/var` offline with the node's own slot. No reconciliation of key slots can see this
   (assumed from the policy design; not demonstrated by a test). Only a key change helps: a new epoch (enroll, then
   raise), or re-encryption when the node is reinstalled.
3. **It can replace the only TPM2 slot** with one of its own that claims the same public key in the token's JSON. By
   LUKS2 metadata the two cannot be told apart (assumed from the slot selection of raise, `docs/disk-encryption.md`,
   "Units (image) and files": a token is kept by the key it names; not demonstrated by a test). This needs remote
   attestation, which v1-alpha does not have (decision 0013, Z12).
4. **It can rewrite the reports in `/run`.** `GetHealth` reports unknown or foreign key material on `/var` as `CRITICAL`
   (`var-key-slots`); that is a witness against an intruder who does not stay, not a control. The control is that a
   raise wipes what does not belong.
5. **It can lower the floor file** `/var/lib/foilbird/min_version`, but not the floor built into the image (the agent's
   floor is the higher of the two, `docs/disk-encryption.md`) and not the epochs (decision 0013, Z13): a release of a wiped epoch still cannot open `/var`. A release that is still above the floor and has a key
   slot (for example the previous slot) can be booted by an attacker with root.
6. **It can persist on `/var`.** Kubernetes keeps static pod manifests on persistent storage
   (`profiles/k8s-worker/README.md`, "Known gaps"); container images and their contents are on `/var`. A pod added this
   way survives reboots and updates.
7. **It can write the ESP**: remove or rename boot entries and counters (denial of service), but not make an unsigned
   UKI boot.
8. **Kubernetes is the boundary for pods.** `kubectl debug node/` and pods with `hostPID` / `hostPath: /` are not blocked
   by the OS; such a pod is root on the node. The cluster's admission policy decides (decision 0011, reserved).

Other limits from the same table of attackers:

- **First boot is trust on first use** (C): the image enrolls its Secure Boot keys when the firmware is in setup mode.
  Whoever controls the machine before the first boot chooses the keys (decision 0012).
- **One client CA** (B): any certificate it issues with `OU=operator` can call every RPC, including `EMERGENCY` ones
  (decision 0013, Z6).
- **An older signed release** (D): a hostile channel can serve any release the key signed; only the floor protects, as
  release metadata has no expiry yet (decision 0013, Z9).

**What to do when root on a node is suspected:** treat the node as lost. Reinstall it: wipe the disk, clear the TPM,
issue new TLS material. If it cannot be reinstalled at once, raise to a new epoch, so the copied `/var` key stops working
on that disk; this does not undo anything already read.

## `/var` recovery and TPM reset

**v1-alpha:** `/var` has one TPM2 key slot and no recovery key. After a TPM reset (firmware update that clears it,
board replacement, TPM clear) or a lost key slot, no release opens `/var`. The node stays up without `/var`, units that
need it fail, and the only recovery is a reinstall (`docs/disk-encryption.md`, "When no token opens /var"). All node
state is on `/var`, so the node's configuration and identity are lost with it.

**Direction for v1** (decision 0013, Z4 and Z10; not implemented):

- the agent tells "TPM was reset" from "failure"; on a Kubernetes worker, whose `/var` is disposable, it recreates `/var`
  and takes the node's identity from the small `state` partition (reserved on fresh v1-alpha installations, unused);
  if `state` is lost too, the node re-registers;
- profiles whose `/var` is not disposable get a recovery key encrypted to an escrow key held by the deployment;
- any added key slot (recovery included) goes through the same tool and lock as the epoch slots, and the health check
  learns to expect it, so a legitimate recovery slot is not reported as `CRITICAL`.

## Consequences

- The documentation and the release notes do not claim protection against root on a running node beyond the table
  "What holds", and list the limits above ([release notes](../release-notes/v1-alpha.md)).
- Losing `/var` or the TPM state means reinstalling the node in v1-alpha.
- Remote attestation (decision 0009, reserved) is the planned answer to limit 3. Limit 2 has no answer other than a key
  change (new epoch or reinstall). Until then both stand.
