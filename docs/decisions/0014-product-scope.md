# 0014. Product scope: an immutable Debian node OS managed through an API, one base, no mutable variant

- Status: accepted (2026-11-24)
- Scope: what Foilbird OS is and is not; base distribution and OS backends; the security contract of the
  `container-host` profile. Does not change v1-alpha: its scope and image contents stay as they are.

## Context

The project was asked to consider a broader direction: one platform for immutable **and** mutable Linux, on several
base distributions (Debian, Rocky Linux, others), with a fleet control layer. Two things were fixed at the same time:

1. **Open source only.** There is no paid control plane and no commercial layer.
2. **The main goal** is a native, safe and fast way for an LLM (and any other API client) to manage a Linux node.
   Kubernetes nodes, with or without GPUs, are a narrow, well-formalised case where an immutable OS is enough. Container
   hosts (Docker / compose) looked as if they might need a mutable OS.

A comparison with [bootc](https://github.com/bootc-dev/bootc) found:

- bootc covers the OS image layer: OCI build and transport, installation, ostree or composefs deployments, UKI, manual
  rollback, soft reboot. It has no remote node agent, no declarative node configuration, no TPM-based node identity,
  no anti-rollback floor and no rollout controller; on the composefs backend it has no boot counting.
- Foilbird overlaps with bootc only in the image layer (build, A/B update and rollback, UKI signing), and that layer
  is already made of stock systemd parts (mkosi, systemd-sysupdate, UKI, systemd-boot), not an own update engine.
- bootc has no working path for Debian. Rocky Linux has no official bootc image.
- A container host does not need a mutable OS: an immutable OS, a writable `/var` and a declarative workload
  specification are enough. The exceptions are out-of-tree kernel modules, vendor agents that ship kernel modules, and
  one-off host packages.

## Decision

### 1. What Foilbird OS is

Foilbird OS is an **open-source, immutable, Debian-based node OS designed to be managed by an LLM** through a typed,
declarative, capability-scoped API, without a shell and without exec. What sets it apart is the management contour,
not the image format:

- an agent API without exec and without file paths, access levels and roles, MCP tools derived from the `.proto`
  (`api/README.md`);
- a transactional node configuration (`NodeConfig`, decision 0005; generations and `TRY` with a local health revert,
  decision 0013, Z1);
- TPM-based node identity and registration (decision 0009, reserved);
- boot gate, automatic revert, anti-rollback floor (decisions 0002, 0003, 0012) and a rollout controller (decision
  0008, reserved).

### 2. Base distribution and OS backends

- **Debian 13 built with mkosi is the required backend, the current one and the only one implemented** (decision
  0001 unchanged). The invariants "unmodified binary packages of the Debian archive" and "built with mkosi" bind this
  backend; changing them needs its own decision.
- **Rocky Linux, AlmaLinux and other RPM bases are not a requirement.** A second backend is not created without a
  concrete consumer who needs it.
- A **hybrid** is allowed, by a separate decision when such a consumer appears: one common layer (agent, API,
  `NodeConfig`, TPM identity, anti-rollback, rollout controller) over several OS backends.
- An abstraction is introduced **only at the real boundary between the agent and the OS**, and only for a capability
  that a second backend actually needs. No generic package-manager API, no distribution adapter layer, no promise that
  APT and DNF have the same semantics. No Debian, APT or sysupdate concept appears in the agent API.

### 3. No mutable variant

- A mutable Foilbird OS is not built and is not on the roadmap. Conventional virtual machines stay under conventional
  configuration management without the agent; Foilbird OS does not replace such tools.
- This is reopened only for a concrete workload that cannot run on an immutable profile.
- Out-of-tree kernel modules and vendor agents are handled by a separate image profile per host class (as the NVIDIA
  modules are in the GPU image), not by changing a running host.

### 4. Security contract of the `container-host` profile

This contract applies **only to the `container-host` profile**. The Kubernetes profile (`profiles/k8s-worker`) is
outside it and keeps its own model: rootful containerd and kubelet; privileged pods are denied by the cluster's
admission policy (the OS does not block them, decision 0010); `/usr` is immutable.

1. **A rootful container runtime is forbidden by default.** The default runtime is **rootless Podman with Quadlet**;
   **rootless Docker** is allowed. A rootful runtime needs a separate decision that states the weakened guarantee.
2. **The runtime's API socket is reachable only by the agent and by one dedicated unprivileged user** that runs the
   workloads. No socket is exposed to workloads (mounts of `podman.sock` / `docker.sock` are denied).
3. **Workloads are declared through the agent**, not started by hand. The agent validates every workload
   specification against a policy before it reaches the runtime.
4. **`privileged` and dangerous host mounts only with a stated reason** in the workload specification: `privileged`,
   host `pid` / `ipc` / `net` / `userns` namespaces, host path mounts outside an allow-list, added capabilities outside
   an allow-list, raw devices outside an allow-list (GPUs through CDI only).
5. **Unprivileged user namespaces are a trade-off.** Rootless containers require them, and they are a kernel attack
   surface: they let an unprivileged process reach kernel code (network, file system, namespace setup) that is
   otherwise reachable only as root. The profile enables them because rootless needs them; this is a conscious
   exchange of a rootful daemon for a larger unprivileged kernel surface.
6. **Rootless does not protect absolutely against kernel vulnerabilities.** A kernel exploit from a container gives
   root on the host whatever the runtime mode.
7. **Persistence is prevented by the OS, not by the runtime:** `/usr` on signed dm-verity, measured boot and the TPM
   binding of `/var` (`docs/disk-encryption.md`). What can persist on `/var` is described in decision 0010.
8. Break-glass access (decision 0011, reserved) is root-equivalent on that host; while it is in use, item 7 is stated
   as not holding.

Disabling unprivileged user namespaces on Kubernetes nodes is **not a requirement**. It is an open hardening question
that needs a compatibility assessment (see Open questions).

### 5. `container-host` is outside v1-alpha

The API already names the profile (`PROFILE_CONTAINER_HOST`), but v1-alpha builds no `container-host` image. The
v1-alpha scope, its acceptance criteria and the contents of its images do not change because of this decision.

### 6. LLM interface

- The agent API is the primary interface; **MCP is an adapter** derived from it, never a path to a shell.
- The model manages the node **only** through declarative resources and typed operations. The agent itself may use
  privileged mechanisms internally (systemd over D-Bus, netlink, the container runtime API, sysupdate). This restates
  the existing rule "agent API without exec"; it is not a new decision.
- Mutating operations follow **plan → approve → apply(plan id) → verify**: `apply` accepts only the id of a plan that
  was produced and has not changed since (builds on decision 0013, Z1 `TRY` and Z2 `dry_run` with a typed diff).
- Reference scenario for testing the API end to end: *"prepare this node to run a compose application with PostgreSQL
  and Redis"*: discover hardware and capabilities, build the declarative configuration, check the policy, plan, ask for
  permission, apply, verify, return a structured report, with no SSH and no shell at any step.

### 7. Explicitly not done

| Not done | Why |
|---|---|
| paid or commercial control plane | open source only |
| mutable Foilbird OS | item 3 |
| Rocky Linux or another second backend without a consumer | item 2 |
| own OS update or rollback engine beyond systemd parts | not needed; the image layer is replaceable |
| adopting bootc | no Debian path; breaks "Debian archive" and "mkosi" with no gain on the management side |
| generic package-manager abstraction | item 2 |
| rootful container runtime on `container-host` by default | item 4 |

### 8. Ideas to evaluate (not decided)

1. Distributing system images as OCI artifacts through a registry. Not verified with mkosi and systemd-sysupdate.
2. A release manifest that binds OS, kernel, NVIDIA driver, container runtime, CDI toolkit and application images into
   one tested combination.
3. `systemctl soft-reboot` (a systemd feature) for updates that change user space only.

## Consequences

- No code change follows from this decision alone. v1-alpha is not affected.
- The `container-host` profile gets its own design record before it is built; it must include the item 4 contract and
  policy list.
- Two deferred items of decision 0013, Z1 and Z2, gain a consumer: the plan / apply flow of item 6.
- Positioning text (README, release notes) is aligned with item 1 when the next release is written.

## Open questions

| # | Question | How to close |
|---|---|---|
| 1 | On `container-host`, can anything besides the agent and the workload user reach the runtime API (break-glass, local services)? | design of decision 0011 and the profile's design record |
| 2 | Rootless Podman on the image: GPUs through CDI, network throughput, ports below 1024, Quadlet coverage of real compose files | a test with two or three real compose applications, one with a GPU |
| 3 | Compose → Quadlet: which compose fields map, which the policy rejects | inventory over the same applications |
| 4 | Plan id binding: what the plan hash covers (specification, node generation, policy version) and how long it lives | design note for decision 0013, Z1 / Z2 |
| 5 | Disabling unprivileged user namespaces on Kubernetes nodes: what breaks (Kubernetes user namespaces for pods, build tools in pods, browsers and sandboxes in workloads) and what it gains | compatibility assessment; a hardening option at most, not a requirement |
