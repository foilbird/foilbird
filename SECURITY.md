# Security policy

## Reporting a vulnerability

Report vulnerabilities **privately**:

1. by e-mail to **security@foilbird.com** (preferred);
2. or through GitHub's private vulnerability reporting: the **"Report a vulnerability"** button on the repository's
   **Security** tab.

Do not open a public issue, pull request or discussion for a suspected vulnerability.

Include what you can: the commit, the image build parameters (`build-params.txt`, without keys), the steps that show the
problem, and what an attacker gains. Never send private keys, production credentials or data of real nodes.

During alpha, reports are handled on a best-effort basis; there is no guaranteed response time. We agree on a
disclosure date with the reporter. There is no bug bounty.

## Supported versions

The project is in **v1-alpha**: only the latest commit of the default branch is supported. There are no maintained
release branches and no backported fixes.

## Scope

In scope: the image build (`images/`, `profiles/`), the node agent and `foilctl` (`agent/`), the API contract (`api/`)
and the documents that describe security properties.

Known limits are not vulnerabilities: what root on a running node can do, `/var` recovery and the other limits in
[decision 0010](docs/decisions/0010-root-on-the-node-and-var-recovery.md) and the
[release notes](docs/release-notes/v1-alpha.md). A way around a property listed there as holding is a vulnerability.

Out of scope: vulnerabilities in Debian packages, the Linux kernel, systemd, Kubernetes, containerd or NVIDIA software
(report them upstream; tell us if our pinned version is affected), and attacks that need the deployment's own signing
keys.

## Keys

The project holds no release, Secure Boot or PCR key and publishes no signed images. Any key in this repository's CI or
test harness is ephemeral and marked `TEST`; it protects nothing (decision 0012).
