# Contributing

Thank you for your interest in this project.

## License

All contributions are made under the [Apache License 2.0](LICENSE). There is no
Contributor License Agreement (CLA).

## Developer Certificate of Origin (DCO)

Every commit must be signed off under the [Developer Certificate of Origin 1.1](DCO).
Signing off means you certify the statements in the DCO for that commit.

Add the sign-off with:

```sh
git commit -s
```

which appends a line like:

```
Signed-off-by: Your Name <your.email@example.org>
```

The name and e-mail must match the commit author. Pull requests with unsigned
commits are not merged; maintainers check the sign-off before merging (there is no
CI check for it yet).

## Ground rules

- Never commit signing keys, credentials or build outputs. Keys in tests are
  ephemeral and carry `TEST` in their name (`tests/lib/keys.sh`).
- Never commit or attach anything built with NVIDIA components (images, `/usr`
  partitions, kernel modules, user-space libraries, package caches): NVIDIA's
  licence terms restrict redistribution of its driver and user space.
- Changes to the security model (boot chain, update, keys, agent API) start with a
  decision record in `docs/decisions/`.
- A change that makes a limit in the [release notes](docs/release-notes/v1-alpha.md)
  or in decision 0010 obsolete updates that text in the same pull request.
- Security issues are reported privately, see [SECURITY.md](SECURITY.md).

## Building and testing

- Agent: `agent/build-release.sh` (pinned toolchain and tools, `agent/README.md`),
  tests `cargo test --release --locked` in `agent/`.
- Image: `images/debian/README.md` and the profile's README.
- Boot tests in QEMU: `make test IMAGE=… FOILCTL=…`, or `make test-selfcheck`
  without an image (`tests/README.md`).
