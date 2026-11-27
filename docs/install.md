# Installing a node (v1-alpha)

v1-alpha publishes no images: you build one with your own keys, then install it. The only install path verified in
v1-alpha is a **virtual machine** with OVMF Secure Boot and a TPM 2.0: plain QEMU/KVM or Proxmox VE (section 5). A
physical machine has no supported way to receive the agent's TLS material yet
([release notes](release-notes/v1-alpha.md), "Known limitations").

The commands below follow what the test harness does (`tests/lib/keys.sh`, `tests/lib/vm.sh`); read those scripts for
the exact options. Every key you create here belongs to your deployment. Never commit one.

## 1. Build host

Debian 13 with mkosi, OpenSSL and GnuPG, plus Rust (`rustup`; `agent/rust-toolchain.toml` pins the compiler) and
`musl-tools` for the agent. The build scripts name what else they need when it is missing; a list of verified tool
versions is not part of v1-alpha. An agent built with the host's own gcc and binutils works, but its bytes differ from a
CI build and the build manifest records it as `agent-toolchain` `unrecorded`; for the same bytes as CI, build the agent
with the C toolchain of `agent/c-toolchain.pins` (`docs/reproducible-build.md`, "C toolchain of the agent"). The
image build fetches packages from Debian, the Kubernetes repository and NVIDIA's repository, checking each against a
pinned key (`images/debian/README.md`, `profiles/k8s-worker/README.md`).

## 2. Keys

| Key | Create | Used by |
|---|---|---|
| Secure Boot db key and certificate | `openssl req -x509 …` (`images/debian/README.md`, "Building") | `build-image.sh --sb-key/--sb-cert`: signs the UKI, the `/usr` verity signature and the NVIDIA kernel modules |
| PCR 11 policy key | the same, a second key | `--pcr-key/--pcr-cert`: unlocks `/var` |
| release key (OpenPGP, exactly one) | `gpg --quick-gen-key …`, export the public key | `--release-keyring`; signs `SHA256SUMS` of your update channel |
| agent CA | an X.509 CA | issues the node's server certificate and the client certificates |
| node server certificate | from the agent CA, `extendedKeyUsage=serverAuth`, a DNS SAN that `foilctl --server-name` will use | the agent |
| client certificates | from the agent CA, `extendedKeyUsage=clientAuth`, **the role in the Subject OU**: `reader`, `controller` or `operator` | `foilctl --tls-dir` (a directory with `ca.crt`, `client.crt`, `client.key`) |

`tests/lib/keys.sh gen <dir>` creates a complete set of ephemeral keys marked `TEST` (seven days). Use it to try the
steps; do not use those keys for anything else (decision 0012).

## 3. Build

```sh
# agent: static musl binaries, reproducible (agent/README.md, "Build")
cd agent && ./build-release.sh --install-tools && ./build-release.sh && ./stage-image-tree.sh dist && cd ..

# image: initrd and recovery entry, then the base image with the Kubernetes profile
(cd images/debian && foilbird-initrd/build.sh && recovery/build.sh)
cd profiles/k8s-worker      # pinned inputs first: README.md of this directory, "Build"
../../images/debian/build-image.sh --profile . --version 1 --output-dir out/1 \
  --release-keyring release.gpg --sb-key db.key --sb-cert db.crt --pcr-key pcr.key --pcr-cert pcr.crt \
  --epoch 1 --min-version 1 --include ../../images/debian/mkosi/pinned.conf
```

`images/debian/tools/build-all.sh` runs the whole sequence offline from a filled cache; `--variant cp` builds an image
without NVIDIA packages, `--variant gpu` one with the NVIDIA driver and user space.

`profiles/k8s-worker/README.md` ("Build") and `images/debian/README.md` ("Building", "Third-party apt inputs") hold the
full sequence; follow them where they differ from this summary.

The output directory holds the disk image `foilbird-deb_1.raw`, the update files, `build-params.txt` (channel, key
fingerprints, epoch) and `lab-gate.txt`: a product build fails if it carries lab-only code. `--channel <url>` sets a
default update channel; without it the node takes the channel from its configuration (`docs/updates.md`).

## 4. Pass the agent's TLS material

The agent reads `agent.tls-cert`, `agent.tls-key` and `agent.tls-ca` as systemd credentials. In QEMU each one is an
SMBIOS type 11 string `io.systemd.credential.binary:<name>=<base64 of the PEM file>` in its own file:

```sh
cred() { printf 'io.systemd.credential.binary:%s=%s' "$1" "$(base64 -w0 < "$2")" > "smbios/$1"; }
cred agent.tls-cert agent.crt; cred agent.tls-key agent.key; cred agent.tls-ca ca.crt
```

Root on the hypervisor and root on the node can read these strings (decision 0010).

## 5. First boot

```sh
cp --sparse=always out/1/foilbird-deb_1.raw disk.raw && truncate -s 16G disk.raw
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd          # empty variables: firmware in setup mode
swtpm socket --tpm2 --tpmstate dir=tpm --ctrl type=unixio,path=swtpm.sock --daemon
qemu-system-x86_64 -machine q35,smm=on -accel kvm -cpu host -m 3G -smp 2 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -drive if=pflash,format=raw,unit=1,file=vars.fd \
  -chardev socket,id=chrtpm,path=swtpm.sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
  -drive if=virtio,format=raw,file=disk.raw \
  -smbios type=11,path=smbios/agent.tls-cert -smbios type=11,path=smbios/agent.tls-key \
  -smbios type=11,path=smbios/agent.tls-ca \
  -netdev user,id=n1,hostfwd=tcp:127.0.0.1:7443-:7443 -device virtio-net-pci,netdev=n1 -serial stdio -display none
```

On the first boot the image enrolls its Secure Boot keys (setup mode: **trust on first use**, decision 0012), reboots
under Secure Boot, creates slot B, the reserved `state` partition and `/var` (LUKS2, bound to the TPM) with
`systemd-repart`, and starts the agent on port 7443. With virtual firmware that already holds your PK, KEK and db,
setup mode is not needed (`tests/lib/vm.sh`, `--enroll vars`).
Known limitation: the first boot needs `/var` created within 5 minutes (`foil-repart.service`, `TimeoutStartSec=300`);
a slower disk fails the installation.

Check it:

```sh
foilctl --addr https://127.0.0.1:7443 --server-name <SAN> --tls-dir pki/reader health
foilctl --addr https://127.0.0.1:7443 --server-name <SAN> --tls-dir pki/reader info   # Secure Boot, TPM, var_protection
```

### Proxmox VE

Verified on Proxmox VE 9.3 (2026-11-26) with a v1-alpha2 image (TEST keys); not re-run on
v1-alpha3. A control plane and a worker: first boot as above, configuration, Kubernetes init and join, reboot through
the agent. As root on the Proxmox host,
with the disk image and the three SMBIOS files from section 4 in `$F`:

```sh
V=9101; S=<storage>; F=/root/foil
qm create $V --name cp1 --machine q35 --bios ovmf --cpu host --cores 2 --memory 3072 --balloon 0 \
  --net0 virtio,bridge=vmbr0 --ostype l26 --scsihw virtio-scsi-single \
  --efidisk0 $S:1,efitype=4m,pre-enrolled-keys=0 --tpmstate0 $S:1,version=v2.0 \
  --virtio0 $S:0,import-from=$F/foilbird-deb_1.raw --boot order=virtio0
qm resize $V virtio0 16G
qm set $V --args "-smbios type=11,path=$F/smbios/agent.tls-cert -smbios type=11,path=$F/smbios/agent.tls-key \
  -smbios type=11,path=$F/smbios/agent.tls-ca -chardev file,id=ser,path=$F/cp1-serial.log -serial chardev:ser"
qm start $V
```

- `efitype=4m,pre-enrolled-keys=0` gives the Secure Boot OVMF (`OVMF_CODE_4M.secboot.fd`) with empty variables:
  setup mode, as above (`qm showcmd $V` shows it).
- The SMBIOS strings go through `args`, which only root may set (`qm set --args`, kept in
  `/etc/pve/qemu-server/<vmid>.conf`); root on the Proxmox host can read them (decision 0010).
- The serial console of the image (ttyS0) is written to a file through `args`; the first boot is logged there.
- The first boot formats `/var`; on a slow disk (an HDD with discard) it took about 3.5 minutes until the agent
  listened.
- Give each node a fixed address (a DHCP reservation by MAC or a static address in its configuration): the Kubernetes
  endpoint and the API server certificate name the address of the first configuration.

## 6. Configure

The configuration is applied through the API in one call, `ApplyConfig`, with the generation the node reports
(`foilctl … config`). The role is explicit and fixed for the installation (`profiles/k8s-worker/README.md`, "Node role").

```sh
G="--addr https://127.0.0.1:7443 --server-name <SAN> --tls-dir pki/controller"

# control plane: kubeadm init with your InitConfiguration (join tokens with ttl, graceful shutdown and kube-apiserver
# audit are required: profiles/k8s-worker/README.md, "Control plane init configuration") and the cluster CA
foilctl $G --hostname cp1 --mac <MAC> --dhcp --ntp <NTP server> --role control-plane \
  --k8s-init init.yaml --k8s-ca-crt ca.crt --k8s-ca-key ca.key --expected-generation <N> apply

# worker: kubeadm join
foilctl $G --hostname w1 --mac <MAC> --dhcp --ntp <NTP server> --role worker \
  --k8s-endpoint <API server>:6443 --k8s-token <token> --k8s-ca-hash sha256:<hash> --expected-generation <N> apply
```

If the reply says `reboot_required`, reboot through the agent (`foilctl … reboot`). The first Kubernetes join waits for a
synchronized clock (`agent/README.md`, "Boot confirmation"). `ApplyConfig` has no dry run and no automatic revert: a
configuration that cuts the node off its network means a reinstall. Every `foilctl` option is listed at the top of
`agent/src/bin/foilctl.rs`.

## 7. Updates

Publish each release (`SHA256SUMS`, its signature by your release key, the update files) on your channel; stage and
reboot node by node (`foilctl … --target <V> stage`, then `foilctl … --expect-staged <V> reboot`). A release that fails
its boot checks three times rolls back by itself. Details: `docs/updates.md`, decisions 0002 and 0003.

## Reinstalling

Losing `/var`, clearing the TPM, changing the node's role or removing its Kubernetes settings all mean a reinstall:
a new disk image, new UEFI variables, a cleared TPM, new TLS material.
