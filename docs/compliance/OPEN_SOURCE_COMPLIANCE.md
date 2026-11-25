# Open source compliance register

Gate: no public OS image is published until every row below is verified for the exact
release being shipped.

| Component | License | Redistribution in image | Obligations | Status |
|---|---|---|---|---|
| Debian packages | per package (`/usr/share/doc/*/copyright`) | yes, unmodified | per license; provide sources on request | to audit |
| Linux kernel (our builds) | GPL-2.0 | yes | corresponding source with each release: exact source, our patches, build config, build scripts | to implement |
| NVIDIA open kernel modules | MIT / GPL-2.0 (check files of the release) | yes | notices; sources for GPL parts | to audit |
| NVIDIA user space driver | NVIDIA proprietary license | conditional: unmodified Linux binaries may be redistributed under the license terms | keep notices, no modification; check the license text of the exact release | to audit |
| NVIDIA firmware (GSP) | NVIDIA proprietary | conditional | as above | to audit |
| containerd, runc | Apache-2.0 | yes | LICENSE / NOTICE; listed in the per-image notices | listed per image |
| Node agent (Rust), controller (Go) | Apache-2.0 | yes | LICENSE / NOTICE | — |

Every image build writes `foilbird-sbom.cdx.json` (CycloneDX 1.5) and `THIRD-PARTY-NOTICES.txt` next to the image and
into it (`/usr/share/foilbird/`), see `THIRD_PARTY_NOTICES.md`; NVIDIA inputs and their provenance are in
`/usr/share/foilbird/sbom/nvidia-inputs.json`. Images with NVIDIA components are not published (v1-alpha).

Release layout (planned): image, UKI, `manifest.json`, `foilbird-sbom.cdx.json`, `THIRD-PARTY-NOTICES.txt`, `provenance.json`,
`sources/` (kernel source, patches, build config).
