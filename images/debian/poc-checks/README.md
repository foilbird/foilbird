# PoC boot checks (lab builds only)

Not part of any product image; `images/debian/tools/lab-gate` fails a build that carries them.

`tree/usr/libexec/foil-poc-check` (enabled by `multi-user.target.wants/`) prints the boot facts and the T9 results to the console
and to `/boot/foil-poc-check.log`, then powers the machine off: Secure Boot state, module signature enforcement (`t9-unsigned`,
`t9-other` refused, `t9-db` loaded), verity read, `nvidia-smi`, CUDA driver init (`cuda-init`). The test modules and
`cuda-init` are built into `/usr/lib/foil-poc-check` by `mkosi/mkosi.build` only with `FOILBIRD_POC_CHECKS=1`:

```sh
./build-image.sh ... -- --environment=FOILBIRD_POC_CHECKS=1 --extra-tree="$PWD/poc-checks/tree:/"
```
