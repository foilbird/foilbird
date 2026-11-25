#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""T12 ext: the authorization matrix "every RPC x every role", generated from
the .proto ((foilbird.agent.v1alpha1.roles), via check_proto.py --roles), compared with
what a running agent answers (agent/examples/authz_probe.rs output).

Usage:
  authz_matrix.py expected [proto_root]            print the expected matrix
  authz_matrix.py check PROBE_DIR [proto_root]     compare; exit 1 on any mismatch

PROBE_DIR holds one file per certificate, <name>.txt, lines "<Rpc> ALLOW|DENY <code>" or
"<Rpc> ERROR transport" (the call never reached the server): ERROR is a mismatch in every
cell, never an allow or a deny.
<name> is a role (reader, diag, updater, configurer, controller, operator), or
"none" / "workload" / "noeku" (no role, or no clientAuth EKU: everything denied),
or roles joined with "+" (several OUs: union), e.g. "reader+updater".
"""
import pathlib
import subprocess
import sys

ROLES = ["reader", "diag", "updater", "configurer", "controller", "operator"]
DENY_ALL = {"none", "workload", "noeku"}


def table(proto_root: str | None) -> dict[str, set[str]]:
    tool = pathlib.Path(__file__).resolve().parent / "check_proto.py"
    args = [sys.executable, "-I", str(tool), "--roles"] + ([proto_root] if proto_root else [])
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    t = {}
    for line in out.splitlines():
        name, _level, roles = line.split()
        t[name] = {r.removeprefix("ROLE_").lower() for r in roles.split(",")}
    return t


def expected(t: dict[str, set[str]], cert: str) -> dict[str, str]:
    held = set() if cert in DENY_ALL else set(cert.split("+"))
    return {rpc: ("ALLOW" if held & allowed else "DENY") for rpc, allowed in t.items()}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("expected", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    if sys.argv[1] == "expected":
        t = table(sys.argv[2] if len(sys.argv) > 2 else None)
        print("rpc".ljust(20) + " ".join(r[:6].ljust(6) for r in ROLES))
        for rpc, allowed in t.items():
            print(rpc.ljust(20) + " ".join(("ALLOW" if r in allowed else "deny").ljust(6) for r in ROLES))
        return 0
    probe_dir = pathlib.Path(sys.argv[2])
    t = table(sys.argv[3] if len(sys.argv) > 3 else None)
    bad = 0
    cells = 0
    for f in sorted(probe_dir.glob("*.txt")):
        cert = f.stem
        want = expected(t, cert)
        got = {}
        for line in f.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("ALLOW", "DENY", "ERROR"):
                got[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
        row = []
        for rpc, w in want.items():
            cells += 1
            g, code = got.get(rpc, ("MISSING", ""))
            ok = g == w
            bad += not ok
            row.append(f"{rpc}={g}{'' if ok else f'(want {w}, {code})'}")
        mism = [x for x in row if "(want" in x]
        print(f"{cert:22s} {'OK' if not mism else 'MISMATCH ' + str(len(mism))}: " + (" ".join(mism) if mism else f"{sum(v == 'ALLOW' for v in want.values())} allow / {sum(v == 'DENY' for v in want.values())} deny"))
    print(f"authz_matrix: {cells} cells, {bad} mismatches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
