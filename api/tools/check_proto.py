#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static check of the node agent API (acceptance test T8).

Fails if any .proto under api/proto:
  * declares an RPC whose name suggests running arbitrary code
    (Exec, Shell, Command, Script, Eval, Spawn, ...);
  * declares a field that could carry a command, script, argument vector,
    file system path, binary or URL;
  * uses untyped containers (google.protobuf.Any / Struct / Value) or raw
    `bytes` fields outside the explicit allowlist;
  * declares an RPC without exactly one valid (<package>.access) option (the options of the file's own versioned
    package, e.g. foilbird.agent.v1alpha1.access);
  * declares an RPC without (<package>.roles), or with roles that do not
    fit its level: EMERGENCY only ROLE_OPERATOR; DESTRUCTIVE never
    ROLE_READER/ROLE_DIAG; ROLE_READER only on READ, ROLE_DIAG only on READ
    and DIAG; ROLE_OPERATOR on every RPC.

Discovery (ADR 0016): the file in the unversioned package <prefix>.agent holds exactly one service Discovery with one
RPC GetApiVersions and no options, imports nothing, and matches discovery.fields next to it (the frozen surface: no
field, reserved number or the service shape may change or go; a new field needs its line); its package is the versioned
package without the version. Versioned packages: <prefix>.agent.v<N>[alpha<M>|beta<M>].

With --mcp it prints the RPCs the gateway may publish as MCP tools, one
"<rpc> <level>" per line: the reference level filter. EMERGENCY is never
published (api/README.md, access levels); an RPC without exactly one valid level is not either.

Deliberately dependency-free (no protoc) so it runs anywhere in CI.
Usage: check_proto.py [--mcp] [proto_root]   (default: api/proto next to this file)
"""
import pathlib
import re
import sys

FORBIDDEN_RPC = re.compile(
    r"(exec|shell|command|cmd|script|eval|spawn|invoke|system|popen|run(?!diagnostic))",
    re.IGNORECASE)
FORBIDDEN_FIELD = re.compile(
    r"^(.*_)?(command|commands|cmd|cmdline|args|argv|arguments|script|scripts|shell|"
    r"exec|executable|path|paths|file|files|filename|binary|program|url|uri|"
    r"interpreter|entrypoint)(_.*)?$",
    re.IGNORECASE)
UNTYPED = re.compile(r"\bgoogle\.protobuf\.(Any|Struct|Value|ListValue)\b")
# "<file>:<Message>.<field>" allowed to be bytes (none yet; e.g. a CSR later).
BYTES_ALLOW: set[str] = set()
ROLES = {"ROLE_READER", "ROLE_DIAG", "ROLE_UPDATER", "ROLE_CONFIGURER",
         "ROLE_CONTROLLER", "ROLE_OPERATOR"}
VERSIONED = re.compile(r"^[a-z][a-z0-9_]*\.agent\.v[1-9][0-9]*((alpha|beta)[1-9][0-9]*)?$")
UNVERSIONED = re.compile(r"^[a-z][a-z0-9_]*\.agent$")


def package(src: str) -> str:
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", src, re.M)
    return m.group(1) if m else ""


def opt_re(pkg: str, name: str) -> str:
    """option (<pkg>.<name>) = VALUE; of the file's own package"""
    return r"option\s*\(\s*" + re.escape(pkg) + r"\." + name + r"\s*\)\s*=\s*(\w+)\s*;"
LEVELS = {"ACCESS_LEVEL_READ", "ACCESS_LEVEL_OPERATE",
          "ACCESS_LEVEL_DESTRUCTIVE", "ACCESS_LEVEL_EMERGENCY", "ACCESS_LEVEL_DIAG"}


# Levels the gateway may publish to MCP (DESTRUCTIVE only with human confirmation).
MCP_LEVELS = {"ACCESS_LEVEL_READ", "ACCESS_LEVEL_DIAG", "ACCESS_LEVEL_OPERATE",
              "ACCESS_LEVEL_DESTRUCTIVE"}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced braces")


def rpc_levels(src: str) -> list[tuple[str, list[str]]]:
    """(rpc name, access levels found in its body) for every rpc."""
    out, pkg = [], package(src)
    for m in re.finditer(r"\brpc\s+(\w+)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)\s*([;{])", src):
        if m.group(4) == ";":
            out.append((m.group(1), []))
            continue
        body = src[m.end(4) - 1: matching_brace(src, m.end(4) - 1) + 1]
        out.append((m.group(1), re.findall(opt_re(pkg, "access"), body)))
    return out


def rpc_roles(src: str) -> list[tuple[str, str, list[str]]]:
    """(rpc name, access level, roles) for every rpc with one access option."""
    out, pkg = [], package(src)
    for m in re.finditer(r"\brpc\s+(\w+)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)\s*([;{])", src):
        if m.group(4) == ";":
            continue
        body = src[m.end(4) - 1: matching_brace(src, m.end(4) - 1) + 1]
        lv = re.findall(opt_re(pkg, "access"), body)
        if len(lv) == 1:
            out.append((m.group(1), lv[0], re.findall(opt_re(pkg, "roles"), body)))
    return out


def role_errors(name: str, level: str, roles: list[str]) -> list[str]:
    errs = []
    if not roles:
        errs.append(f"rpc {name}: no (<package>.roles) option")
    for r in roles:
        if r not in ROLES:
            errs.append(f"rpc {name}: invalid role {r}")
    if len(set(roles)) != len(roles):
        errs.append(f"rpc {name}: duplicate role")
    rs = set(roles)
    if "ROLE_OPERATOR" not in rs:
        errs.append(f"rpc {name}: ROLE_OPERATOR missing (the operator may call every RPC)")
    if level == "ACCESS_LEVEL_EMERGENCY" and rs != {"ROLE_OPERATOR"}:
        errs.append(f"rpc {name}: EMERGENCY allows only ROLE_OPERATOR, has {sorted(rs)}")
    if level == "ACCESS_LEVEL_DESTRUCTIVE" and rs & {"ROLE_READER", "ROLE_DIAG"}:
        errs.append(f"rpc {name}: DESTRUCTIVE must not allow ROLE_READER/ROLE_DIAG")
    if "ROLE_READER" in rs and level != "ACCESS_LEVEL_READ":
        errs.append(f"rpc {name}: ROLE_READER only on READ RPCs")
    if "ROLE_DIAG" in rs and level not in ("ACCESS_LEVEL_READ", "ACCESS_LEVEL_DIAG"):
        errs.append(f"rpc {name}: ROLE_DIAG only on READ and DIAG RPCs")
    return errs


def mcp_rpcs(src: str) -> list[tuple[str, str]]:
    return [(n, lv[0]) for n, lv in rpc_levels(strip_comments(src))
            if len(lv) == 1 and lv[0] in MCP_LEVELS]


def fields_of(src: str) -> dict[str, dict[str, tuple[int, str, str]]]:
    """message -> field -> (number, label single|repeated, type)"""
    out = {}
    for mm in re.finditer(r"\bmessage\s+(\w+)\s*\{", src):
        body = src[mm.end() - 1: matching_brace(src, mm.end() - 1)]
        fs = {}
        for f in re.finditer(r"(?:^|[;{}])\s*(repeated\s+|optional\s+)?(map\s*<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*(\d+)", body):
            if f.group(2) in ("option", "reserved", "message", "enum", "oneof", "extend"):
                continue
            fs[f.group(3)] = (int(f.group(4)), "repeated" if (f.group(1) or "").strip() == "repeated" else "single", f.group(2))
        out[mm.group(1)] = fs
    return out


def reserved_of(src: str) -> set[tuple[str, str]]:
    out = set()
    for mm in re.finditer(r"\bmessage\s+(\w+)\s*\{", src):
        body = src[mm.end() - 1: matching_brace(src, mm.end() - 1)]
        for r in re.finditer(r"\breserved\s+([^;]+);", body):
            for x in r.group(1).split(","):
                out.add((mm.group(1), x.strip()))
    return out


def check_discovery(path: pathlib.Path, rel: str, src: str) -> list[str]:
    """Discovery (ADR 0016): shape, no options, no imports, and the frozen surface of discovery.fields."""
    errs: list[str] = []
    if re.search(r"^\s*import\s", src, re.M):
        errs.append(f"{rel}: Discovery imports nothing (a new API version must never touch it)")
    svcs = re.findall(r"\bservice\s+(\w+)\s*\{", src)
    if svcs != ["Discovery"]:
        errs.append(f"{rel}: exactly one service Discovery expected, found {svcs}")
    rpcs = list(re.finditer(r"\brpc\s+(\w+)\s*\(\s*([\w.]+)\s*\)\s*returns\s*\(\s*([\w.]+)\s*\)\s*([;{])", src))
    for m in rpcs:
        if m.group(4) == "{":
            body = src[m.end(4) - 1: matching_brace(src, m.end(4) - 1) + 1]
            if "option" in body:
                errs.append(f"{rel}: rpc {m.group(1)}: Discovery carries no options (any client of the CA)")
    lock = path.with_name("discovery.fields")
    if not lock.is_file():
        return errs + [f"{rel}: no discovery.fields next to it (the frozen surface)"]
    have_f, have_r = fields_of(src), reserved_of(src)
    want_f: set[tuple[str, str]] = set()
    for line in lock.read_text().splitlines():
        w = line.split()
        if not w or w[0].startswith("#"):
            continue
        if w[0] == "service" and len(w) == 5:
            if svcs[:1] != [w[1]] or not any(m.group(1) == w[2] and m.group(2) == w[3] and m.group(3) == w[4] for m in rpcs):
                errs.append(f"{rel}: frozen: service {w[1]} rpc {w[2]}({w[3]}) returns ({w[4]}) changed or gone")
            if len(rpcs) != 1:
                errs.append(f"{rel}: frozen: Discovery has exactly the RPCs of discovery.fields, found {len(rpcs)}")
        elif w[0] == "field" and len(w) == 6:
            msg, name, num, label, typ = w[1], w[2], int(w[3]), w[4], w[5]
            want_f.add((msg, name))
            got = have_f.get(msg, {}).get(name)
            if got != (num, label, typ):
                errs.append(f"{rel}: frozen: {msg}.{name} must stay = {num} {label} {typ}, found {got}")
        elif w[0] == "reserved" and len(w) == 3:
            if (w[1], w[2]) not in have_r:
                errs.append(f"{rel}: frozen: {w[1]} reserved {w[2]} removed")
        else:
            errs.append(f"{lock.name}: unreadable line: {line}")
    for msg, fs in have_f.items():
        for name in fs:
            if (msg, name) not in want_f:
                errs.append(f"{rel}: {msg}.{name}: a new Discovery field needs its line in discovery.fields")
    return errs


def check_file(path: pathlib.Path, rel: str) -> list[str]:
    errs: list[str] = []
    src = strip_comments(path.read_text())
    pkg = package(src)

    if UNTYPED.search(src):
        errs.append(f"{rel}: untyped google.protobuf container is not allowed")
    if UNVERSIONED.match(pkg):
        errs += check_discovery(path, rel, src)
    elif re.search(r"\bservice\s", src) and not VERSIONED.match(pkg):
        errs.append(f"{rel}: package {pkg!r}: a service lives in <prefix>.agent.v<N>[alpha<M>|beta<M>] or is Discovery in <prefix>.agent")

    # RPCs and their options (Discovery: none, checked above).
    for m in re.finditer(r"\brpc\s+(\w+)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)\s*([;{])", src):
        name = m.group(1)
        if FORBIDDEN_RPC.search(name):
            errs.append(f"{rel}: rpc {name}: name suggests arbitrary execution")
        if UNVERSIONED.match(pkg):
            continue
        if m.group(4) == ";":
            errs.append(f"{rel}: rpc {name}: missing ({pkg}.access) option")
            continue
        body = src[m.end(4) - 1: matching_brace(src, m.end(4) - 1) + 1]
        levels = re.findall(opt_re(pkg, "access"), body)
        if len(levels) != 1:
            errs.append(f"{rel}: rpc {name}: expected exactly one access option, found {len(levels)}")
        elif levels[0] not in LEVELS:
            errs.append(f"{rel}: rpc {name}: invalid access level {levels[0]}")
        else:
            errs += [f"{rel}: {e}" for e in role_errors(name, levels[0], re.findall(opt_re(pkg, "roles"), body))]

    # Fields (message bodies, including oneofs and maps).
    for mm in re.finditer(r"\bmessage\s+(\w+)\s*\{", src):
        msg = mm.group(1)
        body = src[mm.end() - 1: matching_brace(src, mm.end() - 1)]
        for f in re.finditer(
                r"(?:^|[;{}])\s*(?:repeated\s+|optional\s+)?"
                r"(map\s*<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*\d+", body):
            ftype, fname = f.group(1), f.group(2)
            if ftype in ("option", "reserved", "message", "enum", "oneof", "extend"):
                continue
            if FORBIDDEN_FIELD.match(fname):
                errs.append(f"{rel}: {msg}.{fname}: field name suggests command/path/script")
            if ftype == "bytes" and f"{rel}:{msg}.{fname}" not in BYTES_ALLOW:
                errs.append(f"{rel}: {msg}.{fname}: bytes field not in allowlist")
    return errs


def main() -> int:
    argv = sys.argv[1:]
    mcp = "--mcp" in argv
    roles = "--roles" in argv
    argv = [a for a in argv if a not in ("--mcp", "--roles")]
    root = pathlib.Path(argv[0]) if argv else \
        pathlib.Path(__file__).resolve().parent.parent / "proto"
    files = sorted(root.rglob("*.proto"))
    if roles:
        for p in files:
            for name, level, rs in rpc_roles(strip_comments(p.read_text())):
                print(name, level, ",".join(rs))
        return 0
    if mcp:
        for p in files:
            for name, level in mcp_rpcs(p.read_text()):
                print(name, level)
        return 0
    if not files:
        print(f"check_proto: no .proto files under {root}", file=sys.stderr)
        return 2
    errs: list[str] = []
    rpcs = 0
    pkgs = {}
    for p in files:
        rel = str(p.relative_to(root))
        errs += check_file(p, rel)
        src = strip_comments(p.read_text())
        rpcs += len(re.findall(r"\brpc\s+\w+", src))
        if re.search(r"\bservice\s", src):
            pkgs[rel] = package(src)
    # Discovery is the versioned package without its version (a rename of the prefix moves both together)
    disc = sorted({p for p in pkgs.values() if UNVERSIONED.match(p)})
    vers = sorted({p for p in pkgs.values() if VERSIONED.match(p)})
    if vers and disc != sorted({v.rsplit(".", 1)[0] for v in vers}):
        errs.append(f"Discovery package {disc} must be the API package without its version: {vers}")
    for e in errs:
        print(e, file=sys.stderr)
    print(f"check_proto: {len(files)} files, {rpcs} rpcs, {len(errs)} errors")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
