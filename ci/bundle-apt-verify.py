#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The apt chain of an input bundle (docs/ci-gitlab.md), checked against the tree, never against the bundle itself.

  ci/bundle-apt-verify.py --bundle DIR --tree DIR -- SQV...

SQV... is the sqv to run, a command after "--" (e.g. the restored tools tree's sqv through its own loader, whose
options start with "--"; or "sqv" of the pinned tools container), not the host's. The bundle
carries mkosi's package cache (pkgcache/cache/apt/archives/*.deb) and the repository metadata mkosi keeps in its
CacheDirectory (pkgcache/mkosi-cache/<key>.metadata.cache/lib/apt/lists: *_InRelease and *_Packages). Refused unless:

  1. the Debian archive keyring: images/debian/debian-archive-keyring.sha256 of the tree names the snapshot of the tree's
     Snapshot= and the sha256 of the keyring .deb; that .deb is in the bundle with that sha256; its keyring is the only
     trust anchor of the snapshot.debian.org lists
  2. every InRelease: verified by sqv against its anchor (Debian lists: that keyring; the apt-pin sandbox lists
     _srv_apt-pin_<set>_: the set's pinned fingerprint, key material from the bundle's apt-pin cache, apt-pin.py's checks)
     and only the text sqv returns is used; signature digests not weak
  3. every Packages list: named in the signed text of its InRelease (uncompressed path), sha256 and size equal; no
     Packages without its InRelease, no InRelease without a binary-amd64 Packages
  4. every .deb: its Package/Version/Architecture (from the file name, %3a = ':') has a stanza in a verified Packages and
     the .deb's sha256 is that stanza's; no .deb without a stanza

Valid-Until is not checked: mkosi v26 runs apt with Acquire::Check-Valid-Until=false for every source (docs/ci-gitlab.md).
"""
import argparse, hashlib, importlib.util, io, lzma, os, re, shutil, subprocess, sys, tarfile, tempfile

top = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("aptpin", os.path.join(top, "images/debian/tools/apt-pin.py"))
aptpin = importlib.util.module_from_spec(spec); spec.loader.exec_module(aptpin)


class Refused(Exception):
    pass


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def deb_member(deb, path):
    """One file of a .deb's data.tar.* (ar archive parsed here; no dpkg-deb of the host)."""
    raw = open(deb, "rb").read()
    if raw[:8] != b"!<arch>\n":
        raise Refused("%s: not a .deb (ar)" % deb)
    off = 8
    while off + 60 <= len(raw):
        name = raw[off:off + 16].decode().strip().rstrip("/"); size = int(raw[off + 48:off + 58].decode().strip())
        data = raw[off + 60:off + 60 + size]; off += 60 + size + (size & 1)
        if name.startswith("data.tar"):
            if name.endswith(".xz"):
                data = lzma.decompress(data)
            elif name.endswith(".zst"):
                data = subprocess.run(["zstd", "-dc"], input=data, check=True, capture_output=True).stdout
            elif name != "data.tar":
                raise Refused("%s: %s not supported" % (deb, name))
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    if m.name.lstrip("./") == path.lstrip("./") and m.isfile():
                        return t.extractfile(m).read()
            raise Refused("%s: no %s in its data" % (deb, path))
    raise Refused("%s: no data.tar member" % deb)


def stanzas(path):
    out = {}
    for b in open(path, "rb").read().decode().split("\n\n"):
        r = dict(re.findall(r"^([\w-]+): (.*)$", b, re.M))
        if r.get("Package"):
            out[(r["Package"], r.get("Version", ""), r.get("Architecture", ""))] = r
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True); ap.add_argument("--tree", required=True)
    ap.add_argument("sqv", nargs=argparse.REMAINDER, help="-- then the sqv command")
    a = ap.parse_args()
    a.sqv = a.sqv[1:] if a.sqv[:1] == ["--"] else a.sqv
    if not a.sqv:
        ap.error("the sqv command after --")
    B, T = a.bundle, a.tree
    # the program by its absolute path BEFORE the wrapper below goes first in PATH: a bare "sqv" in the wrapper would
    # find the wrapper itself and exec it forever (no output, no exit: ci/offline-try-3 hung there for 4 h 42 min)
    exe = shutil.which(a.sqv[0])
    if exe is None:
        raise Refused("sqv %s not found" % a.sqv[0])
    a.sqv[0] = os.path.abspath(exe)   # not realpath: the tools tree's ld-linux may be an absolute symlink (to the host's)
    # sqv of the tools tree for every signature (aptpin.verify_inrelease calls "sqv": a wrapper earlier in PATH)
    r = subprocess.run(a.sqv + ["--version"], capture_output=True, text=True)
    if r.returncode != 0:
        raise Refused("sqv %s does not run: %s" % (a.sqv, r.stderr.strip()[:200]))
    g = subprocess.run(["gpg", "--version"], capture_output=True, text=True).stdout.splitlines()[:1]
    print("apt-verify: gpg %s (packet listing and key shape only; every signature is checked by sqv)" % (g[0] if g else "?"))
    print("apt-verify: sqv %s (%s)" % (" ".join(a.sqv), r.stdout.strip().splitlines()[0] if r.stdout.strip() else "?"))
    # the sqv wrapper and the keyrings live in a temporary directory: removed on every exit (pass, refusal, error),
    # else one /tmp/apt-verify.* with an executable bin/sqv stays per run (chkrootkit: "Linux.Xor.DDoS", stand 23.11)
    tmp = tempfile.mkdtemp(prefix="apt-verify.")
    try:
        verify(a, B, T, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verify(a, B, T, tmp):
    wrap = os.path.join(tmp, "bin"); os.makedirs(wrap)
    with open(os.path.join(wrap, "sqv"), "w") as f:
        f.write("#!/bin/sh\nexec %s \"$@\"\n" % " ".join("'%s'" % x for x in a.sqv))
    os.chmod(os.path.join(wrap, "sqv"), 0o755)
    os.environ["PATH"] = wrap + ":" + os.environ["PATH"]

    arch = os.path.join(B, "pkgcache/cache/apt/archives")
    meta = [d for d in sorted(os.listdir(os.path.join(B, "pkgcache/mkosi-cache"))) if d.endswith(".metadata.cache")]
    if len(meta) != 1:
        raise Refused("pkgcache/mkosi-cache: %d metadata caches, expected exactly one: %s" % (len(meta), meta))
    lists = os.path.join(B, "pkgcache/mkosi-cache", meta[0], "lib/apt/lists")

    # 1. the Debian keyring, pinned in the tree to the tree's snapshot
    pin = dict(l.split(None, 1) for l in open(os.path.join(T, "images/debian/debian-archive-keyring.sha256")).read().splitlines() if l and not l.startswith("#"))
    snap = subprocess.run(["sh", os.path.join(T, "images/debian/tools/snapshot"), "check"], capture_output=True, text=True, check=True).stdout.strip()
    if pin.get("snapshot") != snap:
        raise Refused("Snapshot= of the tree is %s, the keyring pin is for %s: the pin must change with the snapshot" % (snap, pin.get("snapshot")))
    want, debname = pin["sha256"].split()
    deb = os.path.join(arch, debname)
    if not os.path.isfile(deb):
        raise Refused("keyring %s not in the bundle" % debname)
    if sha256(deb) != want:
        raise Refused("keyring %s: sha256 differs from the tree's pin" % debname)
    kr = os.path.join(tmp, "debian.pgp")
    for name in ("usr/share/keyrings/debian-archive-keyring.pgp", "usr/share/keyrings/debian-archive-keyring.gpg"):
        try:
            open(kr, "wb").write(deb_member(deb, name)); break
        except Refused:
            continue
    else:
        raise Refused("keyring %s: no usr/share/keyrings/debian-archive-keyring.{pgp,gpg}" % debname)
    print("apt-verify: Debian keyring %s sha256 %s (pin of snapshot %s)" % (debname, want, snap))

    # apt-pin sets: anchors from the tree, key material from the bundle's apt-pin cache
    confs = [os.path.join(T, "images/debian/apt-pin.conf"), os.path.join(T, "profiles/k8s-worker/apt-pin.conf")]
    sets = {s.name: s for _, ss, _ in aptpin.load_conf(confs) for s in ss}

    files = sorted(os.listdir(lists))
    irs = [f for f in files if f.endswith("_InRelease")]
    pk = [f for f in files if f.endswith("_Packages")]
    verified = {}
    for ir in irs:
        pre = ir[:-len("InRelease")]
        if ir.startswith("snapshot.debian.org_"):
            key, who = kr, "Debian keyring"
        else:
            m = re.match(r"^_srv_apt-pin_([a-z0-9-]+)_$", pre)
            if not m or m.group(1) not in sets:
                raise Refused("%s: no trust anchor in the tree for this list" % ir)
            s = sets[m.group(1)]
            key = aptpin.key_file(s, os.path.join(B, "apt-cache"), tmp)
            probs = aptpin.check_key(key, s.anchor["fingerprint"])
            if probs:
                raise Refused("%s: anchor of [%s] refused: %s" % (ir, s.name, "; ".join(probs)))
            who = "apt-pin [%s] %s" % (s.name, s.anchor["fingerprint"])
        try:
            signed, dig = aptpin.verify_inrelease(os.path.join(lists, ir), key)
        except aptpin.ChainError as e:
            raise Refused("%s: %s" % (ir, e))
        verified[pre] = aptpin.parse_release(signed)[1]
        print("apt-verify: %s good (%s; digests %s)" % (ir, who, ",".join(sorted(set(map(str, dig))))))

    # 3. every Packages under a verified InRelease, by its signed sha256
    idx = {}
    for p in pk:
        pre = next((x for x in verified if p.startswith(x)), None)
        if pre is None:
            raise Refused("%s: no verified InRelease for this Packages" % p)
        path = p[len(pre):].replace("_", "/")
        if path not in verified[pre]:
            raise Refused("%s: %s is not in the signed text of its InRelease" % (p, path))
        alg, h, size = verified[pre][path]
        f = os.path.join(lists, p)
        if os.path.getsize(f) != size or hashlib.new(alg, open(f, "rb").read()).hexdigest() != h:
            raise Refused("%s: %s/size differs from its InRelease" % (p, alg))
        idx.update(stanzas(f))
    for pre in verified:
        if not any(p.startswith(pre) and (p.endswith("binary-amd64_Packages") or p == pre + "Packages") for p in pk):
            raise Refused("%sInRelease: no Packages of it in the bundle" % pre)
    print("apt-verify: %d Packages lists good under %d InRelease, %d stanzas" % (len(pk), len(irs), len(idx)))

    # 4. every .deb by its stanza
    n = 0
    for d in sorted(os.listdir(arch)):
        if not d.endswith(".deb"):
            continue
        m = re.match(r"^([^_]+)_([^_]+)_([^_]+)\.deb$", d)
        if not m:
            raise Refused("%s: not a <package>_<version>_<arch>.deb name" % d)
        k = (m.group(1), m.group(2).replace("%3a", ":"), m.group(3))
        r = idx.get(k)
        if r is None:
            raise Refused("%s: no stanza %s in a verified Packages (an orphan .deb)" % (d, k))
        alg, h = aptpin.stanza_hash(r)
        if hashlib.new(alg, open(os.path.join(arch, d), "rb").read()).hexdigest() != h:
            raise Refused("%s: %s differs from its Packages stanza" % (d, alg))
        n += 1
    print("apt-verify: %d .deb good against their Packages stanzas" % n)
    print("APT-VERIFY PASS")


if __name__ == "__main__":
    try:
        main()
    except (Refused, aptpin.ChainError, OSError, subprocess.CalledProcessError) as e:
        print("APT-VERIFY FAIL: %s" % e); sys.exit(1)
