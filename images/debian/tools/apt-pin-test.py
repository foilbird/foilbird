#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Refusal probes of apt-pin.py's chain and lock checks, against a cache that `apt-pin.py fetch` filled and verified.

  apt-pin-test.py --conf F [--conf F]... --cache DIR [--sha1-key FILE]

Each probe builds a modified copy of the cache in a temporary directory (unchanged files are symlinks) and runs the
same verify_set() the build uses. For EVERY set of the given set files (nvidia-driver, nvidia-container-toolkit, k8s):
  P0 the unchanged copy passes (positive)
  N1 one byte of a pinned .deb changed in the cache
  N2 a .deb replaced by another file, its Packages stanza and the index hash in InRelease rewritten to match
     (correct sha256 everywhere, original signature kept -> no longer valid)
  N3 as N2, InRelease without any signature
  N4 as N2, InRelease re-signed by a key that is not the trust anchor, that key given as the keyring
  N5 as N4, that key also planted where the anchor's key material comes from (the keyring .deb, or the key file)
  N6 as N2, forged hash lines appended after the (intact) signature block
  N8 the lock disagrees: one line with another sha256 (the cached file is intact and its chain valid)
  N9 the lock is incomplete or stale: one line removed; one line for a file the set does not have
Once:
  N7 a SHA1-bound key (e.g. NVIDIA's debian12 cuda-archive-keyring.gpg) as trust anchor: refused by the key check
Exit 0 only if every positive probe passes and every negative probe is refused; a set whose unchanged cache does not pass
counts as a failed probe, and a run with no probe at all fails.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("apt_pin", os.path.join(here, "apt-pin.py"))
ap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ap)


def h(b, alg="sha256"):
    return hashlib.new(alg, b).hexdigest()


def mirror(src_cache, dst_cache):
    for root, _, files in os.walk(src_cache):
        out = os.path.join(dst_cache, os.path.relpath(root, src_cache))
        os.makedirs(out, exist_ok=True)
        for f in files:
            os.symlink(os.path.join(root, f), os.path.join(out, f))


def write(path, data):
    if os.path.lexists(path):
        os.remove(path)
    open(path, "wb").write(data)


def pack(name, text):
    b = text.encode()
    return gzip.compress(b, mtime=0) if name.endswith(".gz") else lzma.compress(b) if name.endswith(".xz") else b


def unpack(name, raw):
    return (gzip.decompress(raw) if name.endswith(".gz") else lzma.decompress(raw) if name.endswith(".xz") else raw).decode()


def substitute(rd, iname, filename, new_bytes):
    """Replace a .deb and make the index and the InRelease hash lists agree with it (signature left as it was)."""
    write(os.path.join(rd, filename), new_bytes)
    text = unpack(iname, open(os.path.join(rd, iname), "rb").read())
    stanzas = text.split("\n\n")
    for i, s in enumerate(stanzas):
        if re.search(r"^Filename: (\./)?%s$" % re.escape(filename), s, re.M):
            s = re.sub(r"^SHA256: .*$", "SHA256: " + h(new_bytes), s, flags=re.M)
            s = re.sub(r"^SHA512: .*$", "SHA512: " + h(new_bytes, "sha512"), s, flags=re.M)
            s = re.sub(r"^Size: .*$", "Size: %d" % len(new_bytes), s, flags=re.M)
            stanzas[i] = s
    pg = pack(iname, "\n\n".join(stanzas))
    write(os.path.join(rd, iname), pg)
    ir = open(os.path.join(rd, "InRelease"), "rb").read().decode()
    for alg, n in (("sha256", 64), ("sha512", 128)):
        ir = re.sub(r"^ [0-9a-f]{%d}(\s+)\d+(\s+)(\./)?%s$" % (n, re.escape(iname)),
                    lambda m: " %s%s%d%s%s" % (h(pg, alg), m.group(1), len(pg), m.group(2), iname), ir, flags=re.M)
    write(os.path.join(rd, "InRelease"), ir.encode())
    return ir


def signed_body(ir):
    """The cleartext body of an InRelease (undoing dash-escaping)."""
    m = re.search(r"-----BEGIN PGP SIGNED MESSAGE-----\n(?:[^\n]+\n)*\n(.*?)\n-----BEGIN PGP SIGNATURE-----", ir, re.S)
    return "\n".join(l[2:] if l.startswith("- ") else l for l in m.group(1).split("\n")) + "\n"


def attacker_key(home):
    os.makedirs(home, mode=0o700)
    # loopback + empty passphrase: no pinentry; gpg-agent must be installed (Debian: package gpg-agent)
    subprocess.run(["gpg", "--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
                    "probe attacker <probe@example.invalid>", "rsa3072", "sign", "never"], check=True, capture_output=True)
    kr = os.path.join(home, "attacker.gpg")
    subprocess.run(["gpg", "--batch", "--homedir", home, "--export", "--output", kr], check=True)
    return kr


def resign(rd, ir, home):
    p = os.path.join(rd, "InRelease.body")
    open(p, "w").write(signed_body(ir))
    out = os.path.join(rd, "InRelease.new")
    subprocess.run(["gpg", "--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", "",
                    "--digest-algo", "SHA256", "--clearsign", "--output", out, p],
                   check=True, capture_output=True)
    os.remove(os.path.join(rd, "InRelease"))
    os.rename(out, os.path.join(rd, "InRelease"))
    os.remove(p)


def plant_key(s, cache, rd, iname, keyring):
    """Put another key where the anchor's key material comes from: into the cached keyring .deb (Packages and InRelease
    made to agree), or over the cached key file."""
    kind = s.anchor["key"][0]
    if kind == "url":
        write(ap.cache_path(cache, s.anchor["key"][1]), open(keyring, "rb").read())
        return
    t = tempfile.mkdtemp()
    deb = s.anchor["key"][1]
    subprocess.run(["dpkg-deb", "-R", os.path.join(rd, deb), t], check=True)
    shutil.copyfile(keyring, os.path.join(t, s.anchor["key"][2]))
    out = t + ".deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "-b", t, out], check=True, capture_output=True)
    substitute(rd, iname, deb, open(out, "rb").read())


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--conf", action="append", required=True)
    a.add_argument("--cache", required=True)
    a.add_argument("--sha1-key", help="a SHA1-bound key for N7 (e.g. NVIDIA's debian12 cuda-archive-keyring.gpg)")
    o = a.parse_args()
    cache = os.path.abspath(o.cache)
    results = []

    def report(name, ok, expect_ok, msg):
        results.append(ok)
        print("%-24s %-4s expected=%-7s %s" % (name, "PASS" if ok else "FAIL", "pass" if expect_ok else "refused", msg), flush=True)

    try:
        confs = ap.load_conf(o.conf)
    except ap.ChainError as e:
        report("setup", False, True, "set files REFUSED: %s" % e)
        confs = []
    for _, sets, lock in confs:
        for s in sets:
            # the probes start from a cache that passes the check; if it does not, that is a failed probe, not a skip
            try:
                prov, _, iname, lockable = ap.verify_set(s, cache, lock)
            except ap.ChainError as e:
                report("%s P0" % s.name, False, True, "unchanged cache REFUSED, no probe of this set ran: %s" % e)
                continue
            debs = [e for e in prov["files"] if e["role"] != "keyring"]
            victim = debs[0]["filename"]
            other = next((e["filename"] for e in prov["files"] if e["filename"] != victim), None)

            def probe(name, expect_ok, build=None, lk=lock):
                t = tempfile.mkdtemp(prefix="aptpin-%s-%s-" % (s.name, name))
                c = os.path.join(t, "cache")
                mirror(cache, c)
                rd = ap.cache_path(c, s.repo)
                try:
                    kr = build(c, rd, t) if build else None
                except (subprocess.CalledProcessError, OSError) as e:
                    # the probe could not be set up: a failed probe, never a pass (and the other probes still run)
                    err = (getattr(e, "stderr", b"") or b"").decode(errors="replace").strip().splitlines()[-1:] or [""]
                    report("%s %s" % (s.name, name), False, expect_ok, "PROBE NOT SET UP: %s %s" % (e, err[0]))
                    shutil.rmtree(t)
                    return
                try:
                    ap.verify_set(s, c, lk, kr)
                    got, msg = True, "passed"
                except ap.ChainError as e:
                    got, msg = False, "REFUSED: %s" % e
                report("%s %s" % (s.name, name), got == expect_ok, expect_ok, msg)
                shutil.rmtree(t)

            def other_bytes(rd):
                if other:
                    return open(os.path.join(rd, other), "rb").read()
                b = bytearray(open(os.path.join(rd, victim), "rb").read())  # a set of one file: a changed copy of it
                b[-1] ^= 0x01
                return bytes(b)

            def n1(c, rd, t):
                b = bytearray(open(os.path.join(rd, victim), "rb").read())
                b[len(b) // 2] ^= 0x01
                write(os.path.join(rd, victim), bytes(b))

            def n2(c, rd, t):
                substitute(rd, iname, victim, other_bytes(rd))

            def n3(c, rd, t):
                ir = substitute(rd, iname, victim, other_bytes(rd))
                write(os.path.join(rd, "InRelease"), signed_body(ir).encode())

            def n4(c, rd, t):
                home = os.path.join(t, "gnupg")
                kr = attacker_key(home)
                resign(rd, substitute(rd, iname, victim, other_bytes(rd)), home)
                return kr

            def n5(c, rd, t):
                home = os.path.join(t, "gnupg")
                kr = attacker_key(home)
                plant_key(s, c, rd, iname, kr)
                resign(rd, substitute(rd, iname, victim, other_bytes(rd)), home)
                return None

            def n6(c, rd, t):
                orig = open(os.path.join(rd, "InRelease"), "rb").read().decode()
                substitute(rd, iname, victim, other_bytes(rd))
                pg = open(os.path.join(rd, iname), "rb").read()
                write(os.path.join(rd, "InRelease"), (orig + "SHA256:\n %s %d %s\nSHA512:\n %s %d %s\n" % (
                    h(pg), len(pg), iname, h(pg, "sha512"), len(pg), iname)).encode())

            key = ("apt", s.name)
            url0 = sorted(lock[key])[0]
            l8 = copy.deepcopy(lock)
            l8[key][url0] = ("0" * 64, l8[key][url0][1])
            l9a = copy.deepcopy(lock)
            del l9a[key][url0]
            l9b = copy.deepcopy(lock)
            l9b[key][s.repo + "/pool/not-in-the-set_1_amd64.deb"] = ("1" * 64, 1)

            probe("P0", True)
            probe("N1", False, n1)
            probe("N2", False, n2)
            probe("N3", False, n3)
            probe("N4", False, n4)
            probe("N5", False, n5)
            probe("N6", False, n6)
            probe("N8", False, lk=l8)
            probe("N9-missing", False, lk=l9a)
            probe("N9-stale", False, lk=l9b)

    if o.sha1_key:
        fpr = [l.split(":")[9] for l in ap.gpg(["--with-colons", "--show-keys", o.sha1_key]).stdout.decode().splitlines()
               if l.startswith("fpr:")][0]
        probs = ap.check_key(o.sha1_key, fpr)
        report("N7", any("SHA1" in p for p in probs), False, "key %s: %s" % (fpr, "; ".join(probs) or "accepted"))
    print("probes: %d/%d as expected" % (sum(results), len(results)))
    if not results:
        print("probes: none ran: FAIL (an empty probe run is a failure, never a pass)")
    sys.exit(0 if results and all(results) else 1)


if __name__ == "__main__":
    main()
