#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Third-party apt inputs of an image build (NVIDIA driver, NVIDIA container toolkit, pkgs.k8s.io): a local cache of each
pinned set, ONE verification of its signed chain, and a lock file that pins every file a second, independent way.

The cache is not a second source of trust: whatever a build uses is checked by the same code, whether the files came from
the network a second ago or have been sitting in the cache for a month. There is no option to skip or weaken a check.

  fetch    --conf F [--conf F]... --cache DIR    download what is missing (retries with exponential back-off on transient
                                                 errors, resumes partial files), then `verify`
  verify   --conf F [--conf F]... --cache DIR    check the chain and the lock of every file of every set; print provenance
  prepare  --conf F [--conf F]... --cache DIR --out-dir MKOSI_DIR [--source-only SET]...
                                                 `verify`, then write the build inputs (all gitignored, see prepare());
                                                 a --source-only set is verified in full but installs nothing: no apt
                                                 source in the sandbox, no package in pinned.conf, its source-dir and
                                                 provenance are written as usual (k8s-worker cp: NVIDIA modules from
                                                 nvsrc/, no NVIDIA userspace)
  lock     --conf F [--conf F]... --cache DIR    check the chain only and REWRITE the `apt` lines of each lock file from
                                                 it: the maintainer's step after changing a pin; the diff is reviewed

Set file (<name>.conf, INI; one section per set; the lock is <name>.lock next to it):
  [<set>]
  repo       = https URL of a flat apt repository (InRelease at its root); its trust anchor must be in TRUSTED below
  packages   = pkg=ver ...                 installed, exactly these versions
  closure    = root ... + version = V      installed: the closure of the roots over dependencies pinned to "= V"
  source     = pkg[=ver] ...               fetched and verified, never installed (copied to source-dir for mkosi.build)
  source-dir = DIR (relative to --out-dir) provenance = FILE (relative to --out-dir): this set's provenance, extra copy
  license    = SPDX id recorded for packages that ship no copyright file (SBOM)

Chain, checked for every file:
  file  <- its Packages stanza (Filename, Size, SHA256 or SHA512)
        <- the Packages index (Packages.gz / .xz / plain), whose hash is in the SIGNED text of InRelease (only the text
           sqv returns as verified is parsed)
        <- InRelease signature (sqv, the verifier of Debian 13's apt; signature digest not MD5/SHA1/RIPEMD160)
        <- trust anchor: the key fingerprint pinned in TRUSTED for that repository; the key material comes from the
           anchor's source (a keyring .deb of the same repository, itself then checked against Packages, or a key URL);
           every self-signature and binding of the key must use a digest other than MD5/SHA1/RIPEMD160, so a SHA1-bound
           key is refused even with the right fingerprint
Lock, checked for every file after the chain: URL, size and sha256 equal to its `apt <set> <sha256> <size> <url>` line;
a file without a line, a line without a file, any difference -> refused. The chain proves where a file comes from, the
lock that it is the same file as in the build that wrote the lock (a republished repository is noticed, not followed).

Cache layout: DIR/<host>/<path of the URL> (InRelease, the index, each Filename, key files).
"""
import argparse
import calendar
import configparser
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# trust anchors: repository URL -> the only key fingerprint accepted for it and where the key material comes from.
# A new key is a change of this table, never of a set file.
TRUSTED = {
    # NVIDIA CUDA repository for Debian 13 (driver branch 610+)
    "https://developer.download.nvidia.com/compute/cuda/repos/debian13/x86_64": {
        "fingerprint": "02182E60104FCDC26EAE1B8597A5D4CB8793F200",
        "key": ("deb", "cuda-keyring_1.1-1_all.deb", "./usr/share/keyrings/cuda-archive-keyring.gpg")},
    # NVIDIA container toolkit (libnvidia-container), stable channel
    "https://nvidia.github.io/libnvidia-container/stable/deb/amd64": {
        "fingerprint": "C95B321B61E88C1809C4F759DDCAE044F796ECB0",
        "key": ("url", "https://nvidia.github.io/libnvidia-container/gpgkey")},
    # Kubernetes community packages, v1.34 line
    "https://pkgs.k8s.io/core:/stable:/v1.34/deb": {
        "fingerprint": "DE15B14486CD377B9E876E1A234654DA9A296436",
        "key": ("url", "https://pkgs.k8s.io/core:/stable:/v1.34/deb/Release.key")},
}
WEAK_DIGESTS = {1: "MD5", 2: "SHA1", 3: "RIPEMD160"}  # RFC 4880 hash algorithm ids
DIGEST_NAMES = {**WEAK_DIGESTS, 8: "SHA256", 9: "SHA384", 10: "SHA512", 11: "SHA224"}
INDEXES = ("Packages.gz", "Packages.xz", "Packages")    # first one listed in the signed InRelease is used
SANDBOX_ROOT = "/srv/apt-pin"
SET_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class ChainError(Exception):
    pass


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------- set files and lock files
class PinSet:
    def __init__(self, name, sec, conf):
        if not SET_NAME.match(name):
            raise ChainError("%s: bad set name [%s]" % (conf, name))
        self.name, self.conf = name, conf
        self.repo = sec.get("repo", "").rstrip("/")
        if self.repo not in TRUSTED:
            raise ChainError("%s [%s]: no trust anchor for %s (known: %s)" % (conf, name, self.repo, ", ".join(TRUSTED)))
        self.version = sec.get("version") or None
        self.packages = self._pv(sec.get("packages", ""), "packages")
        self.closure = sec.get("closure", "").split()
        self.source = self._pv(sec.get("source", ""), "source")
        if self.closure and not self.version:
            raise ChainError("%s [%s]: closure needs version" % (conf, name))
        if not (self.packages or self.closure or self.source):
            raise ChainError("%s [%s]: nothing pinned" % (conf, name))
        self.source_dir = sec.get("source-dir") or None
        self.provenance = sec.get("provenance") or None
        if self.source and not self.source_dir:
            raise ChainError("%s [%s]: source needs source-dir" % (conf, name))
        self.license = sec.get("license") or None
        unknown = set(sec) - {"repo", "version", "packages", "closure", "source", "source-dir", "provenance", "license"}
        if unknown:
            raise ChainError("%s [%s]: unknown keys %s" % (conf, name, sorted(unknown)))

    def _pv(self, text, what):
        out = []
        for w in text.split():
            p, _, v = w.partition("=")
            v = v or self.version
            if not v:
                raise ChainError("%s [%s]: %s %s has no version" % (self.conf, self.name, what, p))
            out.append((p, v))
        return out

    @property
    def anchor(self):
        return TRUSTED[self.repo]


def lock_path(conf):
    return re.sub(r"\.conf$", "", conf) + ".lock"


# the work tree (images/debian/tools/ -> top): provenance names files relative to it, never by a build host's path
TOP = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))


def tree_rel(path):
    """path relative to the work tree, or its basename when it lies outside (the provenance must not hold host paths)."""
    p = os.path.realpath(path)
    return os.path.relpath(p, TOP) if p.startswith(TOP + os.sep) else os.path.basename(p)


def read_lock(path):
    """{(kind, set): {url: (sha256, size)}}. A missing lock file is an empty lock (every file is then refused)."""
    out = {}
    if not os.path.isfile(path):
        return out
    for n, line in enumerate(open(path), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        f = line.split()
        if len(f) != 5 or not re.fullmatch(r"[0-9a-f]{64}", f[2]) or not f[3].isdigit() or not f[4].startswith("https://"):
            raise ChainError("%s:%d: expected '<kind> <set> <sha256> <size> <https url>'" % (path, n))
        d = out.setdefault((f[0], f[1]), {})
        if f[4] in d:
            raise ChainError("%s:%d: %s listed twice" % (path, n, f[4]))
        d[f[4]] = (f[2], int(f[3]))
    return out


def load_conf(paths):
    """[(conf path, [PinSet], lock)] for the given set files; a set name may appear only once over all of them."""
    out, seen = [], set()
    for p in paths:
        cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",), comment_prefixes=("#",))
        if not cp.read(p):
            raise ChainError("%s: cannot read" % p)
        sets = [PinSet(n, cp[n], p) for n in cp.sections()]
        for s in sets:
            if s.name in seen:
                raise ChainError("set [%s] defined twice" % s.name)
            seen.add(s.name)
        lock = read_lock(lock_path(p))
        stale = [k[1] for k in lock if k[0] == "apt" and k[1] not in {s.name for s in sets}]
        if stale:
            raise ChainError("%s: apt lines for sets not in %s: %s" % (lock_path(p), p, ", ".join(sorted(stale))))
        out.append((p, sets, lock))
    return out


# ---------------------------------------------------------------- network (fetch only)
def download(url, dest, attempts=8, first_delay=2.0, timeout=60):
    """Download url to dest (atomically, via dest.part). Transient errors (timeouts, connection errors, HTTP 408/429/5xx,
    a stalled transfer) are retried with exponential back-off (2, 4, 8, ... s); a retry resumes the partial file with an
    HTTP Range request when the server allows it. Anything else fails at once. Nothing here is trusted: verify() checks."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".part"
    if os.path.exists(tmp):
        os.remove(tmp)
    delay = first_delay
    for n in range(1, attempts + 1):
        have = os.path.getsize(tmp) if os.path.exists(tmp) else 0
        mode = "wb"
        try:
            hdr = {"User-Agent": "foil-build"}
            if have:
                hdr["Range"] = "bytes=%d-" % have
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout) as r:
                mode = "ab" if (have and r.status == 206) else "wb"
                with open(tmp, mode) as f:
                    for chunk in iter(lambda: r.read(1 << 20), b""):
                        f.write(chunk)
            os.replace(tmp, dest)
            log("fetched %s (%d bytes, attempt %d%s)" % (url, os.path.getsize(dest), n, ", resumed" if mode == "ab" else ""))
            return
        except urllib.error.HTTPError as e:
            if e.code not in (408, 429) and e.code < 500:
                raise ChainError("%s: HTTP %d" % (url, e.code))
            err = "HTTP %d" % e.code
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            err = type(e).__name__ + ": " + str(getattr(e, "reason", e))
        if n == attempts:
            raise ChainError("%s: giving up after %d attempts (%s)" % (url, n, err))
        log("transient error on %s (%s, %d bytes so far), retry %d/%d in %.0f s" % (
            url, err, os.path.getsize(tmp) if os.path.exists(tmp) else 0, n, attempts - 1, delay))
        time.sleep(delay)
        delay *= 2


# ---------------------------------------------------------------- verification (network and cache alike)
def digest(path, alg="sha256"):
    h = hashlib.new(alg)
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cache_path(cache, url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.netloc or ".." in u.path.split("/"):
        raise ChainError("not a plain https URL: %s" % url)
    return os.path.join(cache, u.netloc, urllib.parse.unquote(u.path).strip("/"))


def gpg(args, data=None):
    with tempfile.TemporaryDirectory() as home:
        return subprocess.run(["gpg", "--batch", "--homedir", home] + args, input=data, capture_output=True)


def binary_key(src, dst):
    """Copy a key file to dst in binary form (sqv and apt's Signed-By take either; one form keeps the checks simple)."""
    data = open(src, "rb").read()
    if data.lstrip().startswith(b"-----BEGIN PGP"):
        r = gpg(["--dearmor"], data)
        if r.returncode != 0 or not r.stdout:
            raise ChainError("%s: not an OpenPGP key" % src)
        data = r.stdout
    open(dst, "wb").write(data)
    return dst


def signature_packets(path):
    """(issuer keyid, sigclass, digest algo) of every signature packet in an OpenPGP file: a key, or the signature
    block(s) of a cleartext-signed message (gpg does not list the packets of a cleartext message as a whole)."""
    data = open(path, "rb").read()
    if data.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----"):
        blocks = re.findall(rb"-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----\s*", data, re.S)
        out = "".join(gpg(["--list-packets"], b).stdout.decode(errors="replace") for b in blocks)
    else:
        out = gpg(["--list-packets", path]).stdout.decode(errors="replace")
    sigs = []
    for m in re.finditer(r"^:signature packet: algo \d+, keyid ([0-9A-F]+)\n(.*?)(?=^:|\Z)", out, re.M | re.S):
        c = re.search(r"sigclass (0x[0-9a-f]+)", m.group(2))
        d = re.search(r"^\s+digest algo (\d+)", m.group(2), re.M)
        sigs.append((m.group(1), c.group(1) if c else None, int(d.group(1)) if d else None))
    return sigs


def check_key(keyring, fingerprint):
    """Problems of a keyring as a trust anchor (empty list = acceptable): exactly one primary key, the pinned fingerprint,
    no self-signature or binding with a weak digest (a SHA1-bound key is refused). Certifications by other keys are not
    part of the binding and are ignored."""
    probs = []
    cols = gpg(["--with-colons", "--show-keys", keyring]).stdout.decode().splitlines()
    prim = [l.split(":")[9] for p, l in zip(cols, cols[1:]) if l.startswith("fpr:") and p.startswith("pub:")]
    own = {l.split(":")[9][-16:] for p, l in zip(cols, cols[1:]) if l.startswith("fpr:") and p[:4] in ("pub:", "sub:")}
    if prim != [fingerprint]:
        probs.append("primary key fingerprints %s, expected exactly [%s]" % (prim, fingerprint))
    allsigs = signature_packets(keyring)
    sigs = [s for s in allsigs if s[0] in own]
    # trust is ONLY the key's own self-signatures and bindings: a certification by another key (e.g. pkgs.k8s.io's uid,
    # certified by CF0B928CDED64F3B with SHA1) neither helps nor hurts; it is named in the log, never counted
    for k, c, d in sorted({x for x in allsigs if x[0] not in own}, key=str):
        log("foreign certification ignored: %s (issuer %s, class %s)" % (DIGEST_NAMES.get(d, "algo %s" % d), k, c))
    if not sigs:
        probs.append("no self-signatures found in the key")
    weak = sorted({"%s (class %s)" % (WEAK_DIGESTS.get(d, "unknown"), c) for _, c, d in sigs if d in WEAK_DIGESTS or d is None})
    if weak:
        probs.append("key self-signatures/bindings use weak digest(s) %s (SHA1-bound keys are not accepted)" % ", ".join(weak))
    return probs


def sqv_version():
    r = subprocess.run(["sqv", "--version"], capture_output=True, text=True)
    return (r.stdout or r.stderr).strip() or "unknown version"


def sqv_has_cleartext():
    r = subprocess.run(["sqv", "--help"], capture_output=True, text=True)
    return "--cleartext" in r.stdout + r.stderr


def verify_inrelease(inrelease, keyring):
    """sqv-verified text of InRelease (only that text is used afterwards) and the signature digest ids."""
    if shutil.which("sqv") is None:
        raise ChainError("sqv not found (Debian: package sqv); there is no fallback verifier")
    if not sqv_has_cleartext():
        raise ChainError("this sqv (%s) cannot verify a cleartext-signed InRelease (no --cleartext; Ubuntu 24.04 ships such "
                         "an old one): use Debian 13's sqv; there is no fallback verifier" % sqv_version())
    with tempfile.TemporaryDirectory() as t:
        out = os.path.join(t, "signed.txt")
        r = subprocess.run(["sqv", "--keyring", keyring, "--cleartext", "--output", out, inrelease], capture_output=True, text=True)
        if r.returncode != 0:
            raise ChainError("InRelease: signature not valid for the trusted key (sqv rc=%d: %s)" % (r.returncode, r.stderr.strip()[:300]))
        signed = open(out, "rb").read().decode()
    dig = [d for _, _, d in signature_packets(inrelease)]
    if not dig or any(d in WEAK_DIGESTS or d is None for d in dig):
        raise ChainError("InRelease: signature digest(s) %s not acceptable" % dig)
    return signed, dig


def parse_release(signed):
    """Fields and {path: (alg, hex, size)} of the signed Release text: SHA256 entries, SHA512 where there is no SHA256
    (libnvidia-container publishes SHA512 only). MD5Sum/SHA1 sections are never read."""
    fields = dict(re.findall(r"^([\w-]+): (.*)$", signed, re.M))
    sums = {}
    for alg, sect, n in (("sha512", "SHA512", 128), ("sha256", "SHA256", 64)):  # sha256 last: it wins
        sec = re.search(r"^%s:\n((?: .*\n?)+)" % sect, signed, re.M)
        if sec:
            for m in re.finditer(r"^ ([0-9a-f]{%d})\s+(\d+)\s+(\S+)$" % n, sec.group(1), re.M):
                sums[m.group(3).removeprefix("./")] = (alg, m.group(1), int(m.group(2)))
    return fields, sums


def stanza_hash(r):
    if r.get("SHA256"):
        return "sha256", r["SHA256"]
    if r.get("SHA512"):
        return "sha512", r["SHA512"]
    raise ChainError("Packages stanza %s %s has no SHA256/SHA512" % (r.get("Package"), r.get("Version")))


def closure(idx, roots, ver):
    seen, stack = set(), list(roots)
    while stack:
        p = stack.pop()
        if p in seen or (p, ver) not in idx:
            continue
        seen.add(p)
        deps = idx[(p, ver)].get("Depends", "") + "," + idx[(p, ver)].get("Pre-Depends", "")
        for d in re.split(r",\s*", deps):
            for alt in d.split("|"):
                m = re.match(r"\s*([\w.+-]+)(?::\w+)?\s*\(\s*=\s*([^)]+)\)", alt)
                if m and m.group(2).strip() == ver:
                    stack.append(m.group(1))
    missing = [r for r in roots if r not in seen]
    if missing:
        raise ChainError("not in the repository for %s: %s" % (ver, ", ".join(missing)))
    return sorted(seen)


def key_file(s, cache, tmp, override=None):
    """Binary keyring of the set's anchor, from the cache. For a 'deb' anchor the .deb is checked against Packages
    later like every other file (needed() lists it)."""
    if override:
        return binary_key(override, os.path.join(tmp, "override.gpg"))
    kind = s.anchor["key"][0]
    if kind == "url":
        src = cache_path(cache, s.anchor["key"][1])
        if not os.path.isfile(src):
            raise ChainError("[%s] key file %s missing in the cache" % (s.name, s.anchor["key"][1]))
        return binary_key(src, os.path.join(tmp, s.name + ".gpg"))
    deb = os.path.join(cache_path(cache, s.repo), s.anchor["key"][1])
    if not os.path.isfile(deb):
        raise ChainError("[%s] %s missing in the cache" % (s.name, s.anchor["key"][1]))
    data = subprocess.run(["dpkg-deb", "--fsys-tarfile", deb], check=True, capture_output=True).stdout
    out = subprocess.run(["tar", "-xO", s.anchor["key"][2]], input=data, check=True, capture_output=True).stdout
    p = os.path.join(tmp, s.name + ".raw")
    open(p, "wb").write(out)
    return binary_key(p, os.path.join(tmp, s.name + ".gpg"))


def load_index(s, cache, keyring):
    """Trust anchor -> InRelease -> Packages index. Returns (index, provenance, name of the index file)."""
    fpr = s.anchor["fingerprint"]
    probs = check_key(keyring, fpr)
    if probs:
        raise ChainError("[%s] trust anchor refused: %s" % (s.name, "; ".join(probs)))
    rd = cache_path(cache, s.repo)
    ir = os.path.join(rd, "InRelease")
    if not os.path.isfile(ir):
        raise ChainError("[%s] InRelease missing in %s" % (s.name, rd))
    signed, dig = verify_inrelease(ir, keyring)
    fields, sums = parse_release(signed)
    if "Valid-Until" in fields:
        vu = calendar.timegm(time.strptime(fields["Valid-Until"], "%a, %d %b %Y %H:%M:%S %Z"))
        if vu < time.time():
            raise ChainError("[%s] InRelease expired (Valid-Until %s)" % (s.name, fields["Valid-Until"]))
    name = next((n for n in INDEXES if n in sums), None)
    if not name:
        raise ChainError("[%s] signed InRelease lists none of %s" % (s.name, ", ".join(INDEXES)))
    alg, want, size = sums[name]
    p = os.path.join(rd, name)
    if not os.path.isfile(p) or os.path.getsize(p) != size or digest(p, alg) != want:
        raise ChainError("[%s] %s: %s/size does not match the signed InRelease" % (s.name, name, alg))
    raw = open(p, "rb").read()
    text = (gzip.decompress(raw) if name.endswith(".gz") else lzma.decompress(raw) if name.endswith(".xz") else raw).decode()
    recs = [dict(re.findall(r"^([\w-]+): (.*)$", b, re.M)) for b in text.split("\n\n") if b.strip()]
    idx = {(r["Package"], r["Version"]): r for r in recs if r.get("Architecture") in ("amd64", "all")}
    pin = ("o", fields["Origin"]) if fields.get("Origin") else ("l", fields["Label"]) if fields.get("Label") else None
    prov = {
        "set": s.name,
        "repository": s.repo,
        "key": {"fingerprint": fpr, "source": s.anchor["key"][1],
                "signature_digests": sorted({d for _, _, d in signature_packets(keyring) if d is not None}),
                "sha256": digest(keyring)},
        "inrelease": {"sha256": digest(ir), "date": fields.get("Date"), "valid_until": fields.get("Valid-Until"),
                      "origin": fields.get("Origin"), "label": fields.get("Label"),
                      "signature_digests": sorted(set(dig)),
                      "verifier": sqv_version()},
        "index": {"name": name, alg: want, "size": size},
        "pin": pin,
    }
    if name == "Packages.gz":  # the key earlier provenance files used
        prov["packages_gz"] = {alg: want, "size": size}
    return idx, prov, name


def needed(s, idx):
    """[(package, version, role)] of every .deb the set takes from the repository; role install|source|keyring."""
    out = []
    if s.closure:
        out += [(p, s.version, "install") for p in closure(idx, s.closure, s.version)]
    for p, v in s.packages:
        if (p, v) not in idx:
            have = sorted(v2 for (p2, v2) in idx if p2 == p)[-3:]
            raise ChainError("[%s] %s=%s not in the repository (have %s)" % (s.name, p, v, have))
        out.append((p, v, "install"))
    for p, v in s.source:
        if (p, v) not in idx:
            raise ChainError("[%s] source %s=%s not in the repository" % (s.name, p, v))
        out.append((p, v, "source"))
    if s.anchor["key"][0] == "deb":
        k = [kk for kk, r in idx.items() if r.get("Filename", "").removeprefix("./") == s.anchor["key"][1]]
        if len(k) != 1:
            raise ChainError("[%s] %s not listed exactly once in Packages" % (s.name, s.anchor["key"][1]))
        out.append(k[0] + ("keyring",))
    seen, uniq = set(), []
    for e in out:
        if e[:2] not in seen:
            seen.add(e[:2])
            uniq.append(e)
    return uniq


def check_lock(s, files, lock):
    """Every file of the set (chain-checked .debs and a URL key file) against the set's apt lines of the lock."""
    want = lock.get(("apt", s.name), {})
    have = {f["url"]: (f["sha256"], f["size"]) for f in files}
    probs = []
    for u in sorted(set(have) - set(want)):
        probs.append("not in the lock: %s" % u)
    for u in sorted(set(want) - set(have)):
        probs.append("in the lock but not in the set: %s" % u)
    for u in sorted(set(have) & set(want)):
        if have[u] != want[u]:
            probs.append("%s: sha256/size %s/%d, lock %s/%d" % (u, have[u][0][:16], have[u][1], want[u][0][:16], want[u][1]))
    if probs:
        raise ChainError("[%s] lock %s refused: %s" % (s.name, lock_path(s.conf), "; ".join(probs)))


def verify_set(s, cache, lock, keyring_override=None):
    """THE check of one set. Used by fetch (after downloading), verify, prepare and lock (lock=None: chain only, for
    rewriting the lock). Returns (provenance, binary keyring bytes, index name)."""
    with tempfile.TemporaryDirectory() as t:
        k = key_file(s, cache, t, keyring_override)
        idx, prov, iname = load_index(s, cache, k)
        keyring_bytes = open(k, "rb").read()
    rd = cache_path(cache, s.repo)
    files = []
    for p, v, role in needed(s, idx):
        r = idx[(p, v)]
        rel = r["Filename"].removeprefix("./")
        f = os.path.join(rd, rel)
        if not os.path.isfile(f):
            raise ChainError("[%s] %s missing in the cache" % (s.name, rel))
        alg, want = stanza_hash(r)
        if os.path.getsize(f) != int(r["Size"]) or digest(f, alg) != want:
            raise ChainError("[%s] %s: %s/size does not match its Packages stanza" % (s.name, rel, alg))
        files.append({"package": p, "version": v, "role": role, "filename": rel, "size": int(r["Size"]),
                      "sha256": digest(f), "url": s.repo + "/" + rel})
    lockable = list(files)
    if s.anchor["key"][0] == "url":
        kp = cache_path(cache, s.anchor["key"][1])
        lockable.append({"url": s.anchor["key"][1], "sha256": digest(kp), "size": os.path.getsize(kp)})
        prov["key"]["file_sha256"] = digest(kp)
    if lock is not None:
        check_lock(s, lockable, lock)
    prov.update({"version": s.version, "license": s.license, "files": files,
                 "lock": None if lock is None else tree_rel(lock_path(s.conf)),
                 "chain": "file <- Packages <- %s in signed InRelease <- sqv signature <- key %s" % (iname, s.anchor["fingerprint"])})
    return prov, keyring_bytes, iname, lockable


def fetch_set(s, cache, refresh=False):
    rd = cache_path(cache, s.repo)
    kind, ksrc = s.anchor["key"][:2]
    kp = cache_path(cache, ksrc) if kind == "url" else os.path.join(rd, ksrc)
    if refresh or not os.path.isfile(kp):
        download(ksrc if kind == "url" else s.repo + "/" + ksrc, kp)
    if refresh or not os.path.isfile(os.path.join(rd, "InRelease")):
        download(s.repo + "/InRelease", os.path.join(rd, "InRelease"))
    # the index is chosen from, and checked against, the SIGNED InRelease before it is read
    with tempfile.TemporaryDirectory() as t:
        k = key_file(s, cache, t)
        probs = check_key(k, s.anchor["fingerprint"])
        if probs:
            raise ChainError("[%s] trust anchor refused: %s" % (s.name, "; ".join(probs)))
        _, sums = parse_release(verify_inrelease(os.path.join(rd, "InRelease"), k)[0])
        name = next((n for n in INDEXES if n in sums), None)
        if name:
            alg, want, _ = sums[name]
            p = os.path.join(rd, name)
            if not os.path.isfile(p) or digest(p, alg) != want:
                download(s.repo + "/" + name, p)
        idx, _, _ = load_index(s, cache, k)
    for p, v, _ in needed(s, idx):
        r = idx[(p, v)]
        rel = r["Filename"].removeprefix("./")
        f = os.path.join(rd, rel)
        alg, want = stanza_hash(r)
        if not os.path.isfile(f) or digest(f, alg) != want:
            download(s.repo + "/" + rel, f)


def prepare(confs, cache, out_dir, source_only=()):
    """`verify` every set, then write into out_dir (the mkosi configuration directory, all gitignored):
       aptpin/                      mkosi SandboxTrees=: per set an apt source file:/srv/apt-pin/<set>/, its keyring and
                                    apt preferences (the repository may supply ONLY the pinned packages)
         srv/apt-pin/<set>/         the cached repository subset: the original signed InRelease and index and the pinned
                                    .debs; apt in the build verifies them again
       <source-dir>/                source packages (never installed) + origin.txt, for mkosi.build
       <provenance>                 the set's provenance (e.g. nvsrc/nvidia-inputs.json, copied into the image SBOM)
       apt-pin-inputs.json          provenance of every set
       pinned.conf                  mkosi include: SandboxTrees=<out_dir>/aptpin (absolute) + every installed package
                                    pinned to its version
    A set named in source_only gets no apt source and no package in pinned.conf (only its source-dir and provenance)."""
    sets = [(s, lock) for _, ss, lock in confs for s in ss]
    unknown = sorted(set(source_only) - {s.name for s, _ in sets})
    if unknown:
        raise ChainError("--source-only %s: no such set in %s" % (" ".join(unknown), " ".join(c for c, _, _ in confs)))
    provs = [(s,) + verify_set(s, cache, lock)[:3] for s, lock in sets]
    sbx = os.path.join(out_dir, "aptpin")
    shutil.rmtree(sbx, ignore_errors=True)
    for s, _ in sets:
        if s.source_dir:
            shutil.rmtree(os.path.join(out_dir, s.source_dir), ignore_errors=True)
    for d in ("etc/apt/keyrings", "etc/apt/sources.list.d", "etc/apt/preferences.d"):
        os.makedirs(os.path.join(sbx, d))
    installed = []
    for s, prov, keyring_bytes, iname in provs:
        rd = cache_path(cache, s.repo)
        if s.name in source_only:
            log("[%s] source only: %s and the provenance written, nothing installed" % (s.name, s.source_dir or "no source-dir"))
        else:
            srv = os.path.join(sbx, SANDBOX_ROOT.lstrip("/"), s.name)
            os.makedirs(srv)
            open(os.path.join(sbx, "etc/apt/keyrings/apt-pin-%s.gpg" % s.name), "wb").write(keyring_bytes)
            with open(os.path.join(sbx, "etc/apt/sources.list.d/apt-pin-%s.sources" % s.name), "w") as f:
                f.write("Types: deb\nURIs: file:%s/%s/\nSuites: /\nSigned-By: /etc/apt/keyrings/apt-pin-%s.gpg\n" % (SANDBOX_ROOT, s.name, s.name))
            inst = sorted({(e["package"], e["version"]) for e in prov["files"] if e["role"] == "install"})
            installed += inst
            # the repository may supply ONLY the pinned set: NVIDIA's also carries packages that Debian has (dkms, ...), and
            # apt would otherwise take a newer third-party build of those. Specific entries win (apt_preferences(5)).
            if not prov["pin"]:
                raise ChainError("[%s] InRelease has neither Origin nor Label: nothing to pin the repository by" % s.name)
            pin = "release %s=%s" % prov["pin"]
            with open(os.path.join(sbx, "etc/apt/preferences.d/apt-pin-%s.pref" % s.name), "w") as f:
                if inst:
                    f.write("Package: %s\nPin: %s\nPin-Priority: 500\n\n" % (" ".join(p for p, _ in inst), pin))
                f.write("Package: *\nPin: %s\nPin-Priority: -1\n" % pin)
            # the original signed metadata, unchanged: apt in the build re-verifies InRelease -> index -> .deb itself
            for n in ("InRelease", iname):
                shutil.copyfile(os.path.join(rd, n), os.path.join(srv, n))
            for e in prov["files"]:
                dst = os.path.join(srv, e["filename"])
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(os.path.join(rd, e["filename"]), dst)
        copies = [] if s.name in source_only else [(e, os.path.join(srv, e["filename"])) for e in prov["files"]]
        for e in prov["files"]:
            if e["role"] == "source":
                sd = os.path.join(out_dir, s.source_dir)
                os.makedirs(sd, exist_ok=True)
                dst = os.path.join(sd, os.path.basename(e["filename"]))
                shutil.copyfile(os.path.join(rd, e["filename"]), dst)
                copies.append((e, dst))
                with open(os.path.join(sd, "origin.txt"), "a") as f:
                    f.write(e["url"] + "\n")
        # second read of every copied file: nothing changed between verify and the build tree
        for e, dst in copies:
            if digest(dst) != e["sha256"]:
                raise ChainError("[%s] %s changed while copying" % (s.name, e["filename"]))
        if s.provenance:
            pp = os.path.join(out_dir, s.provenance)
            os.makedirs(os.path.dirname(pp), exist_ok=True)
            with open(pp, "w") as f:
                json.dump(prov, f, indent=2, sort_keys=True)
                f.write("\n")
    with open(os.path.join(out_dir, "apt-pin-inputs.json"), "w") as f:
        json.dump({"sets": [p for _, p, _, _ in provs], "source_only": sorted(source_only)}, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(os.path.join(out_dir, "pinned.conf"), "w") as f:
        f.write("# generated by images/debian/tools/apt-pin.py prepare from %s: verified local copies, pinned versions\n"
                % " ".join(c for c, _, _ in confs))
        if source_only:
            f.write("# source only (nothing installed): %s\n" % " ".join(sorted(source_only)))
        # absolute: mkosi resolves a relative SandboxTrees= of an --include file against the directory it builds in (the
        # profile), not against this file (the build then fails with "aptpin does not exist")
        f.write("[Build]\nSandboxTrees=%s\n\n[Content]\nPackages=\n" % sbx)
        f.writelines("        %s=%s\n" % pv for pv in sorted(installed))
    log("pinned.conf: %d packages from %d sets (%d source only); build tree: %s" % (
        len(installed), len(provs) - len(set(source_only)), len(set(source_only)), out_dir))
    return [p for _, p, _, _ in provs]


def write_lock(conf, sets, lock, cache):
    """Rewrite the apt lines of conf's lock from the chain; other kinds (e.g. `release`, fetch-upstream.py) are kept."""
    path = lock_path(conf)
    keep = [l for l in (open(path).read().splitlines() if os.path.isfile(path) else [])
            if l.split()[:1] and not l.startswith("#") and l.split()[0] != "apt"]
    lines = ["# %s: pinned files of %s, one line each: <kind> <set> <sha256> <size> <url>" % (os.path.basename(path), os.path.basename(conf)),
             "# apt lines: written by images/debian/tools/apt-pin.py lock from the verified chain; review the diff"]
    for s in sets:
        _, _, _, lockable = verify_set(s, cache, None)
        lines += ["apt %s %s %d %s" % (s.name, e["sha256"], e["size"], e["url"]) for e in sorted(lockable, key=lambda e: e["url"])]
    open(path, "w").write("\n".join(lines + keep) + "\n")
    log("%s: %d apt lines written" % (path, len(lines) - 2))


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("command", choices=["fetch", "verify", "prepare", "lock"])
    a.add_argument("--conf", action="append", required=True, help="set file (repeatable)")
    a.add_argument("--cache", required=True)
    a.add_argument("--out-dir", help="prepare: the mkosi configuration directory (images/debian/mkosi)")
    a.add_argument("--refresh", action="store_true", help="fetch: download the keys and InRelease again")
    a.add_argument("--source-only", action="append", default=[], metavar="SET",
                   help="prepare: verify SET and write its source-dir/provenance, install nothing from it (repeatable)")
    o = a.parse_args()
    cache = os.path.abspath(o.cache)
    try:
        confs = load_conf(o.conf)
        if o.command == "lock":
            for c, sets, lock in confs:
                write_lock(c, sets, lock, cache)
            return
        if o.command == "fetch" and os.environ.get("NL_OFFLINE") == "1":
            raise SystemExit("fetch refused: NL_OFFLINE=1 (offline build: verify and prepare from the cache only)")
        if o.command == "fetch":
            for _, sets, _ in confs:
                for s in sets:
                    fetch_set(s, cache, o.refresh)
        if o.command == "prepare":
            if not o.out_dir:
                a.error("prepare needs --out-dir")
            provs = prepare(confs, cache, os.path.abspath(o.out_dir), o.source_only)
        elif o.source_only:
            a.error("--source-only applies to prepare only")
        else:
            provs = [verify_set(s, cache, lock)[0] for _, sets, lock in confs for s in sets]
    except ChainError as e:
        sys.exit("apt-pin: REFUSED: %s" % e)
    for p in provs:
        log("[%s] chain ok + lock ok: key %s, InRelease %s (Date %s), %s %s, %d files" % (
            p["set"], p["key"]["fingerprint"], p["inrelease"]["sha256"][:16], p["inrelease"]["date"], p["index"]["name"],
            p["index"].get("sha256", p["index"].get("sha512", ""))[:16], len(p["files"])))
        for e in p["files"]:
            log("  %s %s %-7s %s" % (e["sha256"], e["size"], e["role"], e["filename"]))


if __name__ == "__main__":
    main()
