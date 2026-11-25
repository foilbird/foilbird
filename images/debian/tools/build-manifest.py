#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Build manifest of one image build (docs/reproducible-build.md): a sorted text file that two builds of the same
commit and snapshot can be compared by, line by line, even when they were signed with different keys.

  build-manifest.py make --out-dir DIR [--usr-image FILE | --usr-tree DIR] [--input NAME=FILE]... [--output FILE]
      DIR       the build-image.sh output directory (build-params.txt, the mkosi JSON package manifest *.manifest,
                the partition images and the UKI); the /usr image is found there unless --usr-image/--usr-tree is given
      --input   a build input whose sha256 is recorded (apt-pin.lock, apt-pin-inputs.json, the agent dist SHA256SUMS,
                upstream.json, ...); NAME is the label in the manifest
  build-manifest.py extract LOG [--output FILE]
      the manifest a CI job printed between "=== BEGIN build-manifest.txt" and "=== END build-manifest.txt", from
      its raw log (`gh run view --log`: "<job>\t<step>\t<timestamp> <line>") or a plain log; CI <-> CI comparison
      of two runs of one tag = extract both, then compare
  build-manifest.py compare A B
      exit 0 if A and B agree on every line of a stable class and differ at most in the classes that depend on keys or
      deployment parameters (each such difference is printed with its reason); exit 1 otherwise, listing what differs
      The keyed list is CLOSED: a keyed line of either manifest that is not in KEYED (with that class), ARTIFACT or
      BUILD_PARAMS, or a ko-signed module without its unsigned-content `usr ko` line, is a failure. Printed: keyed lines per
      class, every keyed path but the modules, and the sha256 of the closed list (a change of it is a reviewed change).
      Sizes (manifest v2): the size of the /usr verity hash tree (*.usr-x86-64-verity.raw) and of the disk image
      (<name>_<V>.raw) must be EQUAL (a different size is a different layout, whatever the keys); the sizes of the other
      keyed artifacts and files are printed for reference. A v1 manifest has no sizes: printed, not compared.

Lines (`<section> <class> <value...> <name>`; sorted):
  input    param   <value> <name>          build-params.txt: debian_snapshot, source_date_epoch, seed, mkosi, version, ...
  input    file    <sha256> <name>         every --input file
  package  deb     <version> <arch> <name> the mkosi package manifest (what apt installed, with versions)
  usr      file    <sha256> <mode> <path>  every regular file of /usr (content and permission bits)
  usr      link    <target> <path>         every symlink
  usr      dir     <mode> <path>           every directory
  usr      ko      <sha256> <mode> <path>  a kernel module: sha256 of the module WITHOUT its appended signature (after
                                           xz/zstd decompression), the same for any signing key
  keyed    <class> <sha256> <size> <path|name>
                                           differs with the keys or the deployment parameters by construction (see KEYED):
                                           files that hold a key or the channel, partition images and the UKI (artifact);
                                           size in bytes (v2)
  keyed    ko-signed <sha256> <path>       a signed module as shipped
  keyed    build-param <value> <name>      key fingerprints and the channel of build-params.txt
Ownership is not recorded (an unprivileged extraction of the erofs image cannot read it).
"""
import argparse
import fnmatch
import glob
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

# files of /usr that depend on the keys or the deployment parameters of build-image.sh: (glob, class, reason)
KEYED = [
    ("usr/lib/systemd/import-pubring.gpg", "release-key", "the release keyring (--release-keyring)"),
    ("usr/lib/systemd/import-pubring.pgp", "release-key", "the release keyring (--release-keyring)"),
    ("usr/lib/foilbird/pcr-key.pem", "pcr-key", "public PCR policy key (--pcr-cert)"),
    ("usr/lib/foil-agent/channel", "channel", "default update channel (--channel)"),
    ("usr/lib/foil-agent/channel-ca.pem", "channel", "CA bundle of the channel (--channel-ca)"),
    ("usr/lib/sysupdate.d/*.transfer", "channel", "Path= of the update channel (--channel http(s))"),
    ("usr/share/foilbird/sbom/nvidia-open-kernel-modules.json", "db-key", "sha256 of the signed modules, db certificate"),
    # found by comparing two CI builds with different ephemeral keys: both carry the db key
    ("usr/lib/systemd/boot/efi/*.efi.signed", "db-key", "systemd-boot signed with the db key (SecureBoot=yes)"),
    ("usr/lib/verity.d/*", "db-key", "the db certificate that verifies the /usr verity signature"),
]
# the other keyed classes, closed as well: what make() writes and nothing else (compare refuses any other keyed line)
ARTIFACT = re.compile(r"^[a-z0-9-]+_[0-9]+(\.efi|\.raw|\.esp\.raw|\.usr-x86-64\.raw|\.usr-x86-64-verity\.raw|\.usr-x86-64-verity-sig\.raw)$")
BUILD_PARAMS = {"release_key", "sb_cert_sha256", "pcr_cert_sha256", "channel", "channel_ca"}
KO = re.compile(r"\.ko(\.xz|\.zst|\.gz)?$")
# keyed artifacts whose SIZE must be equal between two builds of one commit: the verity hash tree (its size follows from the
# size of /usr) and the disk image (its size is the repart layout); the other sizes are for reference
SIZE_STRICT = re.compile(r"(\.usr-x86-64-verity\.raw|^[a-z0-9-]+_[0-9]+\.raw)$")
MANIFEST_VERSION = 2
MODSIG_MAGIC = b"~Module signature appended~\n"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def decompress(path, data):
    if path.endswith(".xz"):
        return lzma.decompress(data)
    if path.endswith(".gz"):
        return gzip.decompress(data)
    if path.endswith(".zst"):
        return subprocess.run(["zstd", "-dc"], input=data, capture_output=True, check=True).stdout
    return data


def strip_module_signature(ko):
    """The module without its appended signature (struct module_signature + signer + key id + signature + magic), or
    the module unchanged if it carries none."""
    if not ko.endswith(MODSIG_MAGIC):
        return ko, False
    end = len(ko) - len(MODSIG_MAGIC)
    algo, hsh, id_type, signer_len, key_id_len, sig_len = struct.unpack(">BBBBB3xI", ko[end - 12:end])
    body = end - 12 - sig_len - signer_len - key_id_len
    if body <= 0:
        raise ValueError("bad module signature trailer")
    return ko[:body], True


def keyed_class(rel):
    for g, c, why in KEYED:
        if fnmatch.fnmatchcase(rel, g):
            return c, why
    return None, None


def walk_usr(root):
    """Manifest lines of the tree root/usr (root = a directory holding usr/)."""
    lines = []
    usr = os.path.join(root, "usr")
    if not os.path.isdir(usr):
        raise SystemExit("build-manifest: %s has no usr/" % root)
    for d, dirs, files in os.walk(usr):
        dirs.sort()
        for n in sorted(dirs + files):
            p = os.path.join(d, n)
            rel = os.path.relpath(p, root)
            st = os.lstat(p)
            mode = "%04o" % stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                lines.append("usr link %s %s" % (os.readlink(p), rel))
            elif stat.S_ISDIR(st.st_mode):
                lines.append("usr dir %s %s" % (mode, rel))
            elif stat.S_ISREG(st.st_mode):
                data = open(p, "rb").read()
                c, _ = keyed_class(rel)
                if c:
                    lines.append("keyed %s %s %d %s" % (c, sha256(data), len(data), rel))
                elif KO.search(rel) and rel.startswith("usr/lib/modules/"):
                    body, signed = strip_module_signature(decompress(rel, data))
                    lines.append("usr ko %s %s %s" % (sha256(body), mode, rel))
                    if signed:
                        lines.append("keyed ko-signed %s %s" % (sha256(data), rel))
                else:
                    lines.append("usr file %s %s %s" % (sha256(data), mode, rel))
            else:
                lines.append("usr special %s %s" % (mode, rel))
    return lines


def extract_usr(image, dest):
    """Unpack an erofs /usr partition image into dest/usr with fsck.erofs (erofs-utils)."""
    if shutil.which("fsck.erofs") is None:
        raise SystemExit("build-manifest: fsck.erofs not found (erofs-utils; or run inside the mkosi tools tree)")
    os.makedirs(os.path.join(dest, "usr"))
    r = subprocess.run(["fsck.erofs", "--extract=" + os.path.join(dest, "usr"), "--preserve-perms", "--overwrite", image],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build-manifest: fsck.erofs %s: rc=%d %s" % (image, r.returncode, r.stderr.strip()[-300:]))


def make(o):
    out = []
    bp = os.path.join(o.out_dir, "build-params.txt")
    if not os.path.isfile(bp):
        raise SystemExit("build-manifest: %s missing (build-image.sh writes it)" % bp)
    for line in open(bp).read().split("\n"):
        # key=value pairs; a value may hold spaces (mkosi=mkosi 26): words without '=' belong to the previous value
        kvs = []
        for w in line.split():
            if re.match(r"^\w+=", w):
                kvs.append(list(w.split("=", 1)))
            elif kvs:
                kvs[-1][1] += " " + w
        for k, v in kvs:
            if v:
                c = "keyed" if k in ("release_key", "sb_cert_sha256", "pcr_cert_sha256", "channel", "channel_ca") else "input"
                out.append("%s %s %s %s" % (c, "param" if c == "input" else "build-param", v, k))
    for spec in o.input or []:
        name, _, path = spec.partition("=")
        if not path or not os.path.isfile(path):
            raise SystemExit("build-manifest: --input %s: expected NAME=FILE" % spec)
        out.append("input file %s %s" % (sha256_file(path), name))
    mans = sorted(glob.glob(os.path.join(o.out_dir, "*.manifest")))
    if not mans:
        raise SystemExit("build-manifest: no mkosi package manifest (*.manifest, ManifestFormat=json) in %s" % o.out_dir)
    for m in mans:
        for p in json.load(open(m)).get("packages", []):
            out.append("package %s %s %s %s" % (p.get("type", "deb"), p["version"], p.get("architecture", "-"), p["name"]))
        out.append("input file %s manifest:%s" % (sha256_file(m), os.path.basename(m)))
    for f in sorted(os.listdir(o.out_dir)):
        p = os.path.join(o.out_dir, f)
        if os.path.isfile(p) and not os.path.islink(p) and (f.endswith(".raw") or f.endswith(".efi")):
            out.append("keyed artifact %s %d %s" % (sha256_file(p), os.path.getsize(p), f))
    if o.usr_tree:
        out += walk_usr(o.usr_tree)
    else:
        img = o.usr_image or next(iter(sorted(glob.glob(os.path.join(o.out_dir, "*.usr-x86-64.raw")))), None)
        if not img:
            raise SystemExit("build-manifest: no /usr image (*.usr-x86-64.raw) in %s; --usr-image or --usr-tree" % o.out_dir)
        with tempfile.TemporaryDirectory() as t:
            extract_usr(img, t)
            out += walk_usr(t)
    text = "# foilbird build manifest v%d (images/debian/tools/build-manifest.py)\n" % MANIFEST_VERSION + "\n".join(sorted(set(out))) + "\n"
    if o.output:
        open(o.output, "w").write(text)
    else:
        sys.stdout.write(text)


GH_PREFIX = re.compile(r"^[^\t]*\t[^\t]*\t\d{4}-\d\d-\d\dT[\d:.]+Z ?")


def extract(o):
    out, inside, found = [], False, False
    for raw in open(o.log, encoding="utf-8", errors="replace"):
        line = GH_PREFIX.sub("", raw.rstrip("\n").replace("\ufeff", ""))
        if line == "=== BEGIN build-manifest.txt":
            out, inside, found = [], True, True   # the last printed manifest wins
            continue
        if line == "=== END build-manifest.txt":
            inside = False
            continue
        if inside:
            out.append(line)
    if not found or inside:
        raise SystemExit("build-manifest: %s: no complete BEGIN/END build-manifest.txt block" % o.log)
    text = "\n".join(out) + "\n"
    if o.output:
        open(o.output, "w").write(text)
    else:
        sys.stdout.write(text)


def parse(path):
    """{(section, class, name): value} of a manifest; name = last field, value = the fields between."""
    d = {}
    for line in open(path):
        if line.startswith("#") or not line.strip():
            continue
        f = line.split()
        d[(f[0], f[1], f[-1])] = " ".join(f[2:-1])
    return d


def keyed_open(M):
    """Keyed lines of manifest M outside the closed list (empty = all accounted for)."""
    out = []
    for (sec, c, name), v in sorted(M.items()):
        if sec != "keyed":
            continue
        if c == "ko-signed":
            if not KO.search(name) or ("usr", "ko", name) not in M:
                out.append("keyed ko-signed %s: no `usr ko` line with its unsigned content" % name)
        elif c == "artifact":
            if not ARTIFACT.match(name):
                out.append("keyed artifact %s: not a known output (ARTIFACT)" % name)
        elif c == "build-param":
            if name not in BUILD_PARAMS:
                out.append("keyed build-param %s: not in BUILD_PARAMS" % name)
        else:
            kc, _ = keyed_class(name)
            if kc is None:
                out.append("keyed %s %s: path not in KEYED" % (c, name))
            elif kc != c:
                out.append("keyed %s %s: KEYED gives class %s" % (c, name, kc))
    return out


def sized(M, k):
    """(sha256, size or None) of a keyed artifact/file line; v1 lines carry no size."""
    v = M.get(k)
    if v is None:
        return None, None
    f = v.split()
    return f[0], (int(f[1]) if len(f) == 2 and f[1].isdigit() else None)


def closed_list_digest():
    text = repr((KEYED, ARTIFACT.pattern, sorted(BUILD_PARAMS), KO.pattern))
    return hashlib.sha256(text.encode()).hexdigest()


def compare(a, b):
    A, B = parse(a), parse(b)
    bad, expected = [], []
    # closed keyed list: every keyed line of either manifest must be accounted for; a signed module is
    # keyed only with an EQUAL unsigned-content line (`usr ko`, compared as a stable line below)
    for tag, M in (("A", A), ("B", B)):
        for l in keyed_open(M):
            bad.append("%s: %s" % (tag, l))
    for tag, M in (("A", A), ("B", B)):
        per = {}
        for (sec, c, _), _v in M.items():
            if sec == "keyed":
                per[c] = per.get(c, 0) + 1
        print("keyed lines %s: %d (%s)" % (tag, sum(per.values()), ", ".join("%s %d" % kv for kv in sorted(per.items()))))
    print("closed keyed list: sha256 %s (KEYED + ARTIFACT + BUILD_PARAMS of this build-manifest.py)" % closed_list_digest())
    for k in sorted(k for k in set(A) | set(B) if k[0] == "keyed" and k[1] not in ("ko-signed",)):
        print("keyed path %s %s" % (k[1], k[2]))
    reasons = {c: why for _, c, why in KEYED}
    reasons.update({"ko-signed": "module signature (db key)", "artifact": "signed partition or UKI",
                    "build-param": "key fingerprint or channel of the build"})
    # sizes (v2): strict for the verity hash tree and the disk image, for reference otherwise
    for k in sorted(k for k in set(A) | set(B) if k[0] == "keyed" and k[1] not in ("ko-signed", "build-param")):
        (_, sa), (_, sb) = sized(A, k), sized(B, k)
        strict = k[1] == "artifact" and SIZE_STRICT.search(k[2]) is not None
        if sa is None or sb is None:
            print("size %s %s: %s -> %s (not in a v1 manifest: not compared)" % (k[1], k[2], sa, sb))
        elif strict and sa != sb:
            bad.append("size %s %s: %d -> %d (must be equal: layout)" % (k[1], k[2], sa, sb))
        else:
            print("size %s %s: %d -> %d %s" % (k[1], k[2], sa, sb, "EQUAL (strict)" if strict else
                                                  ("equal" if sa == sb else "differs (reference only)")))
    for k in sorted(set(A) | set(B)):
        va, vb = A.get(k), B.get(k)
        if va == vb:
            continue
        line = "%s %s %s: %s -> %s" % (k[0], k[1], k[2], va or "(absent)", vb or "(absent)")
        if k[0] == "keyed" and va is not None and vb is not None:
            expected.append(line + "  [%s]" % reasons.get(k[1], k[1]))
        else:
            bad.append(line)
    for l in expected:
        print("EXPECTED", l)
    for l in bad:
        print("DIFF    ", l)
    sig = sum(1 for k in set(A) | set(B) if k[:2] == ("keyed", "ko-signed"))
    print("keyed ko-signed: %d modules, each with an equal unsigned-content `usr ko` line (checked above)" % sig)
    print("size: strict for *.usr-x86-64-verity.raw and <name>_<V>.raw, reference for the other keyed artifacts and files"
          " (v1 manifests carry no size); composition = the keyed path set (equal or DIFF above) and every stable line")
    print("compare: %d lines, %d expected differences (keys/deployment), %d unexplained" % (len(set(A) | set(B)), len(expected), len(bad)))
    return 0 if not bad else 1


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = a.add_subparsers(dest="command", required=True)
    m = sub.add_parser("make")
    m.add_argument("--out-dir", required=True)
    g = m.add_mutually_exclusive_group()
    g.add_argument("--usr-image")
    g.add_argument("--usr-tree")
    m.add_argument("--input", action="append")
    m.add_argument("--output")
    x = sub.add_parser("extract")
    x.add_argument("log")
    x.add_argument("--output")
    c = sub.add_parser("compare")
    c.add_argument("a")
    c.add_argument("b")
    o = a.parse_args()
    if o.command == "make":
        make(o)
    elif o.command == "extract":
        extract(o)
    else:
        sys.exit(compare(o.a, o.b))


if __name__ == "__main__":
    main()
