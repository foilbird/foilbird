#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Upstream inputs of the k8s-worker profile that are not Debian packages (runs on the build host, not on the node).

  fetch-upstream.py fetch   --cache DIR              download what is missing (containerd, runc releases; the profile's
                                                     apt sets through apt-pin.py), then verify as `prepare` does
  fetch-upstream.py prepare --cache DIR --out DIR    verify from the cache only (no network) and write <out>/:
      containerd-<v>-linux-amd64.tar.gz, runc.amd64     verified release artifacts (mkosi.build installs them)
      SHA256SUMS, containerd.version                    re-checked by mkosi.build before anything goes into the image
      upstream.json                                     versions, URLs, sha256, licences (SBOM input, k8s-worker-upstream.json)
      verify.log                                        what was checked, with digests
  fetch-upstream.py lock    --cache DIR              verify the releases (not against the lock) and REWRITE the `release`
                                                     lines of ../apt-pin.lock; the diff is reviewed

The apt sets of the profile (pkgs.k8s.io: kubelet, kubeadm, cri-tools, kubernetes-cni; nvidia-container-toolkit-base)
are pinned in ../apt-pin.conf and go into the build through images/debian/tools/apt-pin.py prepare (with the base
image's set file), not through this script; here they are only verified again for upstream.json.

Checks (the same for a file downloaded a second ago and one from the cache):
  containerd  sha256 of the tarball == its release .sha256sum
  runc        version = script/setup/runc-version of the containerd tag; GPG signature (.asc) against runc.keyring from
              the same runc tag (gpgv) + sha256 in the release runc.sha256sum
  every file  URL, size and sha256 equal to its `release <name> <sha256> <size> <url>` line of ../apt-pin.lock, and every
              line has its file (a re-tagged or re-uploaded release stops the build)
At fetch only (network): containerd's GitHub asset digest == the tarball's sha256, the tarball listed as a subject of the
release's provenance attestation (logged; the DSSE signature is not verified: no sigstore verifier on the builder).
"""
import argparse
import base64
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

here = os.path.dirname(os.path.abspath(__file__))
profile = os.path.dirname(here)
spec = importlib.util.spec_from_file_location("apt_pin", os.path.join(profile, "../../images/debian/tools/apt-pin.py"))
ap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ap)

CONF = os.path.join(profile, "apt-pin.conf")
PIN = {"containerd": "2.3.7"}  # 2.3 = upstream LTS; runc: the version containerd pins for this tag
LICENSE = {"containerd": "Apache-2.0", "runc": "Apache-2.0"}
GH = "https://github.com"
RAW = "https://raw.githubusercontent.com"


def urls_containerd():
    v = PIN["containerd"]
    rel = "%s/containerd/containerd/releases/download/v%s" % (GH, v)
    name = "containerd-%s-linux-amd64.tar.gz" % v
    return {"tarball": "%s/%s" % (rel, name), "sha256sum": "%s/%s.sha256sum" % (rel, name),
            "runc-version": "%s/containerd/containerd/v%s/script/setup/runc-version" % (RAW, v)}


def urls_runc(v):
    rel = "%s/opencontainers/runc/releases/download/v%s" % (GH, v)
    return {"binary": rel + "/runc.amd64", "asc": rel + "/runc.amd64.asc", "sha256sum": rel + "/runc.sha256sum",
            "keyring": "%s/opencontainers/runc/v%s/runc.keyring" % (RAW, v)}


class Log:
    def __init__(self):
        self.lines = []

    def __call__(self, *a):
        s = " ".join(str(x) for x in a)
        print(s, flush=True)
        self.lines.append(s)


def cached(cache, url):
    p = ap.cache_path(cache, url)
    if not os.path.isfile(p):
        raise ap.ChainError("%s missing in the cache (run fetch)" % url)
    return p


def runc_version(cache):
    rv = open(cached(cache, urls_containerd()["runc-version"])).read().strip().lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+(-rc\.?\d+)?", rv):
        raise ap.ChainError("containerd runc-version file says [%s]" % rv)
    return rv


def verify_releases(cache, lock, log):
    """THE check of the release files, from the cache. lock=None: not against the lock (for `lock`). Returns
    (components, {name: [(url, sha256, size)]})."""
    cu = urls_containerd()
    tb = cached(cache, cu["tarball"])
    ss = open(cached(cache, cu["sha256sum"])).read().split()
    d = ap.digest(tb)
    log("containerd", PIN["containerd"], "sha256", d, "release-sha256sum", ss[0] if ss else None)
    if not ss or ss[0] != d:
        raise ap.ChainError("containerd: tarball sha256 does not match the release .sha256sum")
    rv = runc_version(cache)
    log("containerd v%s pins runc %s" % (PIN["containerd"], rv))
    ru = urls_runc(rv)
    binp, asc, kr = cached(cache, ru["binary"]), cached(cache, ru["asc"]), cached(cache, ru["keyring"])
    with tempfile.TemporaryDirectory() as t:
        home = os.path.join(t, "gnupg")
        os.makedirs(home, mode=0o700)
        subprocess.run(["gpg", "--batch", "--homedir", home, "--import", kr], capture_output=True)
        kb = os.path.join(t, "runc.keyring.gpg")
        subprocess.run(["gpg", "--batch", "--homedir", home, "--export", "--output", kb], check=True, capture_output=True)
        r = subprocess.run(["gpgv", "--keyring", kb, asc, binp], capture_output=True, text=True)
    log("runc", rv, "gpgv rc", r.returncode, " | ".join(l for l in r.stderr.splitlines() if "Good signature" in l or "using" in l or "BAD" in l))
    if r.returncode != 0:
        raise ap.ChainError("runc: signature does not verify with runc.keyring of v%s" % rv)
    rd = ap.digest(binp)
    m = re.search(r"^([0-9a-f]{64})\s+\*?runc\.amd64$", open(cached(cache, ru["sha256sum"])).read(), re.M)
    log("runc sha256", rd, "release", m and m.group(1))
    if not m or m.group(1) != rd:
        raise ap.ChainError("runc: binary sha256 does not match runc.sha256sum")
    files = {"containerd": list(cu.values()), "runc": list(ru.values())}
    got = {n: [(u, ap.digest(cached(cache, u)), os.path.getsize(cached(cache, u))) for u in us] for n, us in files.items()}
    if lock is not None:
        probs = []
        for n, fs in got.items():
            want = lock.get(("release", n), {})
            have = {u: (s, z) for u, s, z in fs}
            probs += ["not in the lock: %s" % u for u in sorted(set(have) - set(want))]
            probs += ["in the lock but not used: %s" % u for u in sorted(set(want) - set(have))]
            probs += ["%s: sha256/size %s/%d, lock %s/%d" % (u, have[u][0][:16], have[u][1], want[u][0][:16], want[u][1])
                      for u in sorted(set(have) & set(want)) if have[u] != want[u]]
        stale = [k[1] for k in lock if k[0] == "release" and k[1] not in files]
        probs += ["release lines for unknown %s" % n for n in stale]
        if probs:
            raise ap.ChainError("release lock %s refused: %s" % (ap.lock_path(CONF), "; ".join(probs)))
        log("release lock ok: %d files" % sum(len(v) for v in got.values()))
    comps = [
        {"name": "containerd", "version": PIN["containerd"], "url": cu["tarball"], "sha256": d, "license": LICENSE["containerd"]},
        {"name": "runc", "version": rv, "url": ru["binary"], "sha256": rd, "license": LICENSE["runc"],
         "signature": "gpg, runc.keyring@v" + rv},
    ]
    return comps, got


def fetch(cache, log):
    cu = urls_containerd()
    for u in cu.values():
        if not os.path.isfile(ap.cache_path(cache, u)):
            ap.download(u, ap.cache_path(cache, u))
    for u in urls_runc(runc_version(cache)).values():
        if not os.path.isfile(ap.cache_path(cache, u)):
            ap.download(u, ap.cache_path(cache, u))
    # network-only cross-checks (logged): GitHub's asset digest and the provenance attestation of the containerd release
    try:
        req = urllib.request.Request("https://api.github.com/repos/containerd/containerd/releases/tags/v" + PIN["containerd"],
                                     headers={"User-Agent": "foil-build", "Accept": "application/vnd.github+json"})
        rel = json.loads(urllib.request.urlopen(req, timeout=60).read())
        d = ap.digest(ap.cache_path(cache, cu["tarball"]))
        a = [x for x in rel["assets"] if x["browser_download_url"] == cu["tarball"]]
        gd = a[0].get("digest") if a else None
        log("containerd github-digest", gd)
        if gd not in (None, "sha256:" + d):
            raise ap.ChainError("containerd: GitHub asset digest %s differs from the tarball's sha256" % gd)
        for x in [x for x in rel["assets"] if x["name"].endswith("attestation.intoto.jsonl")][:1]:
            found = False
            for line in urllib.request.urlopen(x["browser_download_url"], timeout=60).read().decode().splitlines():
                try:
                    env = json.loads(line)
                    env = env.get("dsseEnvelope", env)
                    found |= any(s.get("digest", {}).get("sha256") == d for s in json.loads(base64.b64decode(env["payload"])).get("subject", []))
                except (ValueError, KeyError, TypeError) as e:
                    log("containerd provenance line not parsed:", type(e).__name__)
            log("containerd provenance: tarball digest listed as subject =", found,
                "(signature of the DSSE envelope not verified: no sigstore verifier on the builder)")
    except (OSError, ValueError) as e:
        log("containerd GitHub API cross-check skipped:", type(e).__name__, e)
    for _, sets, _ in ap.load_conf([CONF]):
        for s in sets:
            ap.fetch_set(s, cache)


def write_release_lock(got, log):
    path = ap.lock_path(CONF)
    keep = [l for l in (open(path).read().splitlines() if os.path.isfile(path) else []) if l.split()[:1] != ["release"]]
    lines = ["release %s %s %d %s" % (n, s, z, u) for n in sorted(got) for u, s, z in sorted(got[n])]
    open(path, "w").write("\n".join(keep + lines) + "\n")
    log("%s: %d release lines written" % (path, len(lines)))


def prepare(cache, out, log, source_only=()):
    """upstream.json: the components the image carries. A set in source_only (apt-pin.py prepare --source-only, the
    same list from build-all.sh) is verified in full and listed as nothing installed: not a component of this image."""
    (_, sets, lock), = ap.load_conf([CONF])
    unknown = sorted(set(source_only) - {s.name for s in sets})
    if unknown:
        raise ap.ChainError("--source-only %s: no such set in %s" % (" ".join(unknown), CONF))
    comps, _ = verify_releases(cache, lock, log)
    for s in sets:
        prov = ap.verify_set(s, cache, lock)[0]
        log("[%s] chain ok + lock ok: key %s, InRelease %s, %d files" % (s.name, prov["key"]["fingerprint"], prov["inrelease"]["sha256"][:16], len(prov["files"])))
        if s.name in source_only:
            log("[%s] source only: verified, not a component of this image" % s.name)
            continue
        origin = s.repo.split("://", 1)[1]
        for e in prov["files"]:
            if e["role"] == "install":
                comps.append({"name": e["package"], "version": e["version"], "origin": origin, "url": e["url"],
                              "sha256": e["sha256"], "license": s.license})
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    cu = urls_containerd()
    tbname = os.path.basename(cu["tarball"])
    shutil.copyfile(ap.cache_path(cache, cu["tarball"]), os.path.join(out, tbname))
    shutil.copyfile(ap.cache_path(cache, urls_runc(runc_version(cache))["binary"]), os.path.join(out, "runc.amd64"))
    os.chmod(os.path.join(out, "runc.amd64"), 0o755)
    with open(os.path.join(out, "SHA256SUMS"), "w") as f:
        f.write("%s  %s\n%s  runc.amd64\n" % (comps[0]["sha256"], tbname, comps[1]["sha256"]))
    for n in (tbname, "runc.amd64"):  # nothing changed between the check and the build input
        if ap.digest(os.path.join(out, n)) != (comps[0] if n == tbname else comps[1])["sha256"]:
            raise ap.ChainError("%s changed while copying" % n)
    open(os.path.join(out, "containerd.version"), "w").write(PIN["containerd"] + "\n")
    pins = dict(PIN, runc=comps[1]["version"])
    with open(os.path.join(out, "upstream.json"), "w") as f:
        json.dump({"components": comps, "pins": pins, "lock": os.path.relpath(ap.lock_path(CONF), profile)}, f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("command", choices=["fetch", "prepare", "lock"])
    a.add_argument("--cache", required=True)
    a.add_argument("--out", help="prepare: output directory (the profile's upstream/, gitignored)")
    a.add_argument("--source-only", action="append", default=[], metavar="SET",
                   help="prepare: a set of apt-pin.conf verified but not installed (build-all.sh: the NVIDIA sets for cp)")
    o = a.parse_args()
    cache = os.path.abspath(o.cache)
    log = Log()
    try:
        if o.command == "fetch":
            fetch(cache, log)
            (_, sets, lock), = ap.load_conf([CONF])
            verify_releases(cache, lock, log)
            for s in sets:
                ap.verify_set(s, cache, lock)
                log("[%s] chain ok + lock ok" % s.name)
        elif o.command == "lock":
            _, got = verify_releases(cache, None, log)
            write_release_lock(got, log)
        else:
            if not o.out:
                a.error("prepare needs --out")
            out = os.path.abspath(o.out)
            prepare(cache, out, log, tuple(o.source_only))
            open(os.path.join(out, "verify.log"), "w").write("\n".join(log.lines) + "\n")
    except ap.ChainError as e:
        sys.exit("fetch-upstream: REFUSED: %s" % e)
    log("OK")


if __name__ == "__main__":
    main()
