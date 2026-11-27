#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""SBOM and third-party notices of one node image, written at the end of every image build (mkosi.finalize).

  image-sbom.py <image root> <out dir> [<copy dir>...]

Reads only what is in the image root:
  usr/lib/foilbird/dpkg/status                  Debian packages (also what Trivy/Grype read on the node)
  usr/share/doc/<package>/copyright           licences: the License: fields of machine-readable (DEP-5) files
  usr/share/foilbird/sbom/*.json                components that are no dpkg package (containerd, runc, the Kubernetes and
                                              toolkit packages' origin and sha256, foil-k8s-env, NVIDIA open modules,
                                              NVIDIA input provenance)
  usr/share/foil-agent/sbom.cdx.json           the agent's own CycloneDX (Rust crates, cargo-cyclonedx)
  usr/lib/os-release                          image id, version, profile
Writes into <out dir> (and every <copy dir>):
  foilbird-sbom.cdx.json                        CycloneDX 1.5, deterministic: no timestamp unless SOURCE_DATE_EPOCH is set,
                                              serial number derived from the content
  THIRD-PARTY-NOTICES.txt                     every third-party component with version, licence and where its licence
                                              text is; components NVIDIA licenses are marked (not redistributed)
Fails if a dpkg package has no copyright file or a component has no licence at all.
"""
import glob
import hashlib
import json
import os
import re
import sys
import time
import uuid

NVIDIA_MARK = "NVIDIA component: built into deployment images only, not redistributed by this project"


def read(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def os_release(root):
    for p in ("usr/lib/os-release", "etc/os-release"):
        f = os.path.join(root, p)
        if os.path.isfile(f) and not os.path.islink(f):
            return dict((k, v.strip('"')) for k, v in re.findall(r"^(\w+)=(.*)$", read(f), re.M))
    return {}


def dep5_licenses(text):
    """Short licence names of a machine-readable copyright file, or None when it is not DEP-5."""
    if not re.match(r"^Format:\s*\S*copyright-format", text, re.I | re.M):
        return None
    names = []
    for m in re.finditer(r"^License:[ \t]*(\S[^\n]*)$", text, re.M):
        n = m.group(1).strip()
        if n and n not in names:
            names.append(n)
    return names


def is_nvidia(fields):
    return "nvidia" in (fields.get("Maintainer", "") + fields.get("Homepage", "")).lower() or \
        fields.get("Package", "").startswith(("nvidia-", "libnvidia-", "libcuda", "libnvcuvid", "libnvoptix", "firmware-nvidia"))


def debian_components(root, problems):
    st = os.path.join(root, "usr/lib/foilbird/dpkg/status")
    comps = []
    for block in read(st).split("\n\n"):
        f = dict(re.findall(r"^([\w-]+): (.*)$", block, re.M))
        if "Package" not in f or "install ok installed" not in f.get("Status", ""):
            continue
        name, ver, arch = f["Package"], f["Version"], f.get("Architecture", "all")
        cp = os.path.join(root, "usr/share/doc", name, "copyright")
        if not os.path.isfile(cp):
            # multi-arch or renamed doc directory (dpkg's /usr/share/doc/<package> symlinked to another package)
            alt = os.path.join(root, "usr/share/doc", name.split(":")[0], "copyright")
            cp = alt if os.path.isfile(alt) else None
        if cp is None:
            lic, where = [], None
        else:
            lic = dep5_licenses(read(cp)) or []
            where = "/" + os.path.relpath(cp, root)
        c = {"type": "library" if name.startswith("lib") else "application", "name": name, "version": ver,
             "purl": "pkg:deb/debian/%s@%s?arch=%s" % (name, ver, arch),
             "properties": [{"name": "foilbird:source", "value": "dpkg"}]}
        if f.get("Source"):
            c["properties"].append({"name": "foilbird:debian-source", "value": f["Source"].split()[0]})
        if lic:
            c["licenses"] = [{"license": {"name": n}} for n in lic]
        if where:
            c["properties"].append({"name": "foilbird:license-text", "value": where})
        if is_nvidia(f):
            c["supplier"] = {"name": "NVIDIA Corporation"}
            c["properties"].append({"name": "foilbird:redistribution", "value": "not-published"})
        comps.append(c)
    return comps


def fragment_components(root, problems):
    comps, prov = [], None
    for p in sorted(glob.glob(os.path.join(root, "usr/share/foilbird/sbom/*.json"))):
        d = json.loads(read(p))
        base = os.path.basename(p)
        if base == "nvidia-inputs.json":
            prov = d
            continue
        items = d.get("components") if isinstance(d.get("components"), list) else [d]
        for it in items:
            name = it.get("name") or it.get("component")
            if not name:
                continue
            if it.get("origin", "").startswith("pkgs.k8s.io") or it.get("origin", "").startswith("nvidia.github.io"):
                continue  # dpkg packages: listed from dpkg status, origin recorded as a property below
            c = {"type": "application", "name": name, "version": str(it.get("version", "")),
                 "properties": [{"name": "foilbird:source", "value": "/usr/share/foilbird/sbom/" + base}]}
            if it.get("license"):
                c["licenses"] = [{"license": {"name": it["license"]}}]
            else:
                problems.append("%s in %s: no licence" % (name, base))
            h = it.get("sha256") or (it.get("source") or {}).get("sha256")
            if h:
                c["hashes"] = [{"alg": "SHA-256", "content": h}]
            u = it.get("url") or (it.get("source") or {}).get("origin")
            if u:
                c["externalReferences"] = [{"type": "distribution", "url": u}]
            if name.startswith("nvidia"):
                c["supplier"] = {"name": "NVIDIA Corporation"}
                c["properties"].append({"name": "foilbird:redistribution", "value": "not-published"})
            comps.append(c)
    return comps, prov


def upstream_origins(root):
    """dpkg packages installed from third-party APT repositories: name -> (origin, sha256 of the .deb)."""
    o = {}
    p = os.path.join(root, "usr/share/foilbird/sbom/k8s-worker-upstream.json")
    if os.path.isfile(p):
        for it in json.loads(read(p)).get("components", []):
            if it.get("origin"):
                o[it["name"]] = (it["origin"], it.get("sha256"), it.get("license"))
    p = os.path.join(root, "usr/share/foilbird/sbom/nvidia-inputs.json")
    if os.path.isfile(p):
        d = json.loads(read(p))
        for e in d.get("files", []):
            o[e["package"]] = (d["repository"], e["sha256"], None)
    return o


def agent_components(root):
    p = os.path.join(root, "usr/share/foil-agent/sbom.cdx.json")
    if not os.path.isfile(p):
        return [], None
    d = json.loads(read(p))
    top = (d.get("metadata") or {}).get("component")
    out = []
    for c in d.get("components", []):
        c = {k: v for k, v in c.items() if k in ("type", "name", "version", "purl", "licenses", "hashes", "description")}
        c.setdefault("properties", []).append({"name": "foilbird:source", "value": "/usr/share/foil-agent/sbom.cdx.json"})
        out.append(c)
    return out, top


def license_names(c):
    n = []
    for l in c.get("licenses", []):
        x = l.get("expression") or (l.get("license") or {}).get("id") or (l.get("license") or {}).get("name")
        if x:
            n.append(x)
    return n


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    root, outs = sys.argv[1], sys.argv[2:]
    problems = []
    osr = os_release(root)
    deb = debian_components(root, problems)
    origins = upstream_origins(root)
    for c in deb:
        props = {p["name"] for p in c["properties"]}
        org, h, lic = origins.get(c["name"], (None, None, None))
        if org:
            c["properties"].append({"name": "foilbird:apt-origin", "value": org})
            if h:
                c["hashes"] = [{"alg": "SHA-256", "content": h}]
        if "foilbird:license-text" not in props:
            # third-party .debs without a copyright file (pkgs.k8s.io): the licence recorded by fetch-upstream.py
            common = "usr/share/common-licenses/%s" % lic if lic else None
            if lic and os.path.isfile(os.path.join(root, common)):
                c["licenses"] = [{"license": {"id": lic}}]
                c["properties"].append({"name": "foilbird:license-text", "value": "/" + common})
            else:
                problems.append("dpkg %s %s: no copyright file and no recorded licence" % (c["name"], c["version"]))
    frag, prov = fragment_components(root, problems)
    agent, agent_top = agent_components(root)
    comps = deb + frag
    if agent_top:
        t = {k: v for k, v in agent_top.items() if k in ("type", "name", "version", "purl", "licenses")}
        t.setdefault("properties", []).append({"name": "foilbird:source", "value": "/usr/share/foil-agent/sbom.cdx.json"})
        comps.append(t)
    comps += agent
    for c in comps:
        c["bom-ref"] = c.get("purl") or "%s@%s" % (c["name"], c.get("version", ""))
    # de-duplicate by bom-ref (a crate can appear once per dependency path in some generators)
    seen, uniq = set(), []
    for c in sorted(comps, key=lambda c: (c["bom-ref"], c["name"])):
        if c["bom-ref"] not in seen:
            seen.add(c["bom-ref"])
            uniq.append(c)
    unlicensed = [c["bom-ref"] for c in uniq if not license_names(c)]
    base = ((osr.get("ID_LIKE") or osr.get("ID") or "").split() or [""])[0]   # the base distribution (ID_LIKE=debian)
    image = {"type": "operating-system", "name": osr.get("IMAGE_ID", "foilbird"), "version": osr.get("IMAGE_VERSION", ""),
             "bom-ref": "image", "properties": [{"name": "foilbird:profile", "value": osr.get("FOILBIRD_PROFILE", "base")},
                                                {"name": "foilbird:base", "value": "%s %s" % (base, osr.get("VERSION_ID", ""))}]}
    if prov:
        image["properties"].append({"name": "foilbird:nvidia-inputs", "value": "/usr/share/foilbird/sbom/nvidia-inputs.json"})
        # stable: the repository and the signing key, never the InRelease of one fetch (re-signed upstream; the build's
        # own InRelease is in its build manifest)
        image["properties"].append({"name": "foilbird:nvidia-repository", "value": "%s %s key %s" % (
            prov["repository"], prov["version"], prov["key"]["fingerprint"])})
    body = json.dumps(uniq, sort_keys=True).encode()
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "serialNumber": "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, "foilbird-sbom:" + hashlib.sha256(body).hexdigest()),
           "version": 1, "metadata": {"component": image, "tools": {"components": [{"type": "application", "name": "image-sbom.py"}]}},
           "components": uniq}
    if os.environ.get("SOURCE_DATE_EPOCH"):
        bom["metadata"]["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(os.environ["SOURCE_DATE_EPOCH"])))

    lines = ["Third-party software in %s %s (profile %s)" % (image["name"], image["version"], osr.get("FOILBIRD_PROFILE", "base")),
             "Generated by images/debian/tools/image-sbom.py from the image itself; the CycloneDX SBOM foilbird-sbom.cdx.json lists",
             "the same components with package URLs and hashes. Licence texts: the path given per component, inside the image.",
             "Components marked NVIDIA are built into images by each deployment from NVIDIA's repository under NVIDIA's licence",
             "terms; this project does not redistribute them.", ""]
    for c in uniq:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        lines.append("%s %s" % (c["name"], c.get("version", "")))
        lines.append("  licence: %s" % (" AND ".join(license_names(c)) or "not machine-readable: see the licence text"))
        if props.get("foilbird:license-text"):
            lines.append("  licence text: %s" % props["foilbird:license-text"])
        if props.get("foilbird:apt-origin"):
            lines.append("  from: %s" % props["foilbird:apt-origin"])
        for r in c.get("externalReferences", []):
            lines.append("  from: %s" % r["url"])
        if props.get("foilbird:redistribution") == "not-published":
            lines.append("  " + NVIDIA_MARK)
    notices = "\n".join(lines) + "\n"

    for d in outs:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "foilbird-sbom.cdx.json"), "w") as f:
            json.dump(bom, f, indent=1, sort_keys=True)
            f.write("\n")
        with open(os.path.join(d, "THIRD-PARTY-NOTICES.txt"), "w") as f:
            f.write(notices)
    nv = sum(1 for c in uniq if any(p["value"] == "not-published" for p in c.get("properties", [])))
    print("image-sbom: %d components (dpkg %d, other %d, agent crates %d), NVIDIA-marked %d, without machine-readable licence %d"
          % (len(uniq), len(deb), len(frag), len(agent), nv, len(unlicensed)))
    for p in problems:
        print("image-sbom: ERROR " + p)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
