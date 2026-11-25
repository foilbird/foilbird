#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publication gate rules that need no word list: runs in CI before any build (seconds).

  tests/compliance/oss-gate.py [--repo DIR] [--rev REV] [--own OWNER[/REPO]]... [--history] [--selftest]

Rules over the files of REV (`git archive`, default HEAD), text files only (UTF-8, no NUL, <= 4 MiB), as the
dictionary scan reads them:
  address     every IPv4-shaped literal (four dotted groups of 1-3 digits) is 0.0.0.0, 127.0.0.1, 255.255.255.255, in an
              RFC 5737 range, or listed in docs/compliance/named-addresses.md (of REV) for the path it is under; a line
              carrying "osscheck:allow" is exempt (the same marker as the dictionary scan)
  domains     every domain name (a host in a URL or an e-mail address, or a bare name ending in a TLD of DOMAIN_TLDS)
              is reserved for documentation or tests (example.com/.net/.org, *.example, *.invalid, *.test, *.localhost)
              or its registrable part (the last two labels) is listed in the first column of
              docs/compliance/named-domains.md (of REV); a line carrying "osscheck:allow" is exempt. TLDs that are also
              file extensions of the tree (rs, sh, py, md, pl, network, link, ...) are not in DOMAIN_TLDS: a bare
              "main.rs" is a file, a domain under such a TLD is still caught inside a URL or an e-mail address
  own-names   with --own: the owner's login (a word, any case) and github.com/<owner>/ do not occur. While the project
              name is not chosen (PENDING_RENAME below) the findings are printed as EXPECTED and do not fail the gate
  old-hashes  with --history: no hex token of 7-40 characters names a commit or tag object of the repository's history
              (an ambiguous short id counts); the history must be present in --repo (CI fetches it without trees)
  traces      no internal process ids (case-sensitive, as words): a session or milestone name M<n>[.<n>] (also M<n>-<id>),
              a lab file prefix m<n>-, a marker M<n>-<UPPER>, an acceptance id A<n>[a-z], a question id Q<n>[a-z], a
              tracker reference "backlog <n>", a document part "Part <X>", a plan item R<n>/O<n>/RC<n>/P<n>/B<n> [a-z] or a goal's try o<n>-try, or the name of the
              internal design document (the three letters of a request for comments) without an IETF number after
              it: a section sign, "the …", "…-0007", "… 2" are internal; an IETF number has 3+ digits without a
              leading zero ("… 5737", "…1918"), and "…-compliant" is plain text ("-" before it is an option
              or a range: -O2, A-Z0). TRACE_ALLOW below names
              the exceptions, one token per row with its reason (a hardware model, not an id); the patterns themselves
              are never loosened
  test-ids    every test id T<n>[a-z] in the tree is defined in tests/README.md: a table row "| T<n> | <description> |"
              (the id in the first cell, a non-empty second cell); an id used but not defined fails
  z-ids       every deferred item Z<n>[a-z] in the tree names a row "| Z<n> | <description> |" of the table of ONE
              decision (docs/decisions/0005-*.md or 0013-*.md; the first three ids are in both, so a bare id is
              ambiguous): inside one of those two files a bare id names its own table; anywhere else the id needs the
              qualifier "decision 00NN" or "ADR 00NN" before it in the same line (the nearest one naming 0005 or
              0013 counts; other decisions have no such table) and the row in the table of exactly that decision. A bare id outside them, an id the named table lacks, an invented id, a row removed while the
              id is still used, a row without a description: each fails. "-" or "." before it is no id (A-Z0)
  --selftest  probes of the rules on generated files: an address outside the list, a listed address outside its path,
              a domain outside the list (bare, in a URL, in an e-mail address), the reserved and listed domains and file
              names that look like domains (must pass),
              an own name, the id of a commit of --repo, one line per trace pattern; each must be found, and the
              allowed cases (and the trace negatives: TPM2, LUKS2, an M.2 SSD, x86-64, q35, A100, R&D, IETF numbers, RAID1,
              O_DIRECT, -O2, rc=, P-states, zstd -19, PCIe, [A-Z0-9], base32, P0, B2B, hex) must
              pass; a test id or Z-id used but not defined (or defined without a description, or its row removed) must
              be found
Matches are printed masked (the first two characters and the length), never in full; trace ids (not secrets) in full.
Last line: "OSS-GATE PASS|FAIL ..."; exit 0 PASS, 1 FAIL, 2 bad input.
"""
import argparse, io, re, subprocess, sys, tarfile

# The project name is not chosen yet: the tree still names the current repository (unit Documentation= links). Set to
# False together with the rename; from then on an own name fails the gate.
PENDING_RENAME = True

MAX = 4 << 20
ADDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{7,40}(?![0-9a-fA-F])")
ALWAYS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
ALLOW_MARKER = "osscheck:allow"
LIST = "docs/compliance/named-addresses.md"
DOMAINS_LIST = "docs/compliance/named-domains.md"
# Bare names and e-mail hosts count as domains only under these TLDs: none of them is a file extension of the tree or
# a short word a field or an instance name ends in (self.ca, x.in, unit@3.service); inside a URL (scheme://host) any
# TLD counts.
DOMAIN_TLDS = "com net org io dev app ai gov edu info biz cloud tech online site xyz ru su de uk eu fr cn jp kz ua"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN_BARE = re.compile(r"(?<![A-Za-z0-9_.@/-])((?:%s\.)+(?:%s))(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9])"
                         % (_LABEL, "|".join(DOMAIN_TLDS.split())), re.I)
DOMAIN_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^\s/@]*@)?((?:%s\.)+[A-Za-z][A-Za-z0-9-]*[A-Za-z])(?![A-Za-z0-9_-])"
                        % _LABEL)
DOMAIN_MAIL = re.compile(r"(?<=[A-Za-z0-9_.+-])@((?:%s\.)+(?:%s|example|invalid|test|localhost))(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9])"
                         % (_LABEL, "|".join(DOMAIN_TLDS.split())), re.I)
RESERVED_SLD = {"example.com", "example.net", "example.org"}
RESERVED_TLD = {"example", "invalid", "test", "localhost"}

# Internal process ids (regression guard of the publication cleanup): a word on its own, case-sensitive. "." before an id is part of
# a longer name (file.M<n> is not an id), "-" after M<n> still is (M<n>-<id>).
_B, _E = r"(?<![0-9A-Za-z_.])", r"(?![0-9A-Za-z_])"
TRACES = [
    ("session", re.compile(_B + r"M[0-9]+(?:\.[0-9]+)?" + _E)),
    ("lab-prefix", re.compile(_B + r"m[0-9]-")),
    ("marker", re.compile(_B + r"M[0-9]-[A-Z]+" + _E)),
    ("acceptance", re.compile(_B + r"A[0-9]+[a-z]?" + _E)),
    ("question", re.compile(_B + r"Q[0-9]+[a-z]?" + _E)),
    ("backlog", re.compile(r"(?i)(?<![0-9A-Za-z_])backlog\s+[0-9]+")),
    ("part", re.compile(r"(?<![0-9A-Za-z_])Part [A-Z]" + _E)),
    ("plan", re.compile(r"(?<![0-9A-Za-z_.-])(?:RC|[ROPB])[0-9]+[a-z]?" + _E)),
    ("plan", re.compile(_B + r"o[0-9]+-try")),
    ("plan", re.compile(r"(?<![0-9A-Za-z_])R[F]C(?![A-Za-z0-9_])(?! ?[1-9][0-9]{2,})(?!-compliant)")),
]
# Test ids (the harness and CI print them) are no trace, but each one used must be defined in TEST_IDS_DOC.
# "-T0" is an option (xz), "$T0" / "T0=" a shell variable: neither is a test id.
TEST_ID = re.compile(r"(?<![0-9A-Za-z_.$-])T[0-9]+[a-z]?(?![0-9A-Za-z_=])")
TEST_IDS_DOC = "tests/README.md"
TEST_ID_ROW = re.compile(r"^\|\s*`?(T[0-9]+[a-z]?)`?\s*\|([^|]*)\|")
# Deferred items Z<n> are public (the tables of decisions 0005 and 0013) and no trace, but each one used must be defined
# in one of those tables.
Z_ID = re.compile(r"(?<![0-9A-Za-z_.-])Z[0-9]+[a-z]?(?![0-9A-Za-z_])")
Z_IDS_DOCS = {"0005": "docs/decisions/0005-", "0013": "docs/decisions/0013-"}   # path prefixes: names may change
Z_ID_ROW = re.compile(r"^\|\s*`?(Z[0-9]+[a-z]?)`?\s*\|([^|]*)\|")
Z_ADR_REF = re.compile(r"(?<![0-9A-Za-z_])(?:ADR|decision)\s+(0[0-9]{3})(?![0-9])")
# (token, reason): a token that matches a pattern but is not a process id. One row per token, never a pattern.
TRACE_ALLOW = [
    ("A100", "NVIDIA A100 GPU model (hardware), not an acceptance id"),
    ("P0", "the positive probe of images/debian/tools/apt-pin-test.py (P0 and N<n>), printed by the tool and matched by CI"),
]


def mask(s):
    return s[:2] + "*" * (len(s) - 2)


def text_files(repo, rev):
    """{path: text} of the regular files of rev that the scan reads."""
    tar = subprocess.run(["git", "-C", repo, "archive", "--format=tar", rev], capture_output=True)
    if tar.returncode:
        raise SystemExit("oss-gate: git archive %s: %s" % (rev, tar.stderr.decode(errors="replace").strip()))
    out = {}
    with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
        for m in t:
            if not m.isfile() or m.size > MAX:
                continue
            b = t.extractfile(m).read()
            if b"\0" in b:
                continue
            try:
                out[m.name] = b.decode("utf-8")
            except UnicodeDecodeError:
                continue
    return out


def named_addresses(files):
    """[(address, path prefix)] from the table of docs/compliance/named-addresses.md."""
    rows = []
    for line in files.get(LIST, "").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 2 and cells[0].startswith("`") and ADDR.fullmatch(cells[0].strip("`")):
            rows.append((cells[0].strip("`"), cells[1].strip("`")))
    return rows


def address_rule(files, named):
    bad, allowed = [], 0
    for path, text in sorted(files.items()):
        for n, line in enumerate(text.split("\n"), 1):
            if ALLOW_MARKER in line:
                continue
            for a in ADDR.findall(line):
                if a in ALWAYS or a.startswith(DOC_PREFIXES):
                    continue
                if any(a == na and path.startswith(pre) for na, pre in named):
                    allowed += 1
                    continue
                bad.append("%s:%d %s" % (path, n, mask(a)))
    return bad, allowed


def named_domains(files):
    """{registrable domain} from the first column of docs/compliance/named-domains.md: its first `name`."""
    out = set()
    for line in files.get(DOMAINS_LIST, "").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        m = re.match(r"`([A-Za-z0-9.-]+\.[A-Za-z]+)`", cells[0]) if len(cells) >= 2 else None
        if m:
            out.add(".".join(m.group(1).lower().split(".")[-2:]))
    return out


def domains_in(line):
    """Domain names of one line: hosts of URLs (any TLD), e-mail hosts and bare names (DOMAIN_TLDS)."""
    found = {m.start(1): m.group(1) for m in DOMAIN_URL.finditer(line)}
    for rx in (DOMAIN_MAIL, DOMAIN_BARE):
        for m in rx.finditer(line):
            found.setdefault(m.start(1), m.group(1))
    return [d.rstrip(".").lower() for _, d in sorted(found.items())]


def domain_rule(files, named):
    """[path:line masked] of domains neither reserved nor listed; how many listed ones were found; {listed: uses}."""
    bad, allowed, used = [], 0, {}
    for path, text in sorted(files.items()):
        for n, line in enumerate(text.split("\n"), 1):
            if ALLOW_MARKER in line:
                continue
            for d in domains_in(line):
                labels = d.split(".")
                reg = ".".join(labels[-2:])
                if labels[-1] in RESERVED_TLD or reg in RESERVED_SLD:
                    continue
                if reg in named:
                    allowed += 1
                    used[reg] = used.get(reg, 0) + 1
                    continue
                bad.append("%s:%d %s" % (path, n, mask(d)))
    return bad, allowed, used


def own_rule(files, owners):
    pats = []
    for o in owners:
        login = o.split("/")[0]
        if login:
            pats.append(re.compile(r"(?i)(?<![A-Za-z0-9_-])%s(?![A-Za-z0-9_-])" % re.escape(login)))
            pats.append(re.compile(r"(?i)github\.com[:/]%s/" % re.escape(login)))
    hits = []
    for path, text in sorted(files.items()):
        for n, line in enumerate(text.split("\n"), 1):
            if any(p.search(line) for p in pats):
                hits.append("%s:%d" % (path, n))
    return hits


def old_hash_rule(files, repo):
    where = {}
    for path, text in files.items():
        for n, line in enumerate(text.split("\n"), 1):
            for tok in HEX.findall(line):
                where.setdefault(tok, []).append("%s:%d" % (path, n))
    toks = sorted(where)
    p = subprocess.run(["git", "-C", repo, "cat-file", "--batch-check=%(objecttype)"],
                       input="".join(t + "\n" for t in toks), capture_output=True, text=True)
    hits = []
    for tok, ans in zip(toks, p.stdout.splitlines()):
        if ans in ("commit", "tag") or ans.endswith("ambiguous"):
            hits += ["%s %s (%s)" % (w, mask(tok), ans.split()[-1]) for w in where[tok]]
    return sorted(hits), len(toks)


def trace_rule(files):
    """[(path:line, kind, token)] of every process id outside TRACE_ALLOW; and how many allowed tokens were skipped."""
    allow = {t for t, _ in TRACE_ALLOW}
    hits, allowed = [], 0
    for path, text in sorted(files.items()):
        for n, line in enumerate(text.split("\n"), 1):
            for kind, pat in TRACES:
                for m in pat.finditer(line):
                    if m.group(0) in allow:
                        allowed += 1
                        continue
                    hits.append(("%s:%d" % (path, n), kind, m.group(0)))
    return hits, allowed


def test_id_rule(files):
    """[(path:line, id)] of test ids used in the tree but not defined in TEST_IDS_DOC; and the defined ids."""
    defined = set()
    for line in files.get(TEST_IDS_DOC, "").split("\n"):
        m = TEST_ID_ROW.match(line.strip())
        if m and m.group(2).strip():
            defined.add(m.group(1))
    bad = []
    for path, text in sorted(files.items()):
        for n, line in enumerate(text.split("\n"), 1):
            for tid in TEST_ID.findall(line):
                if tid not in defined:
                    bad.append(("%s:%d" % (path, n), tid))
    return bad, defined


def z_id_rule(files):
    """[(path:line, id, why)] of Z-ids that name no row of exactly one table (Z_IDS_DOCS); {decision: ids}; the docs read."""
    tables, docs = {}, []
    for num, prefix in sorted(Z_IDS_DOCS.items()):
        for p in sorted(x for x in files if x.startswith(prefix) and x.endswith(".md")):
            docs.append(p)
            for line in files[p].split("\n"):
                m = Z_ID_ROW.match(line.strip())
                if m and m.group(2).strip():
                    tables.setdefault(num, set()).add(m.group(1))
    home = lambda path: next((n for n, pre in Z_IDS_DOCS.items() if path.startswith(pre) and path.endswith(".md")), None)
    bad = []
    for path, text in sorted(files.items()):
        own = home(path)
        for n, line in enumerate(text.split("\n"), 1):
            for m in Z_ID.finditer(line):
                zid = m.group(0)
                refs = [r.group(1) for r in Z_ADR_REF.finditer(line[:m.start()]) if r.group(1) in Z_IDS_DOCS]
                adr = refs[-1] if refs else own          # the nearest "ADR 00NN" before it, else the file's own table
                if adr is None:
                    why = "bare id outside decisions 0005/0013 (needs \"decision 00NN, %s\")" % zid
                elif zid not in tables.get(adr, set()):
                    why = "not in the table of decision %s" % adr
                else:
                    continue
                bad.append(("%s:%d" % (path, n), zid, why))
    return bad, tables, docs


def selftest(repo):
    """Probes: every rule must find its planted case and pass the allowed ones."""
    ip = lambda *o: ".".join(map(str, o))   # built at run time: the probes put no address literal into this file
    named = [(ip(10, 0, 2, 2), "tests/")]
    ok = True
    def expect(name, cond):
        nonlocal ok
        print("  probe %s %s" % (name, "ok" if cond else "FAIL"))
        ok &= cond
    bad, allowed = address_rule({"tests/a.sh": "x %s y" % ip(10, 0, 2, 3), "docs/b.md": "host %s" % ip(10, 0, 2, 2)}, named)
    expect("address outside the list (tests/, .3) and the listed address outside its path (docs/)",
           sorted(bad) == ["docs/b.md:1 10******", "tests/a.sh:1 10******"] and allowed == 0)
    bad, allowed = address_rule({"tests/c.sh": "%s %s %s" % (ip(10, 0, 2, 2), ip(192, 0, 2, 7), ip(127, 0, 0, 1)),
                                 "d.md": "%s %s" % (ip(10, 9, 9, 9), ALLOW_MARKER)}, named)
    expect("allowed: listed under its path, RFC 5737, loopback, marker", bad == [] and allowed == 1)
    # domain probes, built at run time so that this file names no domain outside the list
    far, rsd = "unlisted-probe" + "." + "org", "probe-host" + "." + "rs"
    bad, allowed, _ = domain_rule({"docs/a.md": "see %s and https://h.%s/x" % (far, far), "b.sh": "mail ops@%s" % far,
                                   "c.yml": "url: git+ssh://git@%s/r" % rsd}, {"debian.org"})
    expect("domain outside the list: bare, URL host, e-mail host, URL host under a file-extension TLD",
           sorted(bad) == sorted(["docs/a.md:1 " + mask(far), "docs/a.md:1 " + mask("h." + far), "b.sh:1 " + mask(far),
                                  "c.yml:1 " + mask(rsd)]) and allowed == 0)
    ok_lines = "https://snapshot.debian.org/x deb.debian.org www.example.com a@b.invalid h.test main.rs a.sh x.py " \
               "50-x.network 99-y.link README.md v1.2.3 crates.io-index self.ca unit@3.service _@v.efi d@u.raw.xz"
    bad, allowed, used = domain_rule({"ok.md": ok_lines, "m.md": "%s %s" % (far, ALLOW_MARKER)}, {"debian.org"})
    expect("allowed: listed (two hosts), reserved, file names, versions, a name continued by '-', a field, instances, marker",
           bad == [] and allowed == 2 and used == {"debian.org": 2})
    expect("named-domains: the first `name` of each row, its last two labels",
           named_domains({DOMAINS_LIST: "| Domain | Where |\n|---|---|\n| `debian.org` (`deb.debian.org`) | x |\n| `a.b.%s` | y |\n" % "io"})
           == {"debian.org", "b." + "io"})
    expect("own name", own_rule({"x.service": "Documentation=https://github.com/Probe-Owner/r"}, ["probe-owner/r"]) == ["x.service:1"])
    head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    hits, _ = old_hash_rule({"notes.md": "merged in %s" % head[:9]}, repo) if head else ([], 0)
    expect("old hash (HEAD of the repository, 9 characters)", len(hits) == 1)
    # trace probes, built at run time so that this file names no id: one planted id per pattern, then the negatives
    d = "7"
    planted = ["session M%s here" % d, "notes of M%s.2" % d, "unit m%s-probe.service" % d, "marker M%s-PROBE" % d,
               "(A%sb) check" % d, "see Q%s%sa" % (d, d), "fixed in back" + "log 4%s" % d, "Part %s of the plan" % "C",
               "plan item R%sb" % d, "goal O%s" % d, "on RC%s" % d, "layer P%s" % d, "audit B%sa" % d, "branch ci/o%s-try-1" % d, "tag o%s-try-*" % d, "see the R" + "FC section 4", "gateway R" + "FC-000%s" % d]
    hits, _ = trace_rule({"docs/p%d.md" % i: t for i, t in enumerate(planted)})
    found = sorted({h[0].split(":")[0] for h in hits})
    expect("process ids (session, M.N, m-prefix, marker, acceptance, question, backlog, part, plan)",
           found == sorted("docs/p%d.md" % i for i in range(len(planted))))
    neg = "TPM2 LUKS2 an M.2 SSD x86-64 -machine q35 SHA256SUMS nvme0n1 HM2 part B of it on the A100 RFC 5737 R&D RAID1 O_DIRECT gcc -O2 -O3 rc=1 P-states C-states zstd -19 PCIe [A-Z0-9] MZXW6Z2B probe P0 B2B 4CB 8793 proto2-try logo3-try foo2 c0ffee02 RFC 8446 RFC1918 RFC-compliant RFCs RFC 1123"
    hits, allowed = trace_rule({"docs/n.md": neg + " deferred Z%s (a Z-id, no trace)" % d})
    expect("trace negatives and the allowed A100, P0; a Z-id is no trace", hits == [] and allowed == 2)
    t = lambda k: "T%s%s" % (d, k)   # test ids built at run time as well
    doc = "| %s | a defined test |\n| %s |  |\n" % (t("a"), t("b"))
    bad, defined = test_id_rule({TEST_IDS_DOC: doc, "s.sh": "run %s, %s and %s" % (t("a"), t("b"), t("c")),
                                 "v.sh": "%s=$(date) xz -%s x; echo $%s" % (t(""), t(""), t(""))})
    expect("test ids: defined one passes, one without a description and one not defined fail; -T, $T, T= are none",
           defined == {t("a")} and sorted(x[1] for x in bad if x[0] == "s.sh:1") == [t("b"), t("c")]
           and not [x for x in bad if x[0].startswith("v.sh")])
    z = lambda k: "Z%s%s" % (d, k)   # Z-ids built at run time as well
    a5, a13 = "docs/decisions/0005-probe.md", "docs/decisions/0013-probe.md"
    rows = {a5: "| %s | in 0005 and 0013 |\n" % z("1"), a13: "| %s | in 0005 and 0013 |\n| %s | in 0013 only |\n%s and %s here\n"
            % (z("1"), z("2"), z("1"), z("2"))}
    good = {"docs/x.md": "deferred (ADR 0013, %s; ADR 0005, %s)" % (z("2"), z("1")), "docs/w.md": "(decision 0013, %s)" % z("2"), "n.md": "A-%s, -%s, x.%s" % (z(""), z(""), z(""))}
    zb = lambda extra, base=rows: [x[1] for x in z_id_rule(dict(good, **dict(base, **extra)))[0]]
    bad, tables, docs = z_id_rule(dict(good, **rows))
    expect("z-ids: qualified ids of their table and bare ids inside 0005/0013 pass; A-Z, -Z, .Z are none",
           bad == [] and tables == {"0005": {z("1")}, "0013": {z("1"), z("2")}} and docs == [a5, a13])
    expect("z-ids: a bare id outside 0005/0013 fails (ambiguous)", zb({"docs/y.md": "see %s" % z("1")}) == [z("1")])
    expect("z-ids: the qualifier names a table without the id (ADR 0005, Z only in 0013) fails",
           zb({"docs/y.md": "see ADR 0005, %s" % z("2")}) == [z("2")])
    expect("z-ids: decision 0005 with an id only in 0013 fails, decision 0013 passes, bare fails",
           zb({"docs/y.md": "see decision 0005, %s" % z("2")}) == [z("2")] and zb({"docs/y.md": "decision 0013, %s" % z("2")}) == []
           and zb({"docs/y.md": "deferred: %s" % z("2")}) == [z("2")])
    expect("z-ids: a qualifier naming another decision qualifies nothing (inside 0013 its table, outside bare)",
           zb({a13: rows[a13] + "decision 0010, after %s\n" % z("2")}) == [] and zb({"docs/y.md": "decision 0010, %s" % z("2")}) == [z("2")])
    expect("z-ids: an invented id fails", zb({"docs/y.md": "see ADR 0013, %s" % z("99")}) == [z("99")])
    expect("z-ids: a row removed while the id is used fails",
           sorted(zb({}, {a5: rows[a5], a13: "| %s | x |\n%s here\n" % (z("1"), z("2"))})) == [z("2"), z("2"), z("2")])
    expect("z-ids: a row without a description fails", zb({a5: "| %s |  |\n" % z("1")}) == [z("1"), z("1")])
    expect("z-ids: rows outside 0005/0013 define nothing",
           sorted(x[1] for x in z_id_rule({"docs/x.md": good["docs/x.md"], "docs/decisions/0006-other.md": rows[a5]})[0])
           == [z("1"), z("1"), z("2")])
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", default=".")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--own", action="append", default=[])
    ap.add_argument("--history", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    fail = False
    if a.selftest:
        s = selftest(a.repo)
        print("SELFTEST %s" % ("PASS" if s else "FAIL"))
        fail |= not s
    files = text_files(a.repo, a.rev)
    named = named_addresses(files)
    bad, allowed = address_rule(files, named)
    for b in bad:
        print("  address %s" % b)
    print("%s address: %d files, %d not allowed, %d allowed by %s (%s)" % ("FAIL" if bad else "PASS", len(files), len(bad),
          allowed, LIST, ", ".join("%s under %s" % r for r in named) or "no rows"))
    fail |= bool(bad)
    dnamed = named_domains(files)
    dbad, dallowed, dused = domain_rule(files, dnamed)
    for b in dbad:
        print("  domain %s" % b)
    unused = sorted(dnamed - set(dused))
    print("%s domains: %d not allowed, %d listed uses (%s); listed but unused: %s" % ("FAIL" if dbad or unused else "PASS",
          len(dbad), dallowed, ", ".join("%s=%d" % kv for kv in sorted(dused.items())) or "none", ", ".join(unused) or "none"))
    fail |= bool(dbad) or bool(unused)
    own = "skipped"
    if a.own:
        hits = own_rule(files, a.own)
        for h in hits:
            print("  own-name %s" % h)
        if hits and PENDING_RENAME:
            own = "%d EXPECTED" % len(hits)
            print("EXPECTED own-names: %d lines (PENDING_RENAME: the project name is not chosen yet; not failing)" % len(hits))
        else:
            own = str(len(hits))
            print("%s own-names: %d lines" % ("FAIL" if hits else "PASS", len(hits)))
            fail |= bool(hits)
    thits, tallowed = trace_rule(files)
    for where, kind, tok in thits:
        print("  trace %s %s %s" % (where, kind, tok))
    kinds = {}
    for _, kind, _ in thits:
        kinds[kind] = kinds.get(kind, 0) + 1
    print("%s traces: %d ids (%s), %d allowed by TRACE_ALLOW (%s)" % ("FAIL" if thits else "PASS", len(thits),
          ", ".join("%s=%d" % kv for kv in sorted(kinds.items())) or "none", tallowed, ", ".join(t for t, _ in TRACE_ALLOW)))
    fail |= bool(thits)
    tbad, tdef = test_id_rule(files)
    for where, tid in tbad:
        print("  test-id %s %s" % (where, tid))
    print("%s test-ids: %d uses of %d ids not defined in %s (%d defined)" % ("FAIL" if tbad else "PASS", len(tbad),
          len({x[1] for x in tbad}), TEST_IDS_DOC, len(tdef)))
    fail |= bool(tbad)
    zbad, ztab, zdocs = z_id_rule(files)
    for where, zid, why in zbad:
        print("  z-id %s %s %s" % (where, zid, why))
    print("%s z-ids: %d uses of %d ids name no row of exactly one table (%s; %s)" % ("FAIL" if zbad else "PASS", len(zbad),
          len({x[1] for x in zbad}), ", ".join(zdocs) or "no decision 0005/0013",
          ", ".join("%s: %d rows" % (k, len(v)) for k, v in sorted(ztab.items())) or "no rows"))
    fail |= bool(zbad)
    old = "skipped"
    if a.history:
        n = subprocess.run(["git", "-C", a.repo, "rev-list", "--all", "--count"], capture_output=True, text=True).stdout.strip()
        hits, toks = old_hash_rule(files, a.repo)
        for h in hits:
            print("  old-hash %s" % h)
        print("%s old-hashes: %d hex tokens against %s commits, %d name a commit/tag" % ("FAIL" if hits else "PASS", toks, n, len(hits)))
        old = str(len(hits))
        fail |= bool(hits)
    print("OSS-GATE %s rev %s address=%d domains=%d own-names=%s traces=%d test-ids=%d z-ids=%d old-hashes=%s" % ("FAIL" if fail else "PASS",
          a.rev, len(bad), len(dbad), own, len(thits), len(tbad), len(zbad), old))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
