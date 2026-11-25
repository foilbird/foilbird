# Addresses the tree names

The publication check allows only the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), `0.0.0.0`, `127.0.0.1` and `255.255.255.255`. The tree names the addresses below on purpose, each
only under its path; the same address anywhere else, and every other address, is a defect. A new entry is a decision,
recorded here with its reason. The rows are read by `tests/compliance/oss-gate.py` and by the dictionary scan.

| Address | Under | Why | |
|---|---|---|---|
| `10.0.2.2` | `tests/` | the host as a QEMU guest sees it on QEMU's user-mode network (fixed by QEMU, not an address of any network): the harness serves the update channel there and its TLS certificate names it | <!-- osscheck:allow: the entry itself -->
