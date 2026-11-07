# cert-watch

**Read X.509 certificates with no crypto dependency: expiry, names, and whether the chain on the wire is actually the chain a client can build.**

[![CI](https://github.com/aiplusplus360/cert-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/aiplusplus360/cert-watch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```console
$ cert-watch check api.example.com
api.example.com:443  OK
  subject : O=Example Org, CN=api.example.com
  issuer  : O=Example Org, CN=Example Intermediate CA
  valid   : 2026-11-06 -> 2026-12-11 (33 day(s) left)
  names   : api.example.com, *.api.example.com
  chain   : 2 certificates
    1. O=Example Org, CN=Example Intermediate CA  (299 day(s))
  [high] only the leaf certificate was presented; clients must fetch the
         intermediate themselves, which fails on many mobile stacks
```

---

## Why this exists

`openssl x509 -enddate -noout` tells you one number. The failures that actually page someone are not that number:

- **The chain is incomplete.** The leaf is valid and browsers work because they cache or fetch the intermediate. Android and some Java clients do not, and they fail intermittently for a subset of users.
- **The intermediate expires before the leaf.** You renew the leaf, the alarm goes green, and the outage happens on the intermediate's date instead.
- **The leaf is a CA certificate.** Nothing complains until something trusts it too much.
- **The chain is out of order.** The host sends leaf-root-intermediate and expects clients to sort it out.
- **A public-CA limit is exceeded.** 398 days is not a suggestion; some clients reject longer lifetimes outright.

And the observability question: how do you check any of this from a box where the only thing you are allowed to install is Python?

`ssl` will hand you the peer's DER bytes and then stop. Everything else in the ecosystem reaches for `cryptography` (a wheel with a Rust toolchain behind it) or shells out to `openssl` (a CLI whose output format changes between versions). This project reads the DER.

## Install

No dependencies. Python 3.9+.

```bash
pip install git+https://github.com/aiplusplus360/cert-watch
```

## Usage

```bash
cert-watch check example.com                     # connect and inspect the chain
cert-watch check example.com --port 8443 --timeout 5
cert-watch check expired.example.com --insecure   # inspect what verification rejects
cert-watch parse chain.pem                        # PEM bundle or a single DER file
cert-watch parse leaf.der --format json
cert-watch parse chain.pem --warn-days 45 --fail-on warn
```

Exit codes: `0` fine, `1` at or above `--fail-on` (`error` by default; `warn` also fails when the leaf is inside `--warn-days`), `2` unreadable input or a failed connection.

## What it checks

**Validity** — expired, not yet valid, days remaining against a warning threshold.

**Names** — SAN `dNSName` and `iPAddress` entries, falling back to `CN` only when there is no SAN (as RFC 6125 requires). Wildcards match exactly one label and never the bare domain:

```console
$ cert-watch check a.b.example.com
  [error] certificate names (*.example.com) do not cover a.b.example.com
```

`*.example.com` covers `shop.example.com`. It does not cover `example.com`, and it does not cover `a.b.example.com`. That is the rule clients enforce, so it is the rule here.

**Chain construction** — issuer/subject continuity between consecutive certificates, an incomplete chain, a leaf marked as CA, a non-CA in the chain, and an intermediate that expires before the leaf.

**Policy** — leaf lifetime above 398 days.

## The DER reader

`certwatch/core.py` implements TLV parsing (short and long length forms), OID decoding, `UTCTime`/`GeneralizedTime`, `Name` flattening (`CN=…, O=…`), and the three extensions that matter: `subjectAltName`, `basicConstraints`, `keyUsage`.

It deliberately does **not** verify signatures. Signature verification belongs to the TLS stack that already did it; a monitor that re-implements it is a monitor with a second set of bugs and a false sense of assurance. This tool answers "what does this certificate claim, and can a client build a path to a trust anchor from what was sent?"

The parser is tested against DER built by an encoder in `tests/derbuild.py`, so the fixtures exercise real TLV layout rather than a mock.

## Library use

```python
from certwatch import load_certificates, chain_problems, hostname_matches

chain = load_certificates(open("chain.pem", "rb").read(), "chain.pem")
for problem in chain_problems(chain):
    print(problem.severity, problem.code, problem.message)

print(hostname_matches("*.example.com", "api.example.com"))  # True
```

## Tests

```bash
python -m unittest discover -s tests -v
```

37 tests: TLV edge cases, OID arcs, both time encodings, SAN and CN fallback, wildcard rules, chain gap/ordering/expiry logic, and CLI-free use of the committed `examples/` fixtures.
