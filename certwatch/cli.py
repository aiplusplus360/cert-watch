"""Command line interface for cert-watch."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from .core import (
    Certificate,
    CertificateError,
    chain_problems,
    load_certificates,
    parse_certificate,
)

__version__ = "0.1.0"


def _fetch_chain(host: str, port: int, timeout: float,
                 insecure: bool) -> List[Certificate]:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    certificates: List[Certificate] = []
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            leaf_der = tls.getpeercert(binary_form=True)
            if leaf_der:
                certificates.append(parse_certificate(leaf_der, "%s:%d" % (host, port)))
            chain = getattr(tls, "get_unverified_chain", None)
            if callable(chain):
                try:
                    for index, entry in enumerate(chain() or [], 1):
                        blob = entry if isinstance(entry, (bytes, bytearray)) else None
                        if blob is None and hasattr(entry, "public_bytes"):
                            continue
                        if blob:
                            certificates.append(
                                parse_certificate(bytes(blob), "%s:%d#%d"
                                                  % (host, port, index)))
                except (NotImplementedError, ValueError):
                    pass
    return certificates


def _format_report(host: str, certificates: Sequence[Certificate],
                   problems, warn_days: int) -> str:
    lines: List[str] = []
    leaf = certificates[0] if certificates else None
    if leaf is None:
        return "no certificate received from %s" % host
    status = "EXPIRED" if leaf.is_expired() else "OK"
    lines.append("%s  %s" % (host, status))
    lines.append("  subject : %s" % leaf.subject)
    lines.append("  issuer  : %s" % leaf.issuer)
    lines.append("  valid   : %s -> %s (%d day(s) left)"
                 % (leaf.not_before.date(), leaf.not_after.date(), leaf.days_left()))
    lines.append("  names   : %s" % (", ".join(leaf.hostnames) or "-"))
    if len(certificates) > 1:
        lines.append("  chain   : %d certificates" % len(certificates))
        for index, certificate in enumerate(certificates[1:], 1):
            lines.append("    %d. %s  (%d day(s))" % (index, certificate.subject,
                                                     certificate.days_left()))
    else:
        lines.append("  chain   : leaf only")
    if problems:
        lines.append("")
        for problem in problems:
            lines.append("  [%s] %s" % (problem.severity, problem.message))
    if not leaf.is_expired() and leaf.days_left() <= warn_days:
        lines.append("  [warn] expires within %d day(s)" % warn_days)
    return "\n".join(lines)


def _load(paths: Sequence[str]) -> List[Certificate]:
    certificates: List[Certificate] = []
    for path in paths:
        with open(path, "rb") as handle:
            data = handle.read()
        certificates.extend(load_certificates(data, path))
    return certificates


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--warn-days", type=int, default=30,
                        help="warn when the leaf expires within this many days")
    common.add_argument("--fail-on", choices=("error", "warn", "none"),
                        default="error")
    common.add_argument("--format", choices=("table", "json"), default="table")

    parser = argparse.ArgumentParser(
        prog="cert-watch",
        description="Check certificate expiry, names and chain construction.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", parents=[common],
                           help="connect to a host and inspect its chain")
    check.add_argument("host")
    check.add_argument("--port", type=int, default=443)
    check.add_argument("--timeout", type=float, default=10.0)
    check.add_argument("--insecure", action="store_true",
                       help="skip verification so an expired or self-signed chain "
                            "can still be inspected")

    files = sub.add_parser("parse", parents=[common],
                           help="inspect PEM or DER files")
    files.add_argument("paths", nargs="+")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2

    try:
        if args.command == "check":
            certificates = _fetch_chain(args.host, args.port, args.timeout,
                                        args.insecure)
            label = "%s:%d" % (args.host, args.port)
        else:
            certificates = _load(args.paths)
            label = ", ".join(args.paths)
    except (CertificateError, OSError, ssl.SSLError) as exc:
        sys.stderr.write("cert-watch: %s\n" % exc)
        return 2

    if not certificates:
        sys.stderr.write("cert-watch: no certificate found for %s\n" % label)
        return 2

    problems = chain_problems(certificates)
    leaf = certificates[0]
    if args.command == "check" and not leaf.covers(args.host):
        problems = list(problems)
        problems.append(type(problems[0])(
            "name-mismatch", "error",
            "certificate names (%s) do not cover %s"
            % (", ".join(leaf.hostnames) or "none", args.host), 0))

    if args.format == "json":
        print(json.dumps({
            "host": label,
            "certificates": [c.as_dict() for c in certificates],
            "problems": [
                {"code": p.code, "severity": p.severity, "message": p.message,
                 "index": p.index}
                for p in problems
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))
    else:
        print(_format_report(label, certificates, problems, args.warn_days))

    if args.fail_on == "none":
        return 0
    if args.fail_on == "warn":
        if problems or leaf.days_left() <= args.warn_days:
            return 1
        return 0
    return 1 if any(p.severity == "error" for p in problems) else 0
