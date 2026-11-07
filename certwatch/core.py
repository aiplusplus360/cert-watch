"""A dependency-free X.509 reader: enough of DER to answer certificate questions.

The standard library ships TLS, not certificate *inspection*. ``ssl`` will hand
you the peer's DER bytes, and then nothing else — no subject, no validity, no
SAN. That is why most certificate monitors shell out to ``openssl`` or pull in a
crypto package.

This module reads the DER itself. It handles exactly what a monitor needs:
``TBSCertificate`` structure, distinguished names, validity times, basic
constraints and subject alternative names. It deliberately does not verify
signatures; verification belongs to the TLS stack, and a monitor that
re-implements it is a monitor with bugs.

>>> der = bytes.fromhex("3000")
>>> read_tlv(der, 0)[0]
(48, b'', 2)

>>> oid_to_text(bytes.fromhex("2a864886f70d01010b"))
'1.2.840.113549.1.1.11'
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "Certificate",
    "CertificateError",
    "chain_problems",
    "hostname_matches",
    "load_certificates",
    "oid_to_text",
    "parse_certificate",
    "read_tlv",
    "PEM_PATTERN",
]

PEM_PATTERN = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.DOTALL
)

_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}

_OID_SAN = "2.5.29.17"
_OID_BASIC_CONSTRAINTS = "2.5.29.19"
_OID_KEY_USAGE = "2.5.29.15"


class CertificateError(ValueError):
    """Raised when DER cannot be read as an X.509 certificate."""


# --------------------------------------------------------------------------
# DER
# --------------------------------------------------------------------------


def read_tlv(data: bytes, offset: int = 0) -> Tuple[Tuple[int, bytes, int], int]:
    """Read one tag-length-value triple.

    Returns ``((tag, value, header_length), next_offset)``.
    """
    if offset >= len(data):
        raise CertificateError("truncated DER at offset %d" % offset)
    tag = data[offset]
    cursor = offset + 1
    if cursor >= len(data):
        raise CertificateError("truncated DER length at offset %d" % offset)
    first = data[cursor]
    cursor += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise CertificateError("unsupported DER length form at offset %d" % offset)
        if cursor + count > len(data):
            raise CertificateError("truncated DER length at offset %d" % offset)
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    end = cursor + length
    if end > len(data):
        raise CertificateError(
            "DER element at offset %d claims %d bytes, only %d remain"
            % (offset, length, len(data) - cursor)
        )
    return (tag, data[cursor:end], cursor - offset), end


def _children(value: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(value):
        (tag, inner, _header), cursor = read_tlv(value, cursor)
        out.append((tag, inner))
    return out


def oid_to_text(value: bytes) -> str:
    if not value:
        raise CertificateError("empty OID")
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(number))
            number = 0
    return ".".join(parts)


def _decode_string(tag: int, value: bytes) -> str:
    if tag in (0x0C, 0x13, 0x16, 0x1A):  # UTF8, Printable, IA5, Visible
        return value.decode("utf-8", "replace")
    if tag == 0x1E:  # BMPString
        return value.decode("utf-16-be", "replace")
    if tag == 0x14:  # TeletexString, commonly latin-1 in the wild
        return value.decode("latin-1", "replace")
    return value.decode("utf-8", "replace")


def _decode_time(tag: int, value: bytes) -> datetime:
    text = value.decode("ascii", "replace").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
        text = text.replace("+", "+", 1)
        for fmt in ("%y%m%d%H%M%S%z", "%y%m%d%H%M%z"):
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed.astimezone(timezone.utc)
            except ValueError:
                continue
        raise CertificateError("unreadable UTCTime %r" % value)
    for fmt in ("%Y%m%d%H%M%S%z", "%Y%m%d%H%M%z"):
        try:
            return datetime.strptime(text, fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    raise CertificateError("unreadable GeneralizedTime %r" % value)


def _decode_name(value: bytes) -> Tuple[str, Dict[str, List[str]]]:
    """Flatten an X.509 Name into 'CN=a, O=b' and a component map."""
    components: List[str] = []
    mapping: Dict[str, List[str]] = {}
    for tag, rdn in _children(value):
        if tag != 0x31:  # SET
            continue
        for inner_tag, attribute in _children(rdn):
            if inner_tag != 0x30:
                continue
            parts = _children(attribute)
            if len(parts) < 2:
                continue
            oid_tag, oid_value = parts[0]
            if oid_tag != 0x06:
                continue
            name = _OID_NAMES.get(oid_to_text(oid_value), oid_to_text(oid_value))
            text = _decode_string(parts[1][0], parts[1][1])
            components.append("%s=%s" % (name, text))
            mapping.setdefault(name, []).append(text)
    return ", ".join(components), mapping


# --------------------------------------------------------------------------
# Certificate
# --------------------------------------------------------------------------


@dataclass
class Certificate:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial: str = ""
    version: int = 3
    hostnames: List[str] = field(default_factory=list)
    is_ca: bool = False
    path_length: Optional[int] = None
    subject_components: Dict[str, List[str]] = field(default_factory=dict)
    source: str = ""

    # -- questions a monitor actually asks --------------------------------

    def expires_in(self, now: Optional[datetime] = None) -> timedelta:
        reference = now or datetime.now(timezone.utc)
        return self.not_after - reference

    def days_left(self, now: Optional[datetime] = None) -> int:
        return self.expires_in(now).days

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return self.expires_in(now).total_seconds() <= 0

    def is_not_yet_valid(self, now: Optional[datetime] = None) -> bool:
        reference = now or datetime.now(timezone.utc)
        return reference < self.not_before

    def common_name(self) -> str:
        names = self.subject_components.get("CN") or []
        return names[0] if names else ""

    def covers(self, host: str) -> bool:
        for name in self.hostnames:
            if hostname_matches(name, host):
                return True
        return False

    def lifetime_days(self) -> int:
        return (self.not_after - self.not_before).days

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "days_left": self.days_left(),
            "serial": self.serial,
            "hostnames": list(self.hostnames),
            "is_ca": self.is_ca,
            "source": self.source,
        }


def parse_certificate(der: bytes, source: str = "") -> Certificate:
    """Parse one DER certificate."""
    (tag, body, _), _end = read_tlv(der, 0)
    if tag != 0x30:
        raise CertificateError("a certificate starts with SEQUENCE, not 0x%02x" % tag)
    parts = _children(body)
    if len(parts) < 3:
        raise CertificateError("certificate SEQUENCE has %d elements, expected 3" % len(parts))
    tbs_tag, tbs = parts[0]
    if tbs_tag != 0x30:
        raise CertificateError("TBSCertificate is not a SEQUENCE")

    fields = _children(tbs)
    position = 0
    version = 1
    if fields and fields[0][0] == 0xA0:
        inner = _children(fields[0][1])
        if inner and inner[0][0] == 0x02:
            version = int.from_bytes(inner[0][1], "big") + 1
        position = 1

    if position >= len(fields) or fields[position][0] != 0x02:
        raise CertificateError("missing serial number")
    serial = binascii.hexlify(fields[position][1]).decode("ascii")
    serial = serial.lstrip("0") or "0"
    position += 1
    position += 1  # signature algorithm

    if position + 3 >= len(fields):
        raise CertificateError("TBSCertificate is truncated")
    issuer_tag, issuer_value = fields[position]
    issuer, _issuer_map = _decode_name(issuer_value)
    position += 1

    validity_tag, validity_value = fields[position]
    if validity_tag != 0x30:
        raise CertificateError("validity is not a SEQUENCE")
    times = _children(validity_value)
    if len(times) < 2:
        raise CertificateError("validity needs notBefore and notAfter")
    not_before = _decode_time(times[0][0], times[0][1])
    not_after = _decode_time(times[1][0], times[1][1])
    position += 1

    subject_tag, subject_value = fields[position]
    subject, subject_map = _decode_name(subject_value)
    position += 1

    hostnames: List[str] = []
    is_ca = False
    path_length: Optional[int] = None

    for tag, value in fields[position:]:
        if tag != 0xA3:  # [3] EXPLICIT extensions
            continue
        inner = _children(value)
        if not inner:
            continue
        for ext_tag, ext_value in _children(inner[0][1]):
            if ext_tag != 0x30:
                continue
            pieces = _children(ext_value)
            if len(pieces) < 2 or pieces[0][0] != 0x06:
                continue
            oid = oid_to_text(pieces[0][1])
            payload = pieces[-1][1] if pieces[-1][0] == 0x04 else b""
            if oid == _OID_SAN and payload:
                hostnames.extend(_read_san(payload))
            elif oid == _OID_BASIC_CONSTRAINTS and payload:
                is_ca, path_length = _read_basic_constraints(payload)

    if not hostnames:
        common = subject_map.get("CN") or []
        hostnames = [name for name in common if name]

    return Certificate(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        version=version,
        hostnames=hostnames,
        is_ca=is_ca,
        path_length=path_length,
        subject_components=subject_map,
        source=source,
    )


def _read_san(payload: bytes) -> List[str]:
    out: List[str] = []
    (tag, body, _), _end = read_tlv(payload, 0)
    if tag != 0x30:
        return out
    for name_tag, name_value in _children(body):
        if name_tag == 0x82:  # dNSName
            out.append(name_value.decode("ascii", "replace"))
        elif name_tag == 0x87:  # iPAddress
            if len(name_value) == 4:
                out.append(".".join(str(b) for b in name_value))
    return out


def _read_basic_constraints(payload: bytes) -> Tuple[bool, Optional[int]]:
    (tag, body, _), _end = read_tlv(payload, 0)
    if tag != 0x30:
        return False, None
    is_ca = False
    path_length: Optional[int] = None
    for inner_tag, inner_value in _children(body):
        if inner_tag == 0x01:
            is_ca = bool(inner_value and inner_value[0])
        elif inner_tag == 0x02:
            path_length = int.from_bytes(inner_value, "big")
    return is_ca, path_length


def load_certificates(data: bytes, source: str = "") -> List[Certificate]:
    """Load every certificate in a PEM bundle, or one DER certificate."""
    if b"-----BEGIN" in data:
        out: List[Certificate] = []
        for index, match in enumerate(PEM_PATTERN.finditer(data), 1):
            try:
                body = re.sub(rb"\s+", b"", match.group(1))
                der = base64.b64decode(body, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise CertificateError("%s: PEM block %d is not valid base64: %s"
                                       % (source, index, exc))
            out.append(parse_certificate(der, source or "pem#%d" % index))
        if not out:
            raise CertificateError("%s: no CERTIFICATE block found" % (source or "input"))
        return out
    return [parse_certificate(data, source or "der")]


def hostname_matches(pattern: str, host: str) -> bool:
    """RFC 6125 matching: wildcard only in the left-most label, one label only.

    >>> hostname_matches("*.example.com", "api.example.com")
    True
    >>> hostname_matches("*.example.com", "a.b.example.com")
    False
    >>> hostname_matches("api.example.com", "API.example.com")
    True
    """
    pattern = pattern.strip().rstrip(".").lower()
    host = host.strip().rstrip(".").lower()
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix:
            return False
        head, _, tail = host.partition(".")
        return bool(head) and tail == suffix and "." not in head
    return False


# --------------------------------------------------------------------------
# Chain reasoning
# --------------------------------------------------------------------------


@dataclass
class ChainProblem:
    code: str
    severity: str
    message: str
    index: int

    def __str__(self) -> str:
        return "[%s] %s" % (self.severity, self.message)


def chain_problems(certificates: Sequence[Certificate],
                   now: Optional[datetime] = None) -> List[ChainProblem]:
    """Report ordering, gap and validity problems in a presented chain."""
    problems: List[ChainProblem] = []
    if not certificates:
        return problems
    reference = now or datetime.now(timezone.utc)
    for index, certificate in enumerate(certificates):
        if certificate.is_expired(reference):
            problems.append(ChainProblem(
                "expired", "error",
                "certificate %d (%s) expired %d day(s) ago"
                % (index, certificate.common_name(), -certificate.days_left(reference)),
                index))
        elif certificate.is_not_yet_valid(reference):
            problems.append(ChainProblem(
                "not-yet-valid", "error",
                "certificate %d (%s) is not valid until %s"
                % (index, certificate.common_name(), certificate.not_before.date()),
                index))

    for index in range(len(certificates) - 1):
        child, parent = certificates[index], certificates[index + 1]
        if child.issuer != parent.subject:
            problems.append(ChainProblem(
                "chain-gap", "error",
                "certificate %d is issued by %r but certificate %d is %r"
                % (index, child.issuer, index + 1, parent.subject),
                index))

    if len(certificates) > 1 and certificates[0].is_ca:
        problems.append(ChainProblem(
            "leaf-is-ca", "high",
            "the first certificate in the chain is a CA certificate",
            0))

    for index, certificate in enumerate(certificates[1:], 1):
        if not certificate.is_ca:
            problems.append(ChainProblem(
                "non-ca-in-chain", "high",
                "certificate %d (%s) is not marked as a CA"
                % (index, certificate.common_name()),
                index))

    leaf = certificates[0]
    for index in range(1, len(certificates)):
        if certificates[index].not_after < leaf.not_after:
            problems.append(ChainProblem(
                "intermediate-expires-first", "high",
                "certificate %d expires before the leaf, so renewing the leaf "
                "will not fix the chain" % index,
                index))

    if len(certificates) == 1 and leaf.issuer != leaf.subject:
        problems.append(ChainProblem(
            "incomplete-chain", "high",
            "only the leaf certificate was presented; clients must fetch the "
            "intermediate themselves, which fails on many mobile stacks",
            0))

    if leaf.lifetime_days() > 398:
        problems.append(ChainProblem(
            "long-validity", "medium",
            "leaf lifetime is %d days; public CAs are limited to 398"
            % leaf.lifetime_days(),
            0))

    return problems
