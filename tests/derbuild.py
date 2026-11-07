"""Build small but structurally valid DER certificates for the tests.

The point of these fixtures is to exercise the *reader*: the DER layout, the
name flattening, the time encodings and the extension parsing. Signatures are
not verified anywhere in this package, so a placeholder signature is honest —
and it keeps the fixtures readable.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

RSA_SHA256 = "1.2.840.113549.1.1.11"


def tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        encoded = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + encoded + value


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(parts))


def integer(number: int) -> bytes:
    if number == 0:
        return tlv(0x02, b"\x00")
    raw = number.to_bytes((number.bit_length() + 8) // 8, "big")
    return tlv(0x02, raw)


def boolean(value: bool) -> bytes:
    return tlv(0x01, b"\xff" if value else b"\x00")


def oid(text: str) -> bytes:
    parts = [int(piece) for piece in text.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        out.extend(reversed(chunk))
    return tlv(0x06, bytes(out))


def utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode("utf-8"))


def utctime(moment: datetime) -> bytes:
    return tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def gentime(moment: datetime) -> bytes:
    return tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def name(common_name: str = "", organization: str = "") -> bytes:
    parts = []
    if organization:
        parts.append(set_of(seq(oid("2.5.4.10"), utf8(organization))))
    if common_name:
        parts.append(set_of(seq(oid("2.5.4.3"), utf8(common_name))))
    return seq(*parts)


def spki() -> bytes:
    return seq(seq(oid("1.2.840.113549.1.1.1"), tlv(0x05, b"")),
               tlv(0x03, b"\x00" + b"\x30" * 32))


def san(*dns_names: str) -> bytes:
    return seq(*[tlv(0x82, item.encode("ascii")) for item in dns_names])


def basic_constraints(is_ca: bool, path_length: int = None) -> bytes:
    parts = [boolean(is_ca)]
    if path_length is not None:
        parts.append(integer(path_length))
    return seq(*parts)


def extension(oid_text: str, value: bytes, critical: bool = False) -> bytes:
    parts = [oid(oid_text)]
    if critical:
        parts.append(boolean(True))
    parts.append(tlv(0x04, value))
    return seq(*parts)


def extensions(*items: bytes) -> bytes:
    return tlv(0xA3, seq(*items))


def certificate(subject: str, issuer: str, not_before: datetime,
                not_after: datetime, dns_names=(), is_ca: bool = False,
                serial: int = 1, path_length: int = None,
                use_generalized_time: bool = False) -> bytes:
    time_encoder = gentime if use_generalized_time else utctime
    ext_items = [extension("2.5.29.19", basic_constraints(is_ca, path_length), True)]
    if dns_names:
        ext_items.append(extension("2.5.29.17", san(*dns_names)))
    tbs = seq(
        tlv(0xA0, integer(2)),
        integer(serial),
        seq(oid(RSA_SHA256), tlv(0x05, b"")),
        name(issuer, "Example Org"),
        seq(time_encoder(not_before), time_encoder(not_after)),
        name(subject, "Example Org"),
        spki(),
        extensions(*ext_items),
    )
    signature = tlv(0x03, b"\x00" + b"\xAB" * 32)
    return seq(tbs, seq(oid(RSA_SHA256), tlv(0x05, b"")), signature)


def self_signed(common_name: str, days: int = 90, **kwargs) -> bytes:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return certificate(
        common_name,
        common_name,
        now - timedelta(days=1),
        now + timedelta(days=days),
        **kwargs
    )


def to_pem(der: bytes) -> str:
    body = base64.encodebytes(der).decode("ascii").strip()
    return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % body
