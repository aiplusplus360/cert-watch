"""Read X.509 certificates without a crypto dependency."""

__version__ = "0.1.0"

from .core import (
    Certificate,
    CertificateError,
    chain_problems,
    hostname_matches,
    load_certificates,
    oid_to_text,
    parse_certificate,
    read_tlv,
)

__all__ = [
    "Certificate",
    "CertificateError",
    "chain_problems",
    "hostname_matches",
    "load_certificates",
    "oid_to_text",
    "parse_certificate",
    "read_tlv",
]
