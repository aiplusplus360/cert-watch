import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))

import derbuild
from certwatch.core import (
    CertificateError,
    chain_problems,
    hostname_matches,
    load_certificates,
    oid_to_text,
    parse_certificate,
    read_tlv,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def build_cert(subject="api.example.com", issuer=None, days=90, dns=("api.example.com",),
               is_ca=False, serial=1, start=NOW, lifetime=None):
    issuer = issuer if issuer is not None else subject
    not_after = start + timedelta(days=lifetime if lifetime is not None else days)
    return derbuild.certificate(subject, issuer, start - timedelta(days=1), not_after,
                                dns_names=dns, is_ca=is_ca, serial=serial)


def leaf(days=90, names=("api.example.com",), subject="api.example.com"):
    return parse_certificate(build_cert(subject=subject, days=days, dns=names))


class DerReaderTests(unittest.TestCase):
    def test_reads_a_short_form_length(self):
        (tag, value, header), end = read_tlv(bytes.fromhex("3003020101"))
        self.assertEqual(tag, 0x30)
        self.assertEqual(value, bytes.fromhex("020101"))
        self.assertEqual(header, 2)
        self.assertEqual(end, 5)

    def test_reads_a_long_form_length(self):
        payload = b"\x00" * 200
        blob = derbuild.tlv(0x04, payload)
        (tag, value, _header), end = read_tlv(blob)
        self.assertEqual(tag, 0x04)
        self.assertEqual(len(value), 200)
        self.assertEqual(end, len(blob))

    def test_truncated_input_is_an_error(self):
        with self.assertRaises(CertificateError):
            read_tlv(bytes.fromhex("3005") + b"\x01")

    def test_oid_decoding(self):
        self.assertEqual(oid_to_text(bytes.fromhex("2a864886f70d01010b")),
                         "1.2.840.113549.1.1.11")

    def test_oid_decoding_of_a_long_arc(self):
        encoded = b"\x55\x1d\x13"  # 2.5.29.19 (basicConstraints)
        self.assertEqual(oid_to_text(encoded), "2.5.29.19")


class CertificateTests(unittest.TestCase):
    def test_subject_and_issuer_are_flattened(self):
        certificate = parse_certificate(build_cert(subject="api.example.com",
                                                   issuer="Example CA"))
        self.assertIn("CN=api.example.com", certificate.subject)
        self.assertIn("O=Example Org", certificate.subject)
        self.assertEqual(certificate.common_name(), "api.example.com")
        self.assertIn("CN=Example CA", certificate.issuer)

    def test_validity_dates(self):
        certificate = parse_certificate(build_cert(days=30))
        self.assertEqual(certificate.not_before.date(), NOW.date() - timedelta(days=1))
        self.assertEqual(certificate.not_after.date(), NOW.date() + timedelta(days=30))
        self.assertAlmostEqual(certificate.lifetime_days(), 31, delta=1)

    def test_generalized_time_is_understood(self):
        der = derbuild.certificate("a", "a",
                                   datetime(2050, 1, 1, tzinfo=timezone.utc),
                                   datetime(2051, 1, 1, tzinfo=timezone.utc),
                                   dns_names=("a",), use_generalized_time=True)
        certificate = parse_certificate(der)
        self.assertEqual(certificate.not_after.year, 2051)

    def test_san_names_are_read(self):
        certificate = leaf(names=("api.example.com", "www.example.com"))
        self.assertEqual(certificate.hostnames,
                         ["api.example.com", "www.example.com"])

    def test_cn_is_the_fallback_when_there_is_no_san(self):
        der = derbuild.certificate("legacy.example.com", "legacy.example.com",
                                   NOW - timedelta(days=1), NOW + timedelta(days=10))
        certificate = parse_certificate(der)
        self.assertEqual(certificate.hostnames, ["legacy.example.com"])

    def test_basic_constraints_are_read(self):
        der = build_cert(is_ca=True, dns=())
        self.assertTrue(parse_certificate(der).is_ca)

    def test_leaf_is_not_a_ca(self):
        self.assertFalse(leaf().is_ca)

    def test_version_is_read(self):
        self.assertEqual(parse_certificate(build_cert()).version, 3)

    def test_serial_is_hex(self):
        self.assertEqual(parse_certificate(build_cert(serial=255)).serial, "ff")

    def test_expiry_helpers(self):
        certificate = leaf(days=10)
        self.assertFalse(certificate.is_expired(NOW))
        self.assertTrue(certificate.is_expired(NOW + timedelta(days=11)))
        self.assertTrue(certificate.is_not_yet_valid(NOW - timedelta(days=5)))

    def test_days_left_uses_the_supplied_clock(self):
        certificate = leaf(days=10)
        reference = certificate.not_after - timedelta(days=4)
        self.assertEqual(certificate.days_left(reference), 4)

    def test_garbage_is_rejected(self):
        with self.assertRaises(CertificateError):
            parse_certificate(b"\x01\x02\x03")


class PemTests(unittest.TestCase):
    def test_single_pem_certificate(self):
        pem = derbuild.to_pem(build_cert())
        certificates = load_certificates(pem.encode("ascii"), "leaf.pem")
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0].common_name(), "api.example.com")

    def test_bundle_is_read_in_order(self):
        pem = (derbuild.to_pem(build_cert(subject="leaf.example.com",
                                          issuer="Intermediate CA",
                                          dns=("leaf.example.com",)))
               + derbuild.to_pem(build_cert(subject="Intermediate CA",
                                            issuer="Root CA", dns=(),
                                            is_ca=True)))
        certificates = load_certificates(pem.encode("ascii"), "bundle.pem")
        self.assertEqual([c.common_name() for c in certificates],
                         ["leaf.example.com", "Intermediate CA"])

    def test_bad_base64_is_reported(self):
        with self.assertRaises(CertificateError):
            load_certificates(
                b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")

    def test_missing_block_is_reported(self):
        with self.assertRaises(CertificateError):
            load_certificates(b"nothing to see")


class HostnameTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(hostname_matches("api.example.com", "api.example.com"))

    def test_case_insensitive(self):
        self.assertTrue(hostname_matches("API.example.com", "api.example.com"))

    def test_wildcard_matches_one_label(self):
        self.assertTrue(hostname_matches("*.example.com", "api.example.com"))
        self.assertFalse(hostname_matches("*.example.com", "a.b.example.com"))

    def test_wildcard_does_not_match_the_bare_domain(self):
        self.assertFalse(hostname_matches("*.example.com", "example.com"))

    def test_wildcard_in_the_middle_is_not_valid(self):
        self.assertFalse(hostname_matches("api.*.com", "api.example.com"))

    def test_trailing_dot_is_ignored(self):
        self.assertTrue(hostname_matches("api.example.com.", "api.example.com"))

    def test_certificate_covers_its_names(self):
        certificate = leaf(names=("*.example.com",))
        self.assertTrue(certificate.covers("shop.example.com"))
        self.assertFalse(certificate.covers("example.com"))


class ChainTests(unittest.TestCase):
    def _chain(self, leaf_days=90, intermediate_days=365, with_root=True):
        leaf_cert = parse_certificate(build_cert(subject="leaf.example.com",
                                                 issuer="Intermediate CA",
                                                 days=leaf_days,
                                                 dns=("leaf.example.com",)))
        intermediate = parse_certificate(build_cert(subject="Intermediate CA",
                                                    issuer="Root CA",
                                                    days=intermediate_days,
                                                    dns=(), is_ca=True))
        chain = [leaf_cert, intermediate]
        if with_root:
            chain.append(parse_certificate(build_cert(subject="Root CA",
                                                      issuer="Root CA",
                                                      days=3650,
                                                      dns=(), is_ca=True)))
        return chain

    def test_a_correct_chain_has_no_problems(self):
        self.assertEqual(chain_problems(self._chain(), NOW), [])

    def test_missing_intermediate_is_reported(self):
        problems = chain_problems([self._chain()[0]], NOW)
        self.assertIn("incomplete-chain", [p.code for p in problems])

    def test_chain_gap_is_reported(self):
        chain = self._chain()
        chain[1] = parse_certificate(build_cert(subject="Other CA",
                                                issuer="Root CA", dns=(), is_ca=True))
        self.assertIn("chain-gap", [p.code for p in chain_problems(chain, NOW)])

    def test_expired_intermediate_is_reported(self):
        chain = self._chain(intermediate_days=-1)
        codes = [p.code for p in chain_problems(chain, NOW)]
        self.assertIn("expired", codes)

    def test_leaf_marked_as_ca_is_reported(self):
        chain = self._chain()
        chain[0] = parse_certificate(build_cert(subject="leaf.example.com",
                                                issuer="Intermediate CA",
                                                dns=("leaf.example.com",), is_ca=True))
        self.assertIn("leaf-is-ca", [p.code for p in chain_problems(chain, NOW)])

    def test_non_ca_in_the_chain_is_reported(self):
        chain = self._chain()
        chain[1] = parse_certificate(build_cert(subject="Intermediate CA",
                                                issuer="Root CA", dns=()))
        self.assertIn("non-ca-in-chain", [p.code for p in chain_problems(chain, NOW)])

    def test_intermediate_expiring_before_the_leaf_is_reported(self):
        chain = self._chain(leaf_days=400, intermediate_days=100)
        self.assertIn("intermediate-expires-first",
                      [p.code for p in chain_problems(chain, NOW)])

    def test_overlong_leaf_lifetime_is_reported(self):
        chain = self._chain(leaf_days=500)
        self.assertIn("long-validity", [p.code for p in chain_problems(chain, NOW)])

    def test_empty_chain_is_empty(self):
        self.assertEqual(chain_problems([], NOW), [])


if __name__ == "__main__":
    unittest.main()
