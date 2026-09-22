"""
X.509 chain parsing.

Two sources. The committed stream fixtures carry real chains from badssl.com,
which is what proves the framing walk works on traffic. Certificates with
particular key types are generated here, because the corpus contains RSA and
ECDSA only -- no Ed25519, no DSA -- and the key-size reporting has to be right
for the ones it does not happen to contain.
"""
import datetime
import pathlib

import pytest

cryptography = pytest.importorskip("cryptography")

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import (ec,       # noqa: E402
                                                       ed25519, rsa)
from cryptography.x509.oid import NameOID                        # noqa: E402

from pcapscan.certificates import (MAX_CERTIFICATE_LEN,          # noqa: E402
                                   MAX_CHAIN_LENGTH,
                                   describe_certificate, iter_der,
                                   parse_certificate_message)
from pcapscan.sessions import iter_sessions                      # noqa: E402

pytestmark = pytest.mark.smoke

STREAMS = pathlib.Path(__file__).resolve().parent / "fixtures" / "streams"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def self_signed(key, common_name="example.test", hash_algorithm=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    start = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(0x0123456789)
               .not_valid_before(start)
               .not_valid_after(start + datetime.timedelta(days=90))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                              critical=True)
               .add_extension(x509.SubjectAlternativeName(
                   [x509.DNSName(common_name)]), critical=False))
    if hash_algorithm is None and not isinstance(key, ed25519.Ed25519PrivateKey):
        hash_algorithm = hashes.SHA256()
    return builder.sign(key, hash_algorithm).public_bytes(
        serialization.Encoding.DER)


def tls12_message(*ders):
    entries = b''.join(len(d).to_bytes(3, 'big') + d for d in ders)
    return len(entries).to_bytes(3, 'big') + entries


def tls13_message(*ders, context=b''):
    entries = b''.join(len(d).to_bytes(3, 'big') + d + b'\x00\x00'
                       for d in ders)
    return (bytes([len(context)]) + context
            + len(entries).to_bytes(3, 'big') + entries)


# --------------------------------------------------------------------------
# the message framing
# --------------------------------------------------------------------------
def test_tls12_chain_is_walked():
    a, b = bytes(range(100)), bytes(range(50))
    assert list(iter_der(tls12_message(a, b))) == [a, b]


def test_tls13_chain_is_walked_past_its_per_entry_extensions():
    """
    TLS 1.3 gives every entry a trailing extension block and puts a request
    context in front of the list. A walker written for TLS 1.2 reads the
    context byte as part of the length and desynchronises immediately.
    """
    a, b = bytes(range(100)), bytes(range(50))
    assert list(iter_der(tls13_message(a, b))) == [a, b]
    assert list(iter_der(tls13_message(a, context=b'\x01\x02'))) == [a]


def test_the_two_framings_are_told_apart_by_arithmetic():
    """
    Not by the negotiated version, which is not always known where the
    message is parsed. TLS 1.2's list length accounts for every byte after
    itself; TLS 1.3's does not, because of the context prefix.
    """
    der = bytes(range(64))
    assert list(iter_der(tls12_message(der))) == [der]
    assert list(iter_der(tls13_message(der))) == [der]


def test_a_message_that_is_not_a_chain_yields_nothing():
    assert list(iter_der(b'')) == []
    assert list(iter_der(b'\x00\x00')) == []
    assert list(iter_der(b'\xff\xff\xff' + b'\x00' * 10)) == []


def test_an_entry_longer_than_the_message_stops_the_walk():
    blob = b'\x00\x00\x20' + b'\x00\xff\xff' + b'\x00' * 20
    assert list(iter_der(blob)) == []


def test_the_chain_length_is_capped():
    tiny = b'\x01'
    blob = tls12_message(*[tiny] * (MAX_CHAIN_LENGTH + 5))
    assert len(list(iter_der(blob))) == MAX_CHAIN_LENGTH
    assert MAX_CERTIFICATE_LEN < (1 << 24)


# --------------------------------------------------------------------------
# key sizes -- the field CycloneDX needs and the handshake never carries
# --------------------------------------------------------------------------
@pytest.mark.parametrize("key,algorithm,bits", [
    (rsa.generate_private_key(public_exponent=65537, key_size=2048),
     'RSA', 2048),
    (ec.generate_private_key(ec.SECP256R1()), 'EC', 256),
    (ec.generate_private_key(ec.SECP384R1()), 'EC', 384),
    (ed25519.Ed25519PrivateKey.generate(), 'Ed25519', 256),
])
def test_public_key_algorithm_and_size_are_reported(key, algorithm, bits):
    """
    "RSA" says nothing about quantum vulnerability; "RSA-2048" says
    everything. The size is not in the handshake anywhere -- it is inside the
    certificate, which is why this needs a real ASN.1 parser and why
    cert_guess, which reports the algorithm without the size, cannot answer
    the question the tool exists to ask.
    """
    record = describe_certificate(self_signed(key))
    assert record['public_key_algorithm'] == algorithm
    assert record['public_key_size'] == bits


def test_the_curve_is_named_as_well_as_measured():
    """secp256r1 and brainpoolP256r1 are both 256 bits and are not the same."""
    record = describe_certificate(
        self_signed(ec.generate_private_key(ec.SECP384R1())))
    assert record['public_key_curve'] == 'secp384r1'


# --------------------------------------------------------------------------
# the rest of the record
# --------------------------------------------------------------------------
def test_the_usual_fields_are_present():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    record = describe_certificate(self_signed(key, "records.test"))
    assert record['subject'] == 'CN=records.test'
    assert record['issuer'] == 'CN=records.test'
    assert record['self_signed'] is True
    assert record['is_ca'] is False
    assert record['serial_number'] == '123456789'
    assert record['not_before'].startswith('2024-01-01')
    assert record['subject_alt_names'] == ['records.test']
    assert record['signature_algorithm'] == 'sha256WithRSAEncryption'
    assert record['signature_algorithm_oid'].startswith('1.2.840.113549')


def test_the_fingerprint_identifies_the_bytes():
    der = self_signed(ec.generate_private_key(ec.SECP256R1()))
    first = describe_certificate(der)['fingerprint_sha256']
    assert first == describe_certificate(der)['fingerprint_sha256']
    assert len(first) == 64


def test_a_certificate_that_will_not_parse_is_reported_not_dropped():
    """
    A chain out of a capture is attacker-supplied by definition. One bad
    certificate in the middle must not lose the ones around it, and the bad
    one still has a fingerprint, which is enough to recognise it again.
    """
    good = self_signed(ec.generate_private_key(ec.SECP256R1()))
    bad = b'\x30\x82\x01\x00' + b'\xff' * 100
    chain = parse_certificate_message(tls12_message(good, bad, good))
    assert len(chain) == 3
    assert 'parse_error' in chain[1]
    assert chain[1]['fingerprint_sha256']
    assert chain[0]['subject'] == chain[2]['subject'] == 'CN=example.test'


def test_describe_certificate_never_raises():
    for der in (b'', b'\x00', b'\x30' * 40, bytes(range(256))):
        assert 'fingerprint_sha256' in describe_certificate(der)


# --------------------------------------------------------------------------
# on real chains
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,leaf,issuer_fragment", [
    ("tls12_certificate", 'sha384.badssl.com', 'DigiCert'),
    ("tls12_split_certificate", '*.badssl.com', "Let's Encrypt"),
])
def test_a_real_chain_comes_out_whole(name, leaf, issuer_fragment):
    """
    Whole: leaf *and* intermediate. cert_guess finds one 0x0b marker and
    parses forward from it, so it returned at most one certificate per
    handshake and never the chain -- and an intermediate's key size is part
    of the exposure just as much as the leaf's.
    """
    record = list(iter_sessions(STREAMS / f"{name}.pcap"))[0]
    chain = record['tls']['certificates']
    assert len(chain) == 2
    assert leaf in chain[0]['subject']
    assert chain[0]['is_ca'] is False
    assert issuer_fragment in chain[1]['subject']
    assert chain[1]['is_ca'] is True
    assert chain[0]['issuer'] == chain[1]['subject']
    assert all(c['public_key_size'] for c in chain)
    assert not any('parse_error' in c for c in chain)


def test_every_certificate_in_the_fixtures_parses():
    for path in sorted(STREAMS.glob("*.pcap")):
        for record in iter_sessions(path):
            for certificate in record['tls'].get('certificates') or []:
                assert 'parse_error' not in certificate, path.name
