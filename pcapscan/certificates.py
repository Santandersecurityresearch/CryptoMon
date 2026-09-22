"""
X.509 chains, parsed rather than guessed.

What this replaces. `cryptomon.utils.cert_guess` scans a frame for the byte
0x0b, checks that 0x30 0x82 appears ten bytes later and that another 0x30
appears four bytes after *that*, and calls the result a certificate. It has
to work that way, because the live path sees one segment at a time and a
certificate chain is several kilobytes: there was never a whole certificate
in front of it. It also could not tell a Certificate message from any other
run of bytes that happened to match, and its output was whatever `jc` made
of a fragment.

With the chain reassembled there is no need to guess. The Certificate message
declares its own length and the length of every certificate in it, so this
walks the structure and hands each DER blob to `cryptography`.

**Key size is the reason this matters beyond tidiness.** CycloneDX
`certificateProperties` requires the public key algorithm *and its size*, and
so does any statement about whether a certificate is quantum-vulnerable:
"RSA" says nothing, "RSA-2048" says everything. That number is not in the
handshake anywhere -- it is inside the certificate, and it needs a real ASN.1
parser to reach.

`cryptography` is an optional dependency. Reading algorithm negotiation out
of a capture does not require parsing X.509, so importing this module raises
ImportError when it is absent and `pcapscan.sessions` falls back to carrying
the raw DER. That is the whole contract: this module either works or is not
there.
"""
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (dsa, ec, ed448, ed25519,
                                                       rsa, x448, x25519)

# A Certificate message's own framing. TLS 1.2 (RFC 5246) is a 3-byte list
# length then entries of 3-byte length plus DER. TLS 1.3 (RFC 8446) puts a
# request context in front and gives every entry a trailing extension block.
LIST_LEN_BYTES = 3
ENTRY_LEN_BYTES = 3

# A certificate larger than this is not one. The largest in the corpus is
# 5256 bytes; the ceiling is generous and exists only so that a corrupt
# length field costs nothing.
MAX_CERTIFICATE_LEN = 1 << 18
MAX_CHAIN_LENGTH = 16

# Key sizes that are not carried on the key object itself.
_FIXED_KEY_SIZES = {
    ed25519.Ed25519PublicKey: 256,
    ed448.Ed448PublicKey: 456,
    x25519.X25519PublicKey: 256,
    x448.X448PublicKey: 448,
}


def _read_uint(data, offset, width):
    return int.from_bytes(bytes(data[offset:offset + width]), 'big')


def iter_der(body):
    """
    Yield the DER of each certificate in a Certificate message.

    Handles both framings. Which one is in use is decided by arithmetic
    rather than by the negotiated version, because the message is parsed
    where the version may not be known: TLS 1.2's list length accounts for
    every byte after itself, and TLS 1.3's does not, because of the context
    prefix.
    """
    body = bytes(body)
    if len(body) < LIST_LEN_BYTES:
        return
    offset = None
    if _read_uint(body, 0, LIST_LEN_BYTES) == len(body) - LIST_LEN_BYTES:
        offset = LIST_LEN_BYTES                   # TLS 1.2 and below
    else:
        context_len = body[0]
        start = 1 + context_len
        if (len(body) >= start + LIST_LEN_BYTES
                and _read_uint(body, start, LIST_LEN_BYTES)
                == len(body) - start - LIST_LEN_BYTES):
            offset = start + LIST_LEN_BYTES       # TLS 1.3
    if offset is None:
        return
    tls13 = offset != LIST_LEN_BYTES
    end = len(body)
    seen = 0
    while offset + ENTRY_LEN_BYTES <= end and seen < MAX_CHAIN_LENGTH:
        length = _read_uint(body, offset, ENTRY_LEN_BYTES)
        offset += ENTRY_LEN_BYTES
        if length == 0 or length > MAX_CERTIFICATE_LEN or offset + length > end:
            return
        yield body[offset:offset + length]
        offset += length
        seen += 1
        if tls13:
            if offset + 2 > end:
                return
            offset += 2 + _read_uint(body, offset, 2)   # per-entry extensions


def _public_key_description(certificate):
    """(algorithm name, size in bits, curve name or None)."""
    try:
        key = certificate.public_key()
    except Exception:
        return 'unknown', None, None
    if isinstance(key, rsa.RSAPublicKey):
        return 'RSA', key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        # The curve *is* the parameter set, so naming it matters as much as
        # the bit count: secp256r1 and brainpoolP256r1 are both 256 bits and
        # are not interchangeable.
        return 'EC', key.curve.key_size, key.curve.name
    if isinstance(key, dsa.DSAPublicKey):
        return 'DSA', key.key_size, None
    for key_type, bits in _FIXED_KEY_SIZES.items():
        if isinstance(key, key_type):
            return type(key).__name__.replace('PublicKey', ''), bits, None
    return type(key).__name__.replace('PublicKey', ''), None, None


def _field(getter, default=None):
    """
    Read one lazily-decoded certificate field, or give up on that field alone.

    `cryptography` decodes a certificate's body lazily: load_der_x509_certificate
    succeeds on any structurally plausible DER, and the individual attributes
    raise when *they* are decoded -- with a KeyError from an unknown attribute
    OID, or a ValueError out of the ASN.1 parser. So a try/except around the
    load is not a guard at all.

    Nor is one around the helper that formats the value. `_name(cert.subject)`
    evaluates `cert.subject` before `_name` is entered, so the guard inside
    `_name` never runs; that is exactly how this escaped, and fuzzing is what
    found it. Wrapping the *access* rather than the formatting is the fix, and
    it has to be every access, because any of them can be the next one.
    """
    try:
        return getter()
    except Exception:
        return default


def _subject_alt_names(certificate):
    extension = _field(lambda: certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName))
    if extension is None:
        return []
    names = []
    for general_name in _field(lambda: list(extension.value), []):
        name = _field(lambda: str(general_name.value), _MISSING)
        if name is not _MISSING:
            names.append(name)
    return names


def _is_ca(certificate):
    return _field(lambda: bool(
        certificate.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca))


# A sentinel distinct from None, so that "this field decoded to None" and
# "this field would not decode" stay apart.
_MISSING = object()


def _timestamp(certificate, field):
    """
    notBefore/notAfter as an ISO string.

    cryptography 42 renamed these to *_utc and deprecated the originals; both
    spellings are tried so that this works either side of that change rather
    than emitting a warning on one and failing on the other.
    """
    for attribute in (field + '_utc', field):
        value = _field(lambda: getattr(certificate, attribute, None))
        if value is not None:
            return value.isoformat()
    return None


def describe_certificate(der):
    """
    One certificate, as a record. Never raises.

    A chain from a capture is attacker-supplied by definition, and a
    malformed certificate in the middle of one must not lose the rest of the
    handshake. A certificate that will not load at all is reported as such,
    with its fingerprint, which is still enough to recognise it again.

    A certificate that loads but whose individual fields will not decode is
    reported field by field, with the ones that failed named in
    `undecodable_fields`. "We could not read the subject" and "this
    certificate has no subject" are different statements, and a report that
    conflated them would be worth less than one that admits the gap.
    """
    record = {
        'fingerprint_sha256': hashlib.sha256(der).hexdigest(),
        'der_bytes': len(der),
    }
    try:
        certificate = x509.load_der_x509_certificate(der)
    except Exception as exc:
        record['parse_error'] = type(exc).__name__
        return record

    algorithm, bits, curve = _public_key_description(certificate)
    fields = {
        'subject': lambda: certificate.subject.rfc4514_string(),
        'issuer': lambda: certificate.issuer.rfc4514_string(),
        'serial_number': lambda: format(certificate.serial_number, 'x'),
        'not_before': lambda: _timestamp(certificate, 'not_valid_before'),
        'not_after': lambda: _timestamp(certificate, 'not_valid_after'),
        'signature_algorithm': lambda: getattr(
            certificate.signature_algorithm_oid, '_name', None),
        'signature_algorithm_oid':
            lambda: certificate.signature_algorithm_oid.dotted_string,
        'version': lambda: certificate.version.name,
    }
    undecodable = []
    for name, getter in fields.items():
        value = _field(getter, _MISSING)
        if value is _MISSING:
            undecodable.append(name)
            record[name] = None
        else:
            record[name] = value
    record['public_key_algorithm'] = algorithm
    record['public_key_size'] = bits
    if curve:
        record['public_key_curve'] = curve
    public_key_oid = _field(
        lambda: certificate.public_key_algorithm_oid.dotted_string)
    if public_key_oid is not None:
        # CycloneDX joins cryptographic assets on OIDs, so carrying the
        # identifier as well as the name is what lets a CBOM built from
        # traffic line up with one built from source.
        record['public_key_algorithm_oid'] = public_key_oid
    hash_algorithm = _field(lambda: certificate.signature_hash_algorithm)
    if hash_algorithm is not None:
        record['signature_hash'] = _field(lambda: hash_algorithm.name)
    alt_names = _subject_alt_names(certificate)
    if alt_names:
        record['subject_alt_names'] = alt_names
    is_ca = _is_ca(certificate)
    if is_ca is not None:
        record['is_ca'] = is_ca
    record['self_signed'] = _field(
        lambda: certificate.subject == certificate.issuer)
    if undecodable:
        record['undecodable_fields'] = undecodable
    return record


def parse_certificate_message(body):
    """Every certificate in one Certificate message, in the order sent."""
    return [describe_certificate(der) for der in iter_der(body)]
