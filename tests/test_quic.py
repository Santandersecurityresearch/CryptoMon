"""
QUIC Initial packets: the key schedule, the header walk, and the hello inside.

Three kinds of evidence, in that order, because they answer different
questions:

* **RFC 9001 Appendix A.** The published test vectors for the Initial key
  schedule and for header protection. These are the only values here that
  come from outside this project, and they are what proves the derivation is
  the RFC's and not merely self-consistent.
* **Synthetic packets.** Built here with `cryptography` directly rather than
  with `pcapscan.quic`'s own helpers, so that a change which breaks the
  parser cannot also move the goalposts. They cover the shapes the corpus
  does not contain: version 2, Retry, Version Negotiation, a HelloRetryRequest
  pair, a coalesced datagram, and every bound.
* **Real bytes off the wire.** Two Chrome Initials carrying one
  post-quantum ClientHello split across two datagrams, and one Firefox
  server Initial carrying a ServerHello. Committed as hex rather than as a
  capture fixture because they are 2.6KB in total and need no pcap reader to
  be useful. Their decryption is confirmed by the AEAD tag, and the
  handshake bytes that come out were checked against tshark's TLS dissector
  while this was written -- tshark 3.4 cannot decrypt QUIC v1 itself, since
  it predates RFC 9000 and carries the draft-29 Initial salt, but it parses
  the plaintext this produces and agrees on every field.

The file is smoke-marked: no capture fixture, no database, no network, and
the whole thing runs in well under a second.
"""
import pytest

from cryptomon.parsers.tls import parse_hello_message
from pcapscan.datagrams import DatagramKey, DatagramRouter
from pcapscan.quic import (CryptoStream, HANDLER, HAVE_CRYPTO,
                           MAX_ACK_RANGES, MAX_CID_LEN, MAX_CRYPTO_BYTES,
                           MAX_CRYPTO_CHUNKS, MAX_MESSAGES,
                           MAX_PACKETS_PER_DATAGRAM, QuicHandler, VERSION_1,
                           VERSION_2, VERSION_NEGOTIATION,
                           decode_packet_number, decrypt_packet, expand_label,
                           hkdf_extract, initial_keys, iter_crypto_frames,
                           offered_versions, parse_long_header, read_varint,
                           remove_header_protection, split_handshake,
                           version_name)

pytestmark = pytest.mark.smoke

needs_crypto = pytest.mark.skipif(
    not HAVE_CRYPTO, reason='cryptography is not installed')

CLIENT = DatagramKey('10.0.0.1', 50000, '10.0.0.2', 443)
SERVER = CLIENT.reverse()


# --------------------------------------------------------------------------
# RFC 9001 Appendix A -- the only numbers here that came from outside
# --------------------------------------------------------------------------
# Appendix A uses this Destination Connection ID throughout.
RFC_DCID = bytes.fromhex('8394c8f03e515708')
RFC_INITIAL_SECRET = bytes.fromhex(
    '7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44')
RFC_CLIENT_SECRET = bytes.fromhex(
    'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea')
RFC_SERVER_SECRET = bytes.fromhex(
    '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b')
RFC_CLIENT_KEY = bytes.fromhex('1f369613dd76d5467730efcbe3b1a22d')
RFC_CLIENT_IV = bytes.fromhex('fa044b2f42a3fd3b46fb255c')
RFC_CLIENT_HP = bytes.fromhex('9f50449e04a0e810283a1e9933adedd2')
RFC_SERVER_KEY = bytes.fromhex('cf3a5331653c364c88f0f379b6067e37')
RFC_SERVER_IV = bytes.fromhex('0ac1493ca1905853b0bba03e')
RFC_SERVER_HP = bytes.fromhex('c206b8d9b9f0f37644430b490eeaa314')

# A.2: the client Initial's header-protection sample, the mask it produces,
# and the header in both forms. Note which way round they are: the *plain*
# first byte is 0xc3 and the protected one is 0xc0, because protection XORs
# the low four bits and the packet number is four bytes wide, which is what
# 0xc3's low two bits say. Reading the pair the other way round makes the
# packet number one byte long and every value after it wrong -- a mistake
# made while writing this file, and caught by these vectors.
RFC_CLIENT_SAMPLE = bytes.fromhex('d1b1c98dd7689fb8ec11d242b123dc9b')
RFC_CLIENT_MASK = bytes.fromhex('437b9aec36')
RFC_CLIENT_PROTECTED_HEADER = bytes.fromhex(
    'c000000001088394c8f03e5157080000449e7b9aec34')
RFC_CLIENT_PLAIN_HEADER = bytes.fromhex(
    'c300000001088394c8f03e5157080000449e00000002')

# A.3: the same for the server's Initial. Packet number 1, two bytes wide,
# which is 0xc1's low two bits.
RFC_SERVER_SAMPLE = bytes.fromhex('2cd0991cd25b0aac406a5816b6394100')
RFC_SERVER_MASK = bytes.fromhex('2ec0d8356a')
RFC_SERVER_PROTECTED_HEADER = bytes.fromhex(
    'cf000000010008f067a5502a4262b5004075c0d9')
RFC_SERVER_PLAIN_HEADER = bytes.fromhex(
    'c1000000010008f067a5502a4262b50040750001')


def test_initial_secret_matches_rfc9001():
    """HKDF-Extract(salt, DCID). RFC 9001 Appendix A.1."""
    from pcapscan.quic import INITIAL_SALT
    assert hkdf_extract(INITIAL_SALT[VERSION_1],
                        RFC_DCID) == RFC_INITIAL_SECRET


def test_client_and_server_secrets_match_rfc9001():
    """HKDF-Expand-Label(initial_secret, 'client in' / 'server in')."""
    assert expand_label(RFC_INITIAL_SECRET, b'client in', 32) == \
        RFC_CLIENT_SECRET
    assert expand_label(RFC_INITIAL_SECRET, b'server in', 32) == \
        RFC_SERVER_SECRET


def test_initial_keys_match_rfc9001():
    """The whole chain, both directions, against the published answers."""
    assert initial_keys(RFC_DCID, VERSION_1, True) == \
        (RFC_CLIENT_KEY, RFC_CLIENT_IV, RFC_CLIENT_HP)
    assert initial_keys(RFC_DCID, VERSION_1, False) == \
        (RFC_SERVER_KEY, RFC_SERVER_IV, RFC_SERVER_HP)


def test_expand_label_uses_the_tls13_prefix():
    """
    Dropping the `tls13 ` prefix is a silent, total failure.

    Every value still comes out 16 or 32 bytes long and nothing raises; the
    keys are simply wrong and every tag fails. This pins the one byte string
    that makes the difference.
    """
    prefixed = expand_label(RFC_INITIAL_SECRET, b'client in', 32)
    assert prefixed == RFC_CLIENT_SECRET
    assert prefixed != _expand_without_prefix(RFC_INITIAL_SECRET,
                                              b'client in', 32)


def _expand_without_prefix(secret, label, length):
    """HKDF-Expand-Label as it would be with the prefix forgotten."""
    import hashlib
    import hmac
    info = length.to_bytes(2, 'big') + bytes([len(label)]) + label + b'\x00'
    out, block, counter = b'', b'', 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


@needs_crypto
def test_header_protection_mask_matches_rfc9001_client():
    """A.2: the sample, the mask, the recovered first byte and number."""
    # The header declares a 1182-byte payload, so the packet has to be that
    # long or the length check refuses it -- which is the check working.
    packet = (RFC_CLIENT_PROTECTED_HEADER + RFC_CLIENT_SAMPLE
              + b'\x00' * (1200 - 22 - 16))
    header = parse_long_header(packet, 0)
    assert header.pn_offset == 18
    first, pn_bytes = remove_header_protection(packet, header, RFC_CLIENT_HP)
    assert bytes([first]) == RFC_CLIENT_PLAIN_HEADER[:1]
    assert pn_bytes == RFC_CLIENT_PLAIN_HEADER[-4:]
    assert len(pn_bytes) == 4
    assert int.from_bytes(pn_bytes, 'big') == 2


@needs_crypto
def test_header_protection_mask_matches_rfc9001_server():
    """
    A.3, and the case the client vector cannot catch.

    The server's packet number is *two* bytes, not four, and its length is
    in the low bits of the first byte -- which are themselves masked. Reading
    them before unmasking gives 4 here and everything downstream is wrong.
    """
    # The sample is taken four bytes into the packet number field whatever
    # the number's real width, so two bytes of ciphertext sit between the
    # two-byte number and the sample. They are not covered by the mask and
    # their value does not matter.
    packet = (RFC_SERVER_PROTECTED_HEADER + b'\x00\x00' + RFC_SERVER_SAMPLE
              + b'\x00' * (135 - 20 - 2 - 16))
    header = parse_long_header(packet, 0)
    assert header.pn_offset == 18
    first, pn_bytes = remove_header_protection(packet, header, RFC_SERVER_HP)
    assert bytes([first]) == RFC_SERVER_PLAIN_HEADER[:1]
    assert pn_bytes == RFC_SERVER_PLAIN_HEADER[-2:]
    assert len(pn_bytes) == 2
    assert int.from_bytes(pn_bytes, 'big') == 1


@needs_crypto
def test_header_protection_mask_is_aes_ecb_of_the_sample():
    """The masks themselves, so a failure above says which step moved."""
    from pcapscan.quic import _ECB_BLOCK
    assert _ECB_BLOCK(RFC_CLIENT_HP, RFC_CLIENT_SAMPLE)[:5] == RFC_CLIENT_MASK
    assert _ECB_BLOCK(RFC_SERVER_HP, RFC_SERVER_SAMPLE)[:5] == RFC_SERVER_MASK


def test_version_2_derives_different_keys():
    """
    RFC 9369 changes both the salt and the labels, deliberately.

    A v2 connection read with v1's schedule must not decrypt, and the way
    that shows up here is that nothing about the two key sets matches.
    """
    one = initial_keys(RFC_DCID, VERSION_1, True)
    two = initial_keys(RFC_DCID, VERSION_2, True)
    assert one != two
    assert not set(one) & set(two)


def test_version_names():
    assert version_name(VERSION_1) == 'v1'
    assert version_name(VERSION_2) == 'v2'
    assert version_name(VERSION_NEGOTIATION) == 'version_negotiation'
    assert version_name(0xFF00001D) == 'draft-29'
    assert version_name(0x1A2A3A4A) == 'reserved'
    assert version_name(0x51303433) is None        # gQUIC Q043: not this
    assert version_name(0xDEADBEEF) is None


# --------------------------------------------------------------------------
# variable-length integers (RFC 9000 section 16 and Appendix A.1)
# --------------------------------------------------------------------------
@pytest.mark.parametrize('encoded,value,width', [
    ('c2197c5eff14e88c', 151288809941952652, 8),
    ('9d7f3e7d', 494878333, 4),
    ('7bbd', 15293, 2),
    ('25', 37, 1),
    ('4025', 37, 2),          # the same value, deliberately over-encoded
])
def test_varint_examples_from_rfc9000(encoded, value, width):
    buf = bytes.fromhex(encoded)
    assert read_varint(buf, 0) == (value, width)


@pytest.mark.parametrize('encoded', ['c2', '9d7f', '7b', ''])
def test_varint_refuses_a_truncated_integer(encoded):
    """
    None, not zero.

    A length field that ran off the end of the datagram and a length field
    that says zero are different facts, and conflating them is how a parser
    ends up reading a frame that was never sent.
    """
    buf = bytes.fromhex(encoded)
    assert read_varint(buf, 0) == (None, 0)


def test_varint_refuses_an_offset_past_the_end():
    assert read_varint(b'\x25', 5) == (None, 5)
    assert read_varint(b'\x25', -1) == (None, -1)


# --------------------------------------------------------------------------
# building packets -- deliberately not using pcapscan.quic's own helpers
# --------------------------------------------------------------------------
def encode_varint(value):
    for width, ceiling, tag in ((1, 1 << 6, 0x00), (2, 1 << 14, 0x40),
                                (4, 1 << 30, 0x80), (8, 1 << 62, 0xC0)):
        if value < ceiling:
            out = bytearray(value.to_bytes(width, 'big'))
            out[0] |= tag
            return bytes(out)
    raise ValueError('not a QUIC varint')


def xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def seal(key, nonce, plaintext, aad):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_ecb(key, block):
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def build_initial(dcid, payload, from_client=True, scid=b'', number=0,
                  version=VERSION_1, pad_to=0, token=b'', kind=0,
                  header_dcid=None):
    """
    One protected Initial (or other long-header) packet, RFC 9001 section 5.

    `header_dcid` is what goes in the header when that is not what the keys
    came from -- which is every server Initial on the wire, since a server
    addresses the client's Source Connection ID while both ends still key
    from the client's original destination one.
    """
    key, iv, hp_key = initial_keys(dcid, version, from_client)
    dcid = dcid if header_dcid is None else header_dcid
    plaintext = payload + b'\x00' * max(0, pad_to - len(payload))
    pn_bytes = number.to_bytes(4, 'big')
    first = 0xC0 | (kind << 4) | 0x03          # four-byte packet number
    header = (bytes([first]) + version.to_bytes(4, 'big')
              + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid)
    if kind == 0:
        header += encode_varint(len(token)) + token
    header += encode_varint(len(pn_bytes) + len(plaintext) + 16)
    aad = header + pn_bytes
    nonce = xor(iv, number.to_bytes(12, 'big'))
    packet = bytearray(aad + seal(key, nonce, plaintext, aad))
    pn_offset = len(header)
    mask = aes_ecb(hp_key, bytes(packet[pn_offset + 4:pn_offset + 20]))
    packet[0] ^= mask[0] & 0x0F
    for index in range(4):
        packet[pn_offset + index] ^= mask[1 + index]
    return bytes(packet)


def crypto_frame(offset, data):
    return (b'\x06' + encode_varint(offset) + encode_varint(len(data))
            + data)


def handshake_message(msg_type, body):
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def client_hello():
    """A small but structurally complete ClientHello with an SNI."""
    extensions = (
        # server_name: one host_name entry, 'localhost'
        bytes.fromhex('0000000e000c0000096c6f63616c686f7374')
        # supported_versions: TLS 1.3 only
        + bytes.fromhex('002b0003020304')
        # supported_groups: x25519
        + bytes.fromhex('000a00040002001d'))
    body = (bytes.fromhex('0303') + b'\x11' * 32 + b'\x00'
            + b'\x00\x06\x13\x01\x13\x02\x13\x03'
            + b'\x01\x00'
            + len(extensions).to_bytes(2, 'big') + extensions)
    return handshake_message(1, body)


def server_hello():
    """A ServerHello selecting TLS 1.3, AES-128-GCM and x25519."""
    key_share = bytes.fromhex('0033') + (2 + 2 + 32).to_bytes(2, 'big') \
        + bytes.fromhex('001d') + (32).to_bytes(2, 'big') + b'\x22' * 32
    extensions = bytes.fromhex('002b00020304') + key_share
    body = (bytes.fromhex('0303') + b'\x33' * 32 + b'\x00'
            + bytes.fromhex('1301') + b'\x00'
            + len(extensions).to_bytes(2, 'big') + extensions)
    return handshake_message(2, body)


# --------------------------------------------------------------------------
# the long header
# --------------------------------------------------------------------------
@needs_crypto
def test_parse_initial_header_fields():
    packet = build_initial(b'\xaa' * 8, crypto_frame(0, client_hello()),
                           scid=b'\xbb' * 4, pad_to=1162)
    header = parse_long_header(packet, 0)
    assert header.kind == 'initial'
    assert header.label == 'v1'
    assert header.version == VERSION_1
    assert header.dcid == b'\xaa' * 8
    assert header.scid == b'\xbb' * 4
    assert header.end == len(packet)
    assert header.token == b''


@needs_crypto
def test_parse_initial_with_a_token():
    packet = build_initial(b'\xaa' * 8, crypto_frame(0, client_hello()),
                           token=b'retry-token')
    assert parse_long_header(packet, 0).token == b'retry-token'


def test_parse_refuses_a_short_header():
    """The 1-RTT form. There is nothing in it this can read."""
    assert parse_long_header(b'\x40' + b'\x00' * 40, 0) is None


def test_parse_refuses_a_cleared_fixed_bit():
    """
    RFC 9287 allows it, but only once negotiated -- which a long header
    cannot have done yet. Accepting it here widens detection for nothing.
    """
    packet = bytearray(b'\x80' + VERSION_1.to_bytes(4, 'big')
                       + b'\x08' + b'\xaa' * 8 + b'\x00' + b'\x00'
                       + b'\x40\x64' + b'\x00' * 100)
    assert parse_long_header(bytes(packet), 0) is None


def test_parse_refuses_an_unknown_version():
    packet = (b'\xc0' + (0xDEADBEEF).to_bytes(4, 'big') + b'\x08'
              + b'\xaa' * 8 + b'\x00\x00\x40\x64' + b'\x00' * 100)
    assert parse_long_header(packet, 0) is None


@pytest.mark.parametrize('dcid_len', [MAX_CID_LEN + 1, 0xFF])
def test_parse_refuses_an_oversized_connection_id(dcid_len):
    """
    A byte that can claim 255 against a field the RFC caps at 20.

    Without the check the cursor walks past the end of the datagram and every
    field after it is read out of whatever happens to be there.
    """
    packet = (b'\xc0' + VERSION_1.to_bytes(4, 'big') + bytes([dcid_len])
              + b'\xaa' * 32 + b'\x00\x00\x40\x64' + b'\x00' * 200)
    assert parse_long_header(packet, 0) is None


def test_parse_refuses_a_length_past_the_datagram():
    """
    The self-consistency test that makes detection safe.

    A Length of 16000 in a 120-byte datagram is not a QUIC packet, and this
    is the check that random UDP payloads fail.
    """
    packet = (b'\xc0' + VERSION_1.to_bytes(4, 'big') + b'\x08'
              + b'\xaa' * 8 + b'\x00' + b'\x00'
              + encode_varint(16000) + b'\x00' * 100)
    assert parse_long_header(packet, 0) is None


def test_parse_refuses_a_length_too_short_to_sample():
    """RFC 9001 section 5.4.2: under 20 bytes there is no sample to take."""
    body = b'\x00' * 19
    packet = (b'\xc0' + VERSION_1.to_bytes(4, 'big') + b'\x08'
              + b'\xaa' * 8 + b'\x00' + b'\x00'
              + encode_varint(len(body)) + body)
    assert parse_long_header(packet, 0) is None


@pytest.mark.parametrize('cut', range(1, 24))
def test_parse_never_raises_on_a_truncated_header(cut):
    packet = (b'\xc0' + VERSION_1.to_bytes(4, 'big') + b'\x08'
              + b'\xaa' * 8 + b'\x04' + b'\xbb' * 4 + b'\x00'
              + encode_varint(64) + b'\x00' * 64)
    assert parse_long_header(packet[:cut], 0) is None or cut >= len(packet)


def test_parse_version_negotiation():
    """
    Version 0 is not a packet type -- it is the server saying "not that one".

    Recognising it matters because its first byte is unconstrained and its
    type bits mean nothing: read as a v1 packet it is an Initial, a Retry or
    a Handshake depending on random bits, and each of those would be a lie.
    """
    packet = (b'\xf0' + VERSION_NEGOTIATION.to_bytes(4, 'big')
              + b'\x04' + b'\xaa' * 4 + b'\x04' + b'\xbb' * 4
              + VERSION_1.to_bytes(4, 'big')
              + VERSION_2.to_bytes(4, 'big'))
    header = parse_long_header(packet, 0)
    assert header.kind == 'version_negotiation'
    assert header.dcid == b'\xaa' * 4 and header.scid == b'\xbb' * 4
    assert offered_versions(packet, header) == ['0x00000001', '0x6b3343cf']


def test_parse_retry():
    packet = (b'\xf0' + VERSION_1.to_bytes(4, 'big')
              + b'\x04' + b'\xaa' * 4 + b'\x08' + b'\xcc' * 8
              + b'a-retry-token' + b'\x99' * 16)
    header = parse_long_header(packet, 0)
    assert header.kind == 'retry'
    assert header.scid == b'\xcc' * 8
    assert header.token == b'a-retry-token'


def test_version_2_rotates_the_packet_type_bits():
    """
    RFC 9369 section 3.2. The same two bits mean Initial in v1 and Retry in
    v2, so reading v2 with v1's table mislabels every packet in the flow.
    """
    prefix = (VERSION_2.to_bytes(4, 'big') + b'\x04' + b'\xaa' * 4
              + b'\x00')
    retry = bytes([0xC0]) + prefix + b'token' + b'\x99' * 16
    assert parse_long_header(retry, 0).kind == 'retry'
    initial = (bytes([0xD0]) + prefix + b'\x00' + encode_varint(64)
               + b'\x00' * 64)
    assert parse_long_header(initial, 0).kind == 'initial'


# --------------------------------------------------------------------------
# frames
# --------------------------------------------------------------------------
def test_crypto_frames_are_yielded_with_their_offsets():
    payload = crypto_frame(0, b'first') + crypto_frame(5, b'second')
    assert list(iter_crypto_frames(payload)) == [(0, b'first'), (5, b'second')]


def test_padding_run_is_skipped_in_one_step():
    payload = b'\x00' * 1100 + crypto_frame(0, b'hello')
    assert list(iter_crypto_frames(payload)) == [(0, b'hello')]


def test_ping_and_ack_frames_are_skipped():
    ack = (b'\x02' + encode_varint(7) + encode_varint(0) + encode_varint(0)
           + encode_varint(7))
    payload = b'\x01' + ack + crypto_frame(0, b'after')
    assert list(iter_crypto_frames(payload)) == [(0, b'after')]


def test_ack_with_ranges_and_ecn_is_skipped():
    ack = (b'\x03' + encode_varint(20) + encode_varint(3) + encode_varint(2)
           + encode_varint(1)
           + encode_varint(1) + encode_varint(2)
           + encode_varint(3) + encode_varint(4)
           + encode_varint(5) + encode_varint(6) + encode_varint(7))
    payload = ack + crypto_frame(0, b'after')
    assert list(iter_crypto_frames(payload)) == [(0, b'after')]


def test_connection_close_is_skipped():
    close = (b'\x1c' + encode_varint(0x0A) + encode_varint(0x06)
             + encode_varint(5) + b'oops')
    assert list(iter_crypto_frames(close + b'\x00')) == []
    app = b'\x1d' + encode_varint(1) + encode_varint(4) + b'bye!'
    assert list(iter_crypto_frames(app + crypto_frame(0, b'x'))) == \
        [(0, b'x')]


def test_an_impossible_ack_range_count_stops_the_walk():
    """
    The count is a varint and can claim 2**62; the frame cannot be that long.

    Trusting it is a loop that reads past the buffer 4.6 million million
    million times, which is the difference between a refused capture and a
    hung upload worker.
    """
    ack = (b'\x02' + encode_varint(1) + encode_varint(0)
           + encode_varint(MAX_ACK_RANGES + 1) + encode_varint(0))
    assert list(iter_crypto_frames(ack + crypto_frame(0, b'never'))) == []


def test_an_unknown_frame_type_stops_the_walk():
    """
    An Initial may carry five frame types. Anything else means this parser
    has lost its place, and resynchronising would invent frames.
    """
    payload = b'\x08' + b'\xff' * 20 + crypto_frame(0, b'not reached')
    assert list(iter_crypto_frames(payload)) == []


def test_a_crypto_length_past_the_payload_is_refused():
    payload = b'\x06' + encode_varint(0) + encode_varint(9999) + b'short'
    assert list(iter_crypto_frames(payload)) == []


def test_frame_walk_is_bounded():
    """A payload of alternating PING frames costs a bounded walk."""
    assert list(iter_crypto_frames(b'\x01' * 100000)) == []


# --------------------------------------------------------------------------
# CRYPTO stream reassembly
# --------------------------------------------------------------------------
def test_stream_joins_fragments_in_offset_order():
    stream = CryptoStream()
    stream.add(5, b'world')
    stream.add(0, b'hello')
    assert stream.assemble() == b'helloworld'
    assert stream.gap is False


def test_stream_stops_at_a_hole():
    """
    A fragment beyond a gap is real data at an unknown distance from the
    start. Splicing it on would move every message boundary after it.
    """
    stream = CryptoStream()
    stream.add(0, b'hello')
    stream.add(99, b'world')
    assert stream.assemble() == b'hello'
    assert stream.gap is True


def test_stream_tolerates_overlapping_retransmissions():
    stream = CryptoStream()
    stream.add(0, b'abcdef')
    stream.add(3, b'defghi')
    assert stream.assemble() == b'abcdefghi'


def test_stream_refuses_an_absurd_offset():
    stream = CryptoStream()
    stream.add(1 << 40, b'x')
    assert stream.assemble() == b''
    assert stream.overflowed is True


def test_stream_caps_total_bytes():
    stream = CryptoStream()
    for index in range(MAX_CRYPTO_CHUNKS + 10):
        stream.add(index * 4096, b'x' * 4096)
    assert stream.octets <= MAX_CRYPTO_BYTES
    assert len(stream.chunks) <= MAX_CRYPTO_CHUNKS
    assert stream.overflowed is True


# --------------------------------------------------------------------------
# handshake message splitting
# --------------------------------------------------------------------------
def test_split_handshake_returns_whole_messages_only():
    stream = client_hello() + server_hello()
    messages = split_handshake(stream)
    assert [m.msg_type for m in messages] == [1, 2]
    assert messages[0].name == 'client_hello'
    assert split_handshake(stream[:-1])[0].msg_type == 1
    assert len(split_handshake(stream[:-1])) == 1


def test_split_handshake_is_bounded():
    stream = handshake_message(1, b'') * (MAX_MESSAGES + 5)
    assert len(split_handshake(stream)) == MAX_MESSAGES


def test_split_handshake_refuses_an_absurd_length():
    assert split_handshake(b'\x01\xff\xff\xff' + b'x' * 10) == []


# --------------------------------------------------------------------------
# packet number decoding
# --------------------------------------------------------------------------
def test_packet_number_decoding_is_the_identity_at_the_start():
    assert decode_packet_number(-1, 0, 32) == 0
    assert decode_packet_number(-1, 2, 32) == 2


def test_packet_number_decoding_walks_the_window():
    """RFC 9000 Appendix A.3: a one-byte number after 0xa82f30ea."""
    assert decode_packet_number(0xA82F30EA, 0x9B, 8) == 0xA82F309B


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------
@needs_crypto
def test_detect_accepts_an_initial():
    packet = build_initial(b'\xaa' * 8, crypto_frame(0, client_hello()),
                           pad_to=1162)
    assert QuicHandler.detect(packet, CLIENT) is True


@pytest.mark.parametrize('payload', [
    b'',
    b'\x00',
    b'\x40' + b'\xaa' * 100,                              # a 1-RTT packet
    bytes.fromhex('00010100000100000000000003777777076578616d706c6503636f'
                  '6d0000010001'),                          # a DNS query
    bytes.fromhex('000100000001000000000000') + b'\x00' * 20,   # STUN
    b'\x23' + b'\x00' * 47,                               # NTP
    b'\x20' + b'\x00' * 100,                              # HSRP-ish
    b'\xc0' + b'\xff' * 200,                              # right form bits
    b'\xff' * 64,
])
def test_detect_refuses_what_is_not_quic(payload):
    assert QuicHandler.detect(payload, CLIENT) is False


def test_detect_never_raises():
    """
    Offered attacker-chosen bytes on every new UDP flow.

    A detector that raises is caught and counted by the router, but it is
    still a defect: it stops the remaining handlers being offered the same
    datagram, so one malformed packet can make a whole capture's DTLS or
    IKEv2 invisible.
    """
    seed = bytearray(b'\xc0' + VERSION_1.to_bytes(4, 'big') + b'\x08'
                     + b'\xaa' * 8 + b'\x00\x00\x44\xd0' + b'\x11' * 200)
    for index in range(len(seed)):
        for value in (0x00, 0x01, 0x40, 0x7F, 0x80, 0xC0, 0xFF):
            mutated = bytearray(seed)
            mutated[index] = value
            QuicHandler.detect(bytes(mutated), CLIENT)
            QuicHandler.detect(bytes(mutated[:index]), CLIENT)


# --------------------------------------------------------------------------
# the handler, end to end on packets built here
# --------------------------------------------------------------------------
@needs_crypto
def test_client_hello_round_trip():
    dcid = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    packet = build_initial(dcid, crypto_frame(0, client_hello()), pad_to=1162)
    handler = QuicHandler()
    handler.push(1.0, packet, CLIENT, None)
    document = list(handler.finish())[0]
    assert document['tls']['hostname'] == 'localhost'
    assert document['tls']['tls_versions'] == ['TLSv1.3']
    assert document['quic']['initials_decrypted'] == 1
    assert document['quic']['initial_dcid'] == dcid.hex()
    assert document['quic']['version_name'] == 'v1'


@needs_crypto
def test_hello_split_across_two_packets_is_reassembled():
    """
    The reason this module has a reassembler at all.

    A ClientHello offering a post-quantum key share does not fit in one
    packet. Parsing only the first fragment finds no extensions and no SNI,
    so the traffic that most needs reporting is the traffic that would go
    missing.
    """
    dcid = b'\x09' * 8
    hello = client_hello()
    cut = 40
    first = build_initial(dcid, crypto_frame(0, hello[:cut]), number=0,
                          pad_to=1162)
    second = build_initial(dcid, crypto_frame(cut, hello[cut:]), number=1,
                           pad_to=1162)
    handler = QuicHandler()
    handler.push(1.0, first, CLIENT, None)
    handler.push(1.1, second, CLIENT, None)
    document = list(handler.finish())[0]
    assert document['tls']['hostname'] == 'localhost'
    assert document['quic']['crypto_bytes']['client'] == len(hello)


@needs_crypto
def test_a_missing_fragment_is_reported_not_guessed():
    dcid = b'\x09' * 8
    hello = client_hello()
    second = build_initial(dcid, crypto_frame(40, hello[40:]), number=1,
                           pad_to=1162)
    first = build_initial(dcid, b'\x01', number=0, pad_to=1162)
    handler = QuicHandler()
    handler.push(1.0, first, CLIENT, None)
    handler.push(1.1, second, CLIENT, None)
    document = list(handler.finish())[0]
    assert 'tls' not in document
    assert document['quic']['crypto_incomplete'] is True


@needs_crypto
def test_server_initial_fills_the_selected_block():
    dcid = b'\x0a' * 8
    client_packet = build_initial(dcid, crypto_frame(0, client_hello()),
                                  pad_to=1162)
    server_packet = build_initial(dcid, crypto_frame(0, server_hello()),
                                  from_client=False, scid=b'\x0b' * 8)
    handler = QuicHandler()
    handler.push(1.0, client_packet, CLIENT, None)
    handler.push(1.1, server_packet, SERVER, None)
    document = list(handler.finish())[0]
    assert document['tls']['ciphersuite'] == 'TLS_AES_128_GCM_SHA256'
    assert document['tls']['kex_group'] == 'x25519'
    assert document['tls']['messages'] == {'client_hello': 1,
                                           'server_hello': 1}
    assert document['quic']['server_cid'] == (b'\x0b' * 8).hex()


@needs_crypto
def test_the_tag_decides_the_direction_not_the_capture_order():
    """
    A capture that begins with the server's packet must still come out right.

    `pcapscan.datagrams` opens a flow on whichever datagram it sees first and
    calls that the client. The AEAD tag is a 128-bit check on which secret
    was used, so it can say what the framing cannot -- and when it disagrees
    with the guess, the guess loses.
    """
    dcid = b'\x0c' * 8
    server_packet = build_initial(dcid, crypto_frame(0, server_hello()),
                                  from_client=False, scid=b'\x0d' * 8)
    client_packet = build_initial(dcid, crypto_frame(0, client_hello()),
                                  pad_to=1162)
    handler = QuicHandler()
    handler.push(1.0, server_packet, SERVER, None)
    handler.push(1.1, client_packet, CLIENT, None)
    document = list(handler.finish())[0]
    assert document['quic'].get('direction_corrected') is True
    assert document['tls']['hostname'] == 'localhost'
    assert document['tls']['ciphersuite'] == 'TLS_AES_128_GCM_SHA256'
    # and the record's endpoints are the client's, not the capture's guess
    assert document['eth']['dst']['port'] == 443


@needs_crypto
def test_coalesced_packets_in_one_datagram_are_all_walked():
    """
    RFC 9000 section 12.2. The server routinely puts its Initial and its
    Handshake packet in one datagram; stopping after the first loses the
    second, and in the corpus that is 24 packets tshark's own frame count
    never sees either.
    """
    dcid = b'\x0e' * 8
    client_packet = build_initial(dcid, crypto_frame(0, client_hello()),
                                  pad_to=1162)
    first = build_initial(dcid, crypto_frame(0, server_hello()),
                          from_client=False, scid=b'\x0f' * 8)
    second = build_initial(dcid, b'\x01' * 40, from_client=False,
                           scid=b'\x0f' * 8, number=1, kind=2)
    handler = QuicHandler()
    handler.push(1.0, client_packet, CLIENT, None)
    handler.push(1.1, first + second, SERVER, None)
    document = list(handler.finish())[0]
    assert document['quic']['coalesced_packets'] == 1
    assert document['quic']['packets']['handshake'] == 1
    assert document['tls']['ciphersuite'] == 'TLS_AES_128_GCM_SHA256'
    assert document['tls']['certificates_unreadable'] is True


@needs_crypto
def test_packets_per_datagram_are_capped():
    dcid = b'\x10' * 8
    one = build_initial(dcid, b'\x01' * 40)
    handler = QuicHandler()
    handler.push(1.0, one * (MAX_PACKETS_PER_DATAGRAM + 4), CLIENT, None)
    document = list(handler.finish())[0]
    assert document['quic']['packets']['initial'] == MAX_PACKETS_PER_DATAGRAM
    assert handler.counts['packets_over_cap'] == 1


@needs_crypto
def test_a_retry_changes_the_connection_id_the_keys_come_from():
    """
    After a Retry the client starts again with the server's connection ID,
    so the Initial keys change mid-flow. A handler that pinned the first DCID
    reads nothing after the Retry -- which is every Retry-ed connection's
    ClientHello.
    """
    first_dcid = b'\x11' * 8
    new_dcid = b'\x12' * 8
    first = build_initial(first_dcid, crypto_frame(0, b'\x01\x00\x00\x00'),
                          pad_to=1162)
    retry = (b'\xf0' + VERSION_1.to_bytes(4, 'big')
             + bytes([len(first_dcid)]) + first_dcid
             + bytes([len(new_dcid)]) + new_dcid
             + b'the-token' + b'\x99' * 16)
    again = build_initial(new_dcid, crypto_frame(0, client_hello()),
                          token=b'the-token', pad_to=1162)
    handler = QuicHandler()
    handler.push(1.0, first, CLIENT, None)
    handler.push(1.1, retry, SERVER, None)
    handler.push(1.2, again, CLIENT, None)
    document = list(handler.finish())[0]
    assert document['quic']['retry']['new_dcid'] == new_dcid.hex()
    assert document['tls']['hostname'] == 'localhost'


@needs_crypto
def test_a_server_initial_without_a_client_one_is_counted_not_guessed():
    """
    A capture that starts mid-connection has no original DCID in it, so the
    keys cannot be derived at all. That is a fact about the capture and it
    belongs in the record.
    """
    packet = build_initial(b'\x13' * 8, crypto_frame(0, server_hello()),
                           from_client=False, scid=b'\x14' * 8,
                           header_dcid=b'\x15' * 4)
    handler = QuicHandler()
    handler.push(1.0, packet, SERVER, None)
    document = list(handler.finish())[0]
    assert 'tls' not in document
    assert document['quic']['initials_undecryptable'] == 1
    assert document['quic']['handshake_unreadable'] == \
        'no client Initial in the capture'


@needs_crypto
def test_a_1_rtt_only_flow_is_counted_not_hidden():
    """
    The router never offers this handler such a flow -- `detect` refuses a
    short header, because there is nothing in one to recognise -- but a flow
    that starts with an Initial and continues into 1-RTT does reach here, and
    the packets it cannot read should still be counted.
    """
    dcid = b'\x15' * 8
    handler = QuicHandler()
    handler.push(1.0, build_initial(dcid, crypto_frame(0, client_hello()),
                                    pad_to=1162), CLIENT, None)
    handler.push(1.1, b'\x40' + dcid + b'\x77' * 200, CLIENT, None)
    document = list(handler.finish())[0]
    assert document['quic']['packets']['one_rtt'] == 1
    assert document['tls']['hostname'] == 'localhost'


@needs_crypto
def test_a_version_this_cannot_read_is_still_reported_as_quic():
    draft = 0xFF00001D
    packet = (b'\xc0' + draft.to_bytes(4, 'big') + b'\x08' + b'\xaa' * 8
              + b'\x00' + b'\x00' + encode_varint(64) + b'\x00' * 64)
    handler = QuicHandler()
    handler.push(1.0, packet, CLIENT, None)
    document = list(handler.finish())[0]
    assert document['quic']['version_name'] == 'draft-29'
    assert document['quic']['handshake_unreadable'] == \
        'no published salt for this QUIC version'


@needs_crypto
def test_push_never_raises_on_mutated_initials():
    """
    Every byte of this arrives through an upload form.

    Mutating one byte at a time across a whole Initial exercises the length
    fields, the connection-ID lengths, the frame types and the varints, and
    none of it may escape as an exception -- `DatagramRouter.push` does not
    guard `handler.push`, so one raised exception ends the capture.
    """
    seed = build_initial(b'\x16' * 8, crypto_frame(0, client_hello()),
                         pad_to=300)
    for index in range(0, len(seed), 3):
        for value in (0x00, 0x3F, 0x40, 0xC0, 0xFF):
            mutated = bytearray(seed)
            mutated[index] = value
            handler = QuicHandler()
            handler.push(1.0, bytes(mutated), CLIENT, None)
            handler.push(1.1, bytes(mutated[:index]), SERVER, None)
            list(handler.finish())


@needs_crypto
def test_the_document_carries_the_session_record_shape():
    """
    The whole point of putting the TLS facts under `tls`.

    `cryptomon.analysis`, `pcapscan.export` and the dashboard read these
    paths off a TCP session record; a QUIC record that used different names
    would need every one of them changed, and would be a second shape to
    keep in step.
    """
    dcid = b'\x17' * 8
    handler = QuicHandler()
    handler.push(1.0, build_initial(dcid, crypto_frame(0, client_hello()),
                                    pad_to=1162), CLIENT, None)
    handler.push(2.5, build_initial(dcid, crypto_frame(0, server_hello()),
                                    from_client=False, scid=b'\x18' * 8),
                 SERVER, None)
    document = list(handler.finish())[0]
    assert document['ptype'] == 'session'
    assert document['ts'] == 1.0
    assert document['duration'] == 1.5
    for field in ('hostname', 'ech', 'ja4', 'ja4s', 'ciphersuite',
                  'kex_group', 'tls_versions', 'proposed', 'selected',
                  'resumption', 'hello_retry_request', 'messages'):
        assert field in document['tls'], field
    assert set(document) >= {'ptype', 'eth', 'ts', 'duration', 'tls', 'quic'}


@needs_crypto
def test_the_router_finds_and_drives_this_handler():
    """End to end through the seam, not around it."""
    dcid = b'\x19' * 8
    router = DatagramRouter([QuicHandler])
    datagram = _fake_datagram(CLIENT)
    router.flows.clear()
    packet = build_initial(dcid, crypto_frame(0, client_hello()), pad_to=1162)
    router.push(1.0, _frame(packet), datagram)
    documents = list(router.finish())
    assert len(documents) == 1
    assert documents[0]['tls']['hostname'] == 'localhost'
    assert router.stats['flows_quic'] == 1


class _Datagram:
    def __init__(self, endpoints, payload_offset, payload_end):
        self.endpoints = endpoints
        self.payload_offset = payload_offset
        self.payload_end = payload_end
        self.ip_total_len = payload_end
        self.version = 4


def _frame(payload):
    return b'\x00' * 42 + payload


def _fake_datagram(key):
    endpoints = {'src': {'ipv4': key.src, 'port': key.sport},
                 'dst': {'ipv4': key.dst, 'port': key.dport}}
    return _Datagram(endpoints, 42, 42 + 1250)


def test_handler_is_exported_under_the_name_the_router_looks_for():
    assert HANDLER is QuicHandler
    assert QuicHandler.name == 'quic'
    assert 443 in QuicHandler.ports


# --------------------------------------------------------------------------
# degrading without `cryptography`
# --------------------------------------------------------------------------
def test_without_cryptography_the_flow_is_still_reported(monkeypatch):
    """
    `pcapscan` runs on a stock python:3.11-slim with nothing installed.

    Without the AES this cannot read a handshake, and the contract is the
    same one `pcapscan.sessions` keeps when it cannot parse a certificate:
    report what is known, label what is missing, never fail silently.
    """
    import pcapscan.quic as quic
    monkeypatch.setattr(quic, 'HAVE_CRYPTO', False)
    monkeypatch.setattr(quic, '_ECB_BLOCK', None)
    monkeypatch.setattr(quic, '_GCM_OPEN', None)
    packet = (b'\xc0' + VERSION_1.to_bytes(4, 'big') + b'\x08' + b'\xaa' * 8
              + b'\x00' + b'\x00' + encode_varint(1200) + b'\x00' * 1200)
    handler = quic.QuicHandler()
    handler.push(1.0, packet, CLIENT, None)
    document = list(handler.finish())[0]
    assert 'tls' not in document
    assert document['quic']['packets']['initial'] == 1
    assert document['quic']['version_name'] == 'v1'
    assert document['quic']['handshake_unreadable'] == \
        'cryptography is not installed'


def test_detection_still_works_without_cryptography(monkeypatch):
    import pcapscan.quic as quic
    monkeypatch.setattr(quic, 'HAVE_CRYPTO', False)
    packet = (b'\xc0' + VERSION_1.to_bytes(4, 'big') + b'\x08' + b'\xaa' * 8
              + b'\x00' + b'\x00' + encode_varint(1200) + b'\x00' * 1200)
    assert quic.QuicHandler.detect(packet, CLIENT) is True


# --------------------------------------------------------------------------
# real bytes, off the wire
# --------------------------------------------------------------------------
# Two Initial packets from one Chrome connection in
# CryptomonData/UC_1-Common_Apps-Mac_PCAPs/2024-12-11_UC1_Chrome_Mac.pcap.
# Together they carry one 1736-byte ClientHello offering
# X25519Kyber768Draft00 -- the case this whole module exists for, since it is
# the post-quantum offers that are too large to fit in a single packet.
CHROME_CLIENT_INITIAL_0 = (
    'c10000000108ca07d73f8942fd0c000044d0052da02089b1d9e2234233a7ee559a66'
    '4f830359150622083446451adf9b4f39d02e8896b501e423c433074e8e7473256846'
    '711f53776f2bfb1387ffd006cbaddc861d0d101b5b808c8f6bde37c66e09bfbd3411'
    'b223d0354f248ca5730eea85c58b210066e316131d229d385e2f1d098b7c9be6a85b'
    'd080f6502ffa7706be35b028f6b2612b954ee6e2f293c25b51608d5f1709b77216af'
    '7afed3407de82866d1f6c11dad29160d5843eefd9b96580dbabbf024551da4f1e6fc'
    'd61d6477121be5afa7aa43170fd890c5d8b60df6816c763106654dc784817c259817'
    '3c7ef0c7385c6f0762fed3503933c3e213a14c50add77455f38299c430dbc0ff66c5'
    '24bc1807277938b06b0c0e836648193ba36c34fa78e13f48f9ef877d395440d8672b'
    '19a56120826cedf4a03015699d4a39dbedcda763264827cc8c5e9b3d8fda84ac269e'
    '7a3a8ad50042e7e97a9fa7557d1fac705e034b2794e0b7e121b4c7185746cc27b56f'
    'd4be4867cd0cf28147effc3b0d9068b4a729784c92abf87c8a0f3c5dca8a5e606483'
    'e40a8f1c3a2593bea202a1c287d62741baecbd307294455295237f85c4be55438697'
    'e0f22dc8e3089532031fa5a7564334c5b08d97841f2f6f3b463ea23f6568990fb06e'
    'dec50b0846e6a0a10bd43bc5db8540fa52e7a39d7db26355f63b91df00c62fee97b2'
    'a1ec05fa98f255d656de667ff628db45706c656317d6d293ebdb4618de832c7cba1f'
    '694871903a6a96261bb4d06a04753bf24a89e804cdc15010610549c81ea742cd2046'
    '7dd4cac8e36dff13ce4b10ae1f5672a1787de7ef0175b5fc683d4279156b2672be45'
    'f98d717ba72b8d7136726450a43c09a21cc73d61a91f4e6b7f617552d5445654843e'
    'dac3f8d52d6bd3dc9638e0d531acc7a59f22ad0532d5f6a979f0b999b03497e0aa94'
    '1eac8817a2c63a26d9bd47a61c8158f2ddc9a89be7435f1c68028282562281c0e01f'
    '9cf62f3d2bb01dac84372e4b02be9921e9238441f8eae842d47b89c0e1719739cb01'
    '52d6d6211286a2ed1b1ca10a74dfab9bb22d33b3da4251710d1a5a410b4095e4a190'
    'de6f730af05b3dee6f75524789c99970f716dce6f5c938e4a1f70fbdfdcd11bbdccb'
    'df12ae7617fdd2aec8a73ba3b0ee19b957cdc7c89ece6ae1852fd31bf584ec7d3411'
    'e3a8ebf8c86413c8fef9672dc706511144a131ff29eec29453e8671082a544c7b738'
    'd9980cdb89c0bb5f556fdde1559b33ee1ee503acf1377f053e9a9b6824a5dca742c4'
    '908f38af8645a41aecd4e4b411e84ac0cbed4fb1d895064ab483ce912e9479c79bb4'
    '3cdd18ad0869d39747793cb98f5c1fe5cbb36015f7260310eea807a556711b2bd2c6'
    '873bb0f26aefdfbe6bd0b2738de8bdd06576754f8fda1bf5436ed16a0f45c58edf56'
    '3dd56a6724db2be57a0dc428f189339629e893eb1f37a58955d4534e064bd0007fcf'
    'a93d58f066f2fac1729b2757b22e48f90ef3b4692d1553ea6fe3b54ae7b00904654e'
    '03b8b486dd3c247fe63ac84c33c6d23b631217790ef64d088fb6c808864e08d149f2'
    '410882fc53f6531882358871d2bd4e030c43d276468eda2dc8151f4fb0636046e769'
    '3828f1e69435384e88902b40279658831b067aea62bd1f7cf09b11f4ece2fe0a96da'
    '2a5e7a373cadbe8d90774c4c5cc8db8d6a445a2b23d0ad8817ba98cc9c6e8d8a598c'
    '9d0c25d603709a4cf9ac1885165695dfda7b73d040a4a1d503f1'
)

CHROME_CLIENT_INITIAL_1 = (
    'ca0000000108ca07d73f8942fd0c000044d0265e3bb80c84c3d405bf8af7e116a4e1'
    '2d666ec1d4420a310161e9280da3a96508aa9ccf7a48d11a615cae40df1a01e0df8f'
    'b250e6f97d4a610fe2c902a99b222758dda186ce22a8cee7ad8ed4cee9f772ffae8f'
    '5790cb7970e947dd9a549a78057c1a71a0b3148e513aaf9cba9d8ccbd04cefc69d86'
    '8033907849cc9a62c00640d3800e898993a904dc58a3e413db2646f8b350f83f5996'
    '31d4491b08fdc8c3684e5606e67a3fe8e9851a7537cf72431e105eb13858e3c4d27e'
    'd24e8cfcc9cabd7ac9077b17ec4c895af9ac46abf8037cee4811c46dee253ae235f8'
    'ea42f700568e7748578ca5798d1d3e9aa8197f95ea3a64b9e29610a67b2716598f16'
    '5ec2202105b2867b011d118b89775fceda0021ce08c4701e9d5fb75005b1c4aab994'
    'a6e28f56b466d89f72f2b56abe795af8b43de63698afed5da873848f183128783f07'
    '1b36e72799dcb3fac39eaffb0c0bb3f20a7bc320f123062d6aada426964bd3645d00'
    'a998b78069842f02d1e0aad785533138830e1c8b9fca1f578f0b5c3922571a85809e'
    'dedb66677a8d6ba291887881271a236ebdb887b0b60da5c3d2a288fa2e611b853e9b'
    'a0171b1024acdd0eebdf6634a09437eadf7a4db9097c7a6807766e7e7cff20feb41a'
    '3948e283ea05307e3ae19c1fc67735718a386bfdd4126c1371f2ee32f6ba4f8a82c9'
    'f5a227b381941f80db80d5e553accaab6411b743f6a92780738a8120c39fce089f5e'
    '405f086d88bcb383a66106ea7a83754f32ddd5f766d70af052ce9e90b666e2fa55dd'
    '5315ff9ac141a0419162ef498510633d839e66ba5d61909cb14e329dc988d126de21'
    'fe23a1281c2c65ef10827d444b1c4cc798085163591f90d8ded7161eb0fcb891c1fd'
    'c014f524a765e97d99f9e816ecf4dbac9ef558a56c94e240247fc2fea33ee0df07be'
    'a600b290411f23d69b43f7e9ed697f6551200565c1d884b96e0da682dc39ccf6878f'
    '2acf9d8a6384479e776f3154ccc16c588e6eac5552cc03885782e73ca0f807e6cdaf'
    '80c47d01b373a747d372490242cf7a000b4b94df74098084bd4941ff750bfbf50942'
    'f8889bea0eb79a219af030bdc49eef325e02141fd6dc959628df7a0314cdc4e74f36'
    '178af27bdf3eec5200473de8779103913434a93ea27e76b4435c0e85e26476707306'
    '3b7ff623cd483ea244829380a4f476d05054e084131618eb70c3fc553b9957c4a4b6'
    'b0ecc11a4adcd66c4e3125be677be1ca6b6793707185658a478ffbc19e86369325bd'
    '6ac99fa5b43d3b7f8a6d1528ba0eef250623c07cd035eae803e513d2567ac8a328df'
    '2b0b08ae80c71acfeeec09cfbc268d365c600bbe170d7516651d240ed73dfd081a61'
    '7445dd6d4a335aeb11eeb765d199ee26b5c1811b4b0703bb4a0608b38b0e5ab97376'
    '373511f9d00675d617ce466ea612d69f613334fa1884cc7b6cace7215f1980741053'
    '21c3304337a695ffb29a22d3bbe64a0989f1fd6471265c0e5e5fc13dd1b2e218b491'
    'bfb5bf9377604f614cd1538875a318dcbc7f3bbb4b3bc99191dc21c2b734b63f31d1'
    'ebfcba14e78c6ced32de2c1a155b8fce2600e7739c68c11a1768246d672fad925d36'
    '20454ac5b9313ed0f4273d3dc17a6704dd357d1152a552cd097f0adfd725cc1b89b5'
    '2180614c9b56bb03b58b5cf423f97ac1b09dbcd23cccb913444d684be17f469f44a0'
    '7135f99f29974c550e285286648b1041b2500ea5e6861388addd'
)

# One server Initial from a Firefox connection in
# CryptomonData/UC_1-Common_Apps-Mac_PCAPs/2024-12-11_UC1_Firefox_Mac.pcap,
# carrying a whole ServerHello in 138 bytes. Its connection ID is ten bytes
# long, which is worth having: everything else in the corpus uses eight, and
# a parser that assumed a fixed width would pass every other test here.
FIREFOX_SERVER_INITIAL = (
    'c60000000103c1a84408f162f047a045e467004075fc7f065faffa914fdc19c3bf42'
    '2182a33c86aa139096f3ba091644539ac90e68c66db98db467011893a4d8658b7dab'
    '405f86573718bfeaa32cf7064b2e28bcb749c0598e557d8e67f5ef63a57f7c54d9c9'
    '8d7bdfe2206df92d2768c47316f688aaf7f5d27045e95ea0159d30cf20fa31af9cbe'
    '81d2'
)
FIREFOX_ODCID = bytes.fromhex('1162f047a045e4676fee')


@needs_crypto
def test_real_chrome_post_quantum_client_hello():
    """
    Chrome's own bytes: decrypted, reassembled across two datagrams, parsed.

    Every value asserted here comes from `cryptomon.parsers.tls` -- the same
    code that parses a TCP ClientHello -- which is the claim this PR rests
    on. The JA4 ends `h3`, which only an ALPN of HTTP/3 produces, so it could
    not have come from a TCP handshake.
    """
    handler = QuicHandler()
    handler.push(1.0, bytes.fromhex(CHROME_CLIENT_INITIAL_0), CLIENT, None)
    handler.push(1.25, bytes.fromhex(CHROME_CLIENT_INITIAL_1), CLIENT, None)
    document = list(handler.finish())[0]
    tls = document['tls']
    assert tls['hostname'] == 'google-ohttp-relay-safebrowsing.fastly-edge.com'
    assert tls['ja4'] == 't13d0311h3_55b375c5d22e_5a1f323ef56d'
    assert tls['ech'] == 'offered'
    assert tls['tls_versions'] == ['TLSv1.3']
    assert tls['proposed']['kex_group'] == 'X25519Kyber768Draft00'
    assert tls['proposed']['groups'] == ['X25519Kyber768Draft00', 'x25519',
                                         'secp256r1', 'secp384r1']
    assert tls['proposed']['alpn'] == ['h3']
    assert document['quic'] == {
        'version': '0x00000001',
        'version_name': 'v1',
        'datagrams': 2,
        'packets': {'initial': 2},
        'coalesced_packets': 0,
        'initials_decrypted': 2,
        'initials_undecryptable': 0,
        'crypto_bytes': {'client': 1736, 'server': 0},
        'initial_dcid': 'ca07d73f8942fd0c',
    }


@needs_crypto
def test_real_chrome_hello_needs_both_packets():
    """
    Half the hello is not a hello.

    Feeding only the first Initial must produce no ClientHello at all rather
    than a partial one -- 1200 bytes of a 1736-byte message parses to
    something, and that something would be wrong.
    """
    handler = QuicHandler()
    handler.push(1.0, bytes.fromhex(CHROME_CLIENT_INITIAL_0), CLIENT, None)
    document = list(handler.finish())[0]
    assert 'tls' not in document
    assert document['quic']['initials_decrypted'] == 1
    assert document['quic']['crypto_bytes']['client'] < 1736


@needs_crypto
def test_real_firefox_server_hello():
    """A real ServerHello, decrypted with the client's original DCID."""
    packet = bytes.fromhex(FIREFOX_SERVER_INITIAL)
    header = parse_long_header(packet, 0)
    assert header.kind == 'initial'
    assert header.dcid == bytes.fromhex('c1a844')
    assert header.end == len(packet)
    number, plaintext = decrypt_packet(
        packet, header, initial_keys(FIREFOX_ODCID, VERSION_1, False))
    assert number == 1
    frames = list(iter_crypto_frames(plaintext))
    assert [offset for offset, _data in frames] == [0]
    messages = split_handshake(frames[0][1])
    assert [message.name for message in messages] == ['server_hello']
    parsed = parse_hello_message(messages[0].msg_type, messages[0].body)
    assert parsed['tls']['ciphersuite'] == 'TLS_AES_128_GCM_SHA256'
    assert parsed['tls']['kex_group'] == 'x25519'
    assert parsed['tls']['ja4s'] == 't130200_1301_234ea6891581'


@needs_crypto
def test_real_server_initial_refuses_the_wrong_connection_id():
    """
    The mistake this is here to catch: deriving from the DCID in the server's
    own header, which is the client's Source Connection ID and not the
    original. It produces keys, it produces a mask, and it decrypts nothing.
    """
    packet = bytes.fromhex(FIREFOX_SERVER_INITIAL)
    header = parse_long_header(packet, 0)
    wrong = initial_keys(header.dcid, VERSION_1, False)
    assert decrypt_packet(packet, header, wrong) is None
    also_wrong = initial_keys(FIREFOX_ODCID, VERSION_1, True)
    assert decrypt_packet(packet, header, also_wrong) is None
