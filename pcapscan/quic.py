"""
The TLS 1.3 handshake inside QUIC, read without keys.

**The gap this closes.** A growing share of the web's TLS handshakes do not
happen over TCP. They happen inside QUIC, on UDP, and until this module every
one of them was invisible to a tool whose entire purpose is to say what
cryptography is in use. The corpus makes the size of that concrete: 11,722
QUIC packets on UDP 443, 738 of them long-header, and not one byte of them
reached a parser. A post-quantum readiness report built on the TCP half of a
capture is a report on a shrinking sample.

**No keys are needed, and that is not a weakness in QUIC.** RFC 9001 section
5.2 derives the protection keys for *Initial* packets from a constant
published in the RFC and the client's Destination Connection ID, which every
Initial packet carries in the clear. Anyone holding the capture can derive
them; the secrecy of a QUIC handshake never rested on them. They exist to
stop middleboxes ossifying the wire format, not to hide the ClientHello --
which, over TCP, is sent in plaintext anyway. Everything after the Initial
flight (EncryptedExtensions, Certificate, CertificateVerify, Finished) is
protected by keys derived from the handshake secret and is *not* readable,
exactly as it is not readable in TLS 1.3 over TCP. That boundary is reported
rather than glossed: `tls.certificates_unreadable` says "not readable", which
is a different claim from "not sent".

**The hello inside QUIC is the same hello.** This module does not parse a
ClientHello. It reassembles CRYPTO frames into the handshake byte stream and
hands the messages to `pcapscan.sessions.Session`, which is the same object
the TCP path builds, calling the same `cryptomon.parsers.tls` code. JA4, the
extension census, ECH, the key-share group, the sigalgs, resumption and the
HelloRetryRequest pair all come out identical to their TCP equivalents and
land at the same paths, so `cryptomon.analysis`, the CBOM export, the CSV
columns and the dashboard pick QUIC up without a line of change. A second
hello parser would have been a second set of bugs and a second thing to keep
in step with the RFC.

**What is genuinely QUIC-specific** -- the version, the connection IDs, the
packet census, whether a Retry happened -- goes in a `quic` block beside
`tls`, not mixed into it.

Four things about the wire format are easy to get wrong and are called out
where they happen:

* The packet number length lives in the first byte's low two bits, and those
  bits are themselves header-protected (section 5.4). Reading them before
  removing the mask yields a plausible wrong answer rather than an error.
* The Initial keys for *both* directions come from the client's *original*
  Destination Connection ID. The server's Initial carries a different DCID --
  the client's Source Connection ID -- and deriving from it decrypts nothing.
* A datagram may carry several QUIC packets back to back (section 12.2). The
  server's reply routinely coalesces an Initial holding the ServerHello with
  a Handshake packet; stopping after the first packet loses the second.
* A ClientHello with post-quantum key shares does not fit in one packet. It
  arrives as CRYPTO frames at several offsets, across several packets and
  several datagrams, and must be reassembled by offset before it parses.

**`cryptography` is optional.** `pcapscan` is meant to run on a stock
`python:3.11-slim` with nothing installed, and it still does: the key
schedule here is stdlib HMAC, and only AES-ECB and AES-GCM need the package.
(The AES-ECB is RFC 9001 section 5.4.3's header-protection mask, which is a
single-block mask generator and not a mode choice this project made -- see
`_aead.ecb_block`, which is the line static analysers flag.)
Without it a QUIC flow is still detected, still counted, and still reported
-- with `quic.handshake_unreadable` saying why there is no `tls` block. That
is the same contract `pcapscan.sessions` keeps when it cannot parse a
certificate and carries the raw DER instead: degrade with a label, never
silently.

Every byte read here is attacker-chosen and arrives through an upload form,
so every length is validated against its parent, every loop is bounded, and
no length field is ever allowed to drive an allocation.
"""
import collections
import hashlib
import hmac
from typing import NamedTuple

from cryptomon.utils import PARSE_STATS
from pcapscan.datagrams import DatagramKey
from pcapscan.records import MAX_MESSAGE_LEN, MESSAGE_HDR_LEN, Message
from pcapscan.sessions import Session

# --------------------------------------------------------------------------
# versions
# --------------------------------------------------------------------------
# The only two versions whose Initial salt is published, and therefore the
# only two whose handshake this can read. Every long-header packet in the
# capture corpus is version 1.
VERSION_1 = 0x00000001                    # RFC 9000
VERSION_2 = 0x6B3343CF                    # RFC 9369
VERSION_NEGOTIATION = 0x00000000          # RFC 8999 section 6

# RFC 9001 section 5.2 and RFC 9369 section 3.3.1. Constants, printed in the
# RFCs, not secrets -- see the module docstring.
INITIAL_SALT = {
    VERSION_1: bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'),
    VERSION_2: bytes.fromhex('0dede3def700a6db819381be6e269dcbf9bd2ed9'),
}

# v2 renames every key-derivation label rather than reusing v1's, so that a
# v1 endpoint cannot be tricked into deriving v2 keys (RFC 9369 section 3.3.1).
KEY_LABELS = {
    VERSION_1: (b'quic key', b'quic iv', b'quic hp'),
    VERSION_2: (b'quicv2 key', b'quicv2 iv', b'quicv2 hp'),
}

# The long-header type bits mean different things in the two versions: v2
# rotates them, again to break ossification (RFC 9369 section 3.2). Reading
# v2 with v1's table calls an Initial a Retry.
PACKET_TYPES = {
    VERSION_1: {0: 'initial', 1: 'zero_rtt', 2: 'handshake', 3: 'retry'},
    VERSION_2: {1: 'initial', 2: 'zero_rtt', 3: 'handshake', 0: 'retry'},
}

# Versions this recognises as QUIC but cannot read. Naming them is worth the
# few lines: a flow reported as "QUIC, draft-29, not decryptable" is a fact,
# and the same flow left in `udp_flows_unrecognised` is a hole.
DRAFT_RANGE = (0xFF000000, 0xFF0000FF)    # draft-ietf-quic-transport-NN
MVFST_RANGE = (0xFACEB000, 0xFACEB0FF)    # Facebook's mvfst

CLIENT_LABEL = b'client in'
SERVER_LABEL = b'server in'

# --------------------------------------------------------------------------
# bounds
# --------------------------------------------------------------------------
# RFC 9000 section 17.2: a version-1 connection ID is at most 20 bytes. The
# field is a full byte, so without this check a datagram can claim a 255-byte
# connection ID and walk the header pointer past anything.
MAX_CID_LEN = 20

# A datagram may coalesce several packets (section 12.2). Chrome sends at
# most three (Initial + Handshake + 1-RTT); the ceiling is generous and
# exists so that a datagram of 1500 one-byte-advance packets cannot cost 1500
# header walks.
MAX_PACKETS_PER_DATAGRAM = 8

# The handshake stream this will hold per direction. A ClientHello with an
# ML-KEM share is about 2KB; the largest in the corpus is under 4KB. 64KB
# matches the per-flow ceiling in `pcapscan.datagrams` and is far above
# anything a real handshake needs, so a CRYPTO frame claiming an offset of
# 2**62 is refused rather than sized.
MAX_CRYPTO_BYTES = 65536
MAX_CRYPTO_CHUNKS = 64

# Frames walked in one decrypted payload. PADDING is consumed in runs rather
# than one frame at a time, so a 1200-byte padded Initial costs two or three
# iterations, not a thousand.
MAX_FRAMES_PER_PACKET = 256

# ACK ranges walked in one ACK frame. The count is a variable-length integer
# and can claim 2**62; the frame it is in cannot be longer than the packet,
# so anything past this is a lie and the frame walk stops.
MAX_ACK_RANGES = 256

# Handshake messages taken out of one direction's stream. A hello, a retried
# hello and the server's answer is three; the rest of the flight is encrypted.
MAX_MESSAGES = 16

# Versions listed in a Version Negotiation packet before we stop reading.
MAX_VERSIONS_OFFERED = 32

# QUIC frame types this needs to know (RFC 9000 section 12.4). An Initial
# packet may carry only these, which is why the walk can stop dead on
# anything else rather than trying to resynchronise.
FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02
FRAME_ACK_ECN = 0x03
FRAME_CRYPTO = 0x06
FRAME_CONNECTION_CLOSE = 0x1C
FRAME_CONNECTION_CLOSE_APP = 0x1D

# Header protection samples 16 bytes starting 4 bytes into the packet number
# field, which is why every protected packet is at least 20 bytes long from
# there (RFC 9001 section 5.4.2). Used as a structural test as well as a
# bound: a long header whose Length is below this is not a QUIC packet.
SAMPLE_LEN = 16
SAMPLE_OFFSET = 4
AEAD_TAG_LEN = 16
MIN_PROTECTED_LEN = SAMPLE_OFFSET + SAMPLE_LEN


# --------------------------------------------------------------------------
# the optional half
# --------------------------------------------------------------------------
def _aead():
    """
    AES-ECB and AES-GCM, if this installation has `cryptography`.

    Returns (ecb_block, gcm_open) or (None, None). The import is deliberately
    not at module scope: `pcapscan.datagrams.handlers()` treats an
    ImportError naming *this* module as absence and re-raises anything else,
    so a top-level `from cryptography import ...` on a machine without the
    package would take the whole UDP path down instead of degrading. The same
    reasoning as `pcapscan.sessions._certificate_parser`.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                            modes)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None, None

    def ecb_block(key, block):
        """
        One AES block, encrypted. The header-protection mask generator.

        **The ECB below is mandatory, not an oversight.** RFC 9001 section
        5.4.3 defines header protection for every AES-based cipher suite as

            mask = AES-ECB(hp_key, sample)

        of which the first five bytes are used. Static analysers flag
        `modes.ECB()` on sight, and in general they are right to: ECB leaks
        equality between blocks, which is what makes it unusable for a
        message. None of that applies here. This encrypts a single 16-byte
        block; the input is a sample of somebody else's ciphertext, not a
        plaintext; the output is a one-time mask that is XORed and discarded,
        never stored or transmitted; and `hp_key` is a per-connection secret
        derived in `initial_keys`. There is no second block for the first to
        be compared against, so the property ECB fails to provide is not one
        this use has any need of.

        Nor is there a choice to make. The mask has to be computed exactly as
        the sender computed it or the packet number does not come back, so
        any other construction would simply fail to decode QUIC. The
        ChaCha20 suites use ChaCha20 for the same job (section 5.4.4); this
        module only ever opens Initial packets, which section 5.2 fixes to
        AEAD_AES_128_GCM, so AES is the only branch reachable from here.

        For a scanner waiver: RFC 9001 section 5.4.3, single-block mask
        generation, not confidentiality. The caller is
        `remove_header_protection`.
        """
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return encryptor.update(block) + encryptor.finalize()

    def gcm_open(key, nonce, ciphertext, aad):
        """AES-128-GCM open, or None when the tag does not verify."""
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except Exception:                 # noqa: BLE001 -- InvalidTag, mostly
            # A failed tag is the normal outcome of guessing wrong about
            # which secret or which connection ID a packet belongs to, and
            # this function is used to *find out* which. It is not an error.
            return None

    return ecb_block, gcm_open


_ECB_BLOCK, _GCM_OPEN = _aead()
HAVE_CRYPTO = _ECB_BLOCK is not None


# --------------------------------------------------------------------------
# the key schedule (RFC 9001 section 5.2, RFC 8446 section 7.1)
# --------------------------------------------------------------------------
# HKDF is RFC 5869 and is eight lines of HMAC. Writing it here rather than
# importing `cryptography`'s keeps the entire key schedule -- the part that
# is specific to QUIC and therefore the part worth testing -- runnable on a
# checkout with no third-party packages at all, and leaves `cryptography`
# needed only for the AES this cannot reimplement. The values it produces are
# checked against RFC 9001 Appendix A in tests/test_quic.py.
def hkdf_extract(salt, ikm):
    """RFC 5869 section 2.2. Extract is exactly HMAC(salt, ikm)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(secret, info, length):
    """RFC 5869 section 2.3, SHA-256."""
    out = bytearray()
    block = b''
    counter = 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def expand_label(secret, label, length):
    """
    TLS 1.3's HKDF-Expand-Label (RFC 8446 section 7.1), which QUIC reuses.

    The `tls13 ` prefix is part of the label, not decoration: it is what
    stops a key derived for one protocol being derivable for another. The
    context is always empty in the Initial schedule.
    """
    prefixed = b'tls13 ' + label
    info = (length.to_bytes(2, 'big') + bytes([len(prefixed)]) + prefixed
            + b'\x00')
    return hkdf_expand(secret, info, length)


def initial_keys(dcid, version, from_client):
    """
    (key, iv, hp) for one direction of one connection's Initial packets.

    `dcid` is the Destination Connection ID from the client's *first* Initial
    packet -- the "original" DCID. Both directions derive from it. Using the
    DCID off the server's own Initial instead is the classic mistake here:
    that field holds the client's Source Connection ID, and the tag simply
    never verifies.
    """
    secret = hkdf_extract(INITIAL_SALT[version], bytes(dcid))
    side = expand_label(secret, CLIENT_LABEL if from_client else SERVER_LABEL,
                        32)
    key_label, iv_label, hp_label = KEY_LABELS[version]
    return (expand_label(side, key_label, 16),
            expand_label(side, iv_label, 12),
            expand_label(side, hp_label, 16))


# --------------------------------------------------------------------------
# header parsing (RFC 8999 section 5.1, RFC 9000 section 17.2)
# --------------------------------------------------------------------------
def read_varint(buf, offset):
    """
    RFC 9000 section 16. Returns (value, next_offset), or (None, offset).

    The top two bits of the first byte give the encoded width, so a
    single-byte integer cannot claim eight bytes of buffer. None means the
    buffer ends inside the integer -- a refusal, never a zero, because a zero
    length and a truncated length field mean different things.
    """
    if offset < 0 or offset >= len(buf):
        return None, offset
    width = 1 << (buf[offset] >> 6)
    if offset + width > len(buf):
        return None, offset
    value = buf[offset] & 0x3F
    for index in range(1, width):
        value = (value << 8) | buf[offset + index]
    return value, offset + width


def version_name(version):
    """A label for a version number, or None if it is not QUIC's."""
    if version == VERSION_NEGOTIATION:
        return 'version_negotiation'
    if version == VERSION_1:
        return 'v1'
    if version == VERSION_2:
        return 'v2'
    if DRAFT_RANGE[0] <= version <= DRAFT_RANGE[1]:
        return 'draft-{0}'.format(version & 0xFF)
    if MVFST_RANGE[0] <= version <= MVFST_RANGE[1]:
        return 'mvfst-0x{0:08x}'.format(version)
    if version & 0x0F0F0F0F == 0x0A0A0A0A:
        # RFC 9000 section 15 reserves this pattern for versions that exist
        # only to provoke a Version Negotiation reply. Seeing one is a
        # working client exercising the mechanism, not a parse failure.
        return 'reserved'
    return None


class LongHeader(NamedTuple):
    """One QUIC long-header packet located inside a datagram."""
    start: int              # first byte of this packet within the datagram
    first: int              # the first byte, still header-protected
    version: int
    label: str              # version_name(version)
    kind: str               # 'initial', 'handshake', 'retry', ...
    dcid: bytes
    scid: bytes
    token: bytes            # Initial only; empty otherwise
    pn_offset: int          # where the protected packet number starts, or -1
    end: int                # one past this packet's last byte


def parse_long_header(buf, start=0):
    """
    Locate one long-header packet at `start`, or None.

    Every field is checked against the buffer it came from before it is used
    to move the cursor, because all of it is attacker-chosen: the two
    connection-ID lengths are single bytes that can each claim 255, and the
    token and payload lengths are variable-length integers that can each
    claim 2**62.

    `end` is what makes walking a coalesced datagram possible: for the three
    packet types that carry a Length field it is exactly where the next
    packet begins. Retry and Version Negotiation have no Length and run to
    the end of the datagram, so nothing can follow them.
    """
    # Seven bytes is the shortest a long header can be: the form byte, four
    # of version, and a length byte for each connection ID. Checking five and
    # then indexing the sixth is an off-by-one that only a datagram of
    # exactly five bytes reaches, which is why it needs a test rather than a
    # reading.
    if start < 0 or start + 7 > len(buf):
        return None
    first = buf[start]
    if not first & 0x80:
        return None                       # short header: 1-RTT, not this
    version = int.from_bytes(bytes(buf[start + 1:start + 5]), 'big')
    label = version_name(version)
    if label is None:
        return None
    if version != VERSION_NEGOTIATION and not first & 0x40:
        # The fixed bit. RFC 9287 lets a connection turn it off, but only
        # after it has been negotiated in transport parameters -- which
        # cannot have happened yet in a long-header packet. A Version
        # Negotiation packet's first byte is unconstrained (RFC 8999
        # section 6), so it is exempt.
        return None

    offset = start + 5
    dcid_len = buf[offset]
    offset += 1
    if dcid_len > MAX_CID_LEN or offset + dcid_len + 1 > len(buf):
        return None
    dcid = bytes(buf[offset:offset + dcid_len])
    offset += dcid_len
    scid_len = buf[offset]
    offset += 1
    if scid_len > MAX_CID_LEN or offset + scid_len > len(buf):
        return None
    scid = bytes(buf[offset:offset + scid_len])
    offset += scid_len

    if version == VERSION_NEGOTIATION:
        return LongHeader(start, first, version, label, 'version_negotiation',
                          dcid, scid, b'', -1, len(buf))

    # Version 2 is the only version that rotates the type bits; every draft
    # and every reserved version this recognises lays its long header out
    # exactly as version 1 does, so that is the fallback. It is a label on a
    # packet this cannot decrypt either way, so being wrong about a future
    # version costs a counter name and no data.
    kind = PACKET_TYPES.get(version, PACKET_TYPES[VERSION_1])[
        (first >> 4) & 0x03]
    if kind == 'retry':
        # A Retry carries a token and a 16-byte integrity tag and nothing
        # else -- no packet number, no protected payload, and no Length, so
        # it is the last packet in its datagram.
        if offset + AEAD_TAG_LEN > len(buf):
            return None
        return LongHeader(start, first, version, label, kind, dcid, scid,
                          bytes(buf[offset:len(buf) - AEAD_TAG_LEN]), -1,
                          len(buf))

    token = b''
    if kind == 'initial':
        token_len, offset = read_varint(buf, offset)
        if token_len is None or token_len > len(buf) - offset:
            return None
        token = bytes(buf[offset:offset + token_len])
        offset += token_len
    length, offset = read_varint(buf, offset)
    if length is None or length > len(buf) - offset:
        # The declared payload runs past the datagram. This is the test that
        # makes detection safe: a random UDP payload that happens to start
        # with the right two bits and a real version number still has to
        # declare a length that lands inside itself.
        return None
    if length < MIN_PROTECTED_LEN:
        # Too short to hold the header-protection sample, so too short to be
        # a protected packet at all (RFC 9001 section 5.4.2).
        return None
    return LongHeader(start, first, version, label, kind, dcid, scid, token,
                      offset, offset + length)


def offered_versions(buf, header):
    """The version list from a Version Negotiation packet (RFC 8999 s6)."""
    out = []
    # The list starts straight after the source connection ID: five bytes of
    # form and version, then each ID's length byte and body.
    offset = header.start + 7 + len(header.dcid) + len(header.scid)
    while offset + 4 <= len(buf) and len(out) < MAX_VERSIONS_OFFERED:
        value = int.from_bytes(bytes(buf[offset:offset + 4]), 'big')
        out.append('0x{0:08x}'.format(value))
        offset += 4
    return out


# --------------------------------------------------------------------------
# packet protection (RFC 9001 sections 5.3 and 5.4)
# --------------------------------------------------------------------------
def decode_packet_number(largest, truncated, bits):
    """
    RFC 9000 Appendix A.3. Recover the full packet number from its low bits.

    Initial packet numbers start at zero and stay small, so in practice the
    truncated value *is* the packet number and this changes nothing. It is
    here because the one case where it matters -- a long Initial flight after
    a Retry, wrapping the one-byte encoding -- would otherwise produce a
    nonce that is wrong by 256 and a tag that does not verify, which reads as
    "undecryptable" rather than as the bug it is.
    """
    expected = largest + 1
    window = 1 << bits
    half = window >> 1
    candidate = (expected & ~(window - 1)) | truncated
    if candidate <= expected - half and candidate < (1 << 62) - window:
        return candidate + window
    if candidate > expected + half and candidate >= window:
        return candidate - window
    return candidate


def remove_header_protection(buf, header, hp_key, ecb_block=None):
    """
    Undo RFC 9001 section 5.4 for one packet. Returns (first_byte, pn_bytes).

    **The packet number's length is itself protected.** It is in the low two
    bits of the first byte, and those bits are masked; reading them before
    unmasking gives a length between 1 and 4 that is wrong three times in
    four, and the resulting AAD, nonce and ciphertext boundary are then all
    wrong together. So the mask comes first, the first byte is recovered,
    and only then is the length known -- which is also why the 16-byte
    sample is taken at a *fixed* offset of 4 into the packet number field,
    as if the number were always the maximum 4 bytes long.

    Returns (None, None) when the packet is too short to sample.
    """
    block = ecb_block or _ECB_BLOCK
    if block is None:
        return None, None
    sample_start = header.pn_offset + SAMPLE_OFFSET
    if sample_start + SAMPLE_LEN > header.end or header.end > len(buf):
        return None, None
    # `block` is AES-ECB over one 16-byte sample, which is what section 5.4.3
    # specifies and the only thing that reproduces the sender's mask. See the
    # docstring on `_aead.ecb_block` for why that is not the ECB misuse a
    # static analyser reads it as.
    mask = block(hp_key, bytes(buf[sample_start:sample_start + SAMPLE_LEN]))
    # Long headers spend four bits on the packet type and reserved bits, so
    # only the low four are masked; a short header would mask five.
    first = header.first ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    if header.pn_offset + pn_len > header.end:
        return None, None
    pn_bytes = bytes(a ^ b for a, b in
                     zip(buf[header.pn_offset:header.pn_offset + pn_len],
                         mask[1:1 + pn_len]))
    return first, pn_bytes


def decrypt_packet(buf, header, keys, largest_pn=-1, ecb_block=None,
                   gcm_open=None):
    """
    The plaintext of one protected packet, or None.

    `keys` is (key, iv, hp) from `initial_keys`. None means the packet did
    not decrypt under them, which is an answer rather than a failure: it is
    how this tells a client's packet from a server's, and a connection's
    packets from those of the connection that replaced it after a Retry.
    """
    opener = gcm_open or _GCM_OPEN
    if opener is None:
        return None
    key, iv, hp_key = keys
    first, pn_bytes = remove_header_protection(buf, header, hp_key, ecb_block)
    if first is None:
        return None
    packet_number = decode_packet_number(
        largest_pn, int.from_bytes(pn_bytes, 'big'), len(pn_bytes) * 8)
    body_start = header.pn_offset + len(pn_bytes)
    if header.end - body_start < AEAD_TAG_LEN:
        return None
    # The AAD is the whole header with protection removed -- the recovered
    # first byte, the untouched middle, and the recovered packet number.
    aad = (bytes([first]) + bytes(buf[header.start + 1:header.pn_offset])
           + pn_bytes)
    nonce = bytes(a ^ b for a, b in
                  zip(iv, (packet_number & ((1 << 62) - 1)).to_bytes(12,
                                                                    'big')))
    plaintext = opener(key, nonce, bytes(buf[body_start:header.end]), aad)
    if plaintext is None:
        return None
    return packet_number, plaintext


# --------------------------------------------------------------------------
# frames (RFC 9000 section 12.4)
# --------------------------------------------------------------------------
def iter_crypto_frames(plaintext):
    """
    Yield (offset, data) for every CRYPTO frame in a decrypted payload.

    An Initial packet may carry only PADDING, PING, ACK, CRYPTO and
    CONNECTION_CLOSE, so the walk can refuse anything else outright instead
    of hunting for the next plausible frame: the payload decrypted under an
    authenticated tag, so a frame type outside that set means the *parser* is
    out of step, and guessing where it resynchronises would invent frames
    that were never sent.
    """
    offset = 0
    frames = 0
    limit = len(plaintext)
    while offset < limit and frames < MAX_FRAMES_PER_PACKET:
        frames += 1
        kind = plaintext[offset]
        if kind == FRAME_PADDING:
            # Consumed as a run. A client Initial is padded to 1200 bytes,
            # so this is a thousand one-byte frames if walked singly.
            while offset < limit and plaintext[offset] == FRAME_PADDING:
                offset += 1
            continue
        if kind == FRAME_PING:
            offset += 1
            continue
        if kind == FRAME_CRYPTO:
            offset += 1
            crypto_offset, offset = read_varint(plaintext, offset)
            if crypto_offset is None:
                return
            length, offset = read_varint(plaintext, offset)
            if length is None or length > limit - offset:
                return
            yield crypto_offset, bytes(plaintext[offset:offset + length])
            offset += length
            continue
        if kind in (FRAME_ACK, FRAME_ACK_ECN):
            offset = _skip_ack(plaintext, offset + 1, kind == FRAME_ACK_ECN)
            if offset is None:
                return
            continue
        if kind in (FRAME_CONNECTION_CLOSE, FRAME_CONNECTION_CLOSE_APP):
            offset = _skip_connection_close(
                plaintext, offset + 1, kind == FRAME_CONNECTION_CLOSE)
            if offset is None:
                return
            continue
        PARSE_STATS['quic_unknown_frame'] += 1
        return


def _skip_varints(plaintext, offset, count):
    """Past `count` variable-length integers, or None if any is truncated."""
    for _ in range(count):
        value, offset = read_varint(plaintext, offset)
        if value is None:
            return None
    return offset


def _skip_ack(plaintext, offset, ecn):
    """Past one ACK frame, or None if it does not fit its payload."""
    offset = _skip_varints(plaintext, offset, 2)     # largest acked, delay
    if offset is None:
        return None
    ranges, offset = read_varint(plaintext, offset)
    if ranges is None or ranges > MAX_ACK_RANGES:
        # The count is a variable-length integer and the frame is bounded by
        # the packet, so a count this large cannot be honest. Refusing costs
        # the rest of one packet's frames; trusting it costs a loop of up to
        # 2**62 iterations reading past the end of the buffer.
        return None
    # The first range, then a (gap, length) pair for each of the rest, then
    # the three ECN counters if this is an ACK_ECN frame.
    return _skip_varints(plaintext, offset, 1 + ranges * 2 + (3 if ecn else 0))


def _skip_connection_close(plaintext, offset, transport):
    """Past one CONNECTION_CLOSE frame, or None."""
    value, offset = read_varint(plaintext, offset)        # error code
    if value is None:
        return None
    if transport:
        value, offset = read_varint(plaintext, offset)    # offending frame
        if value is None:
            return None
    reason_len, offset = read_varint(plaintext, offset)
    if reason_len is None or reason_len > len(plaintext) - offset:
        return None
    return offset + reason_len


class CryptoStream:
    """
    CRYPTO frames reassembled by offset into one handshake byte stream.

    The QUIC counterpart of `pcapscan.reassembly.Stream`, and small for the
    same reason `pcapscan.datagrams` is small: a CRYPTO frame states its own
    offset, so there is no sequence space to track and no wrap to handle.
    What it shares with TCP reassembly is the thing that matters -- a
    ClientHello carrying an ML-KEM key share is larger than one packet, so
    without this the only hellos ever parsed would be the small classical
    ones, and the statistic the tool exists to produce would be biased
    against exactly the traffic it is looking for.

    Bounded twice, because both bounds are reachable from the wire: a frame
    may claim an offset of 2**62, and a flow may send unbounded frames that
    never close the gap at zero.
    """

    __slots__ = ('chunks', 'octets', 'overflowed', 'gap')

    def __init__(self):
        self.chunks = {}
        self.octets = 0
        self.overflowed = False           # a cap was hit; data was dropped
        self.gap = False                  # set by assemble(): data lost

    def add(self, offset, data):
        if not data:
            return
        if offset < 0 or offset > MAX_CRYPTO_BYTES:
            self.overflowed = True
            return
        if (len(self.chunks) >= MAX_CRYPTO_CHUNKS
                or self.octets + len(data) > MAX_CRYPTO_BYTES):
            self.overflowed = True
            return
        if offset in self.chunks and len(self.chunks[offset]) >= len(data):
            return                        # a retransmission of what we have
        self.octets += len(data)
        self.chunks[offset] = data

    def assemble(self):
        """
        The contiguous run from offset zero. Stops at the first hole.

        A hole means a packet was lost, was not captured, or was dropped by
        the per-flow cap. Everything past it is real data at an unknown
        distance from the start, so splicing it on would corrupt the message
        boundaries rather than recover anything.
        """
        out = bytearray()
        self.gap = False
        for offset in sorted(self.chunks):
            data = self.chunks[offset]
            if offset > len(out):
                self.gap = True
                break
            overlap = len(out) - offset
            if overlap < len(data):
                out += data[overlap:]
        return bytes(out)


def split_handshake(stream):
    """
    Handshake messages out of a reassembled CRYPTO stream.

    This is `pcapscan.records.HandshakeStream` with the record layer taken
    away, and it borrows that module's header length, message ceiling and
    `Message` type rather than restating them. QUIC deletes the TLS record
    layer outright (RFC 9001 section 4): a CRYPTO stream is the concatenation
    of handshake messages and nothing else, with no content type, no version
    and no record length. Feeding these bytes to `HandshakeStream` would mean
    fabricating record headers around them so that it could strip them off
    again, and the first thing it does with a fabricated header is decide the
    stream is malformed.
    """
    out = []
    offset = 0
    while offset + MESSAGE_HDR_LEN <= len(stream) and len(out) < MAX_MESSAGES:
        msg_type = stream[offset]
        length = ((stream[offset + 1] << 16) | (stream[offset + 2] << 8)
                  | stream[offset + 3])
        if length > MAX_MESSAGE_LEN:
            break
        end = offset + MESSAGE_HDR_LEN + length
        if end > len(stream):
            break                         # the rest has not arrived
        out.append(Message(msg_type,
                           bytes(stream[offset + MESSAGE_HDR_LEN:end])))
        offset = end
    return out


# --------------------------------------------------------------------------
# the handler
# --------------------------------------------------------------------------
class QuicHandler:
    """
    One QUIC flow, from long headers to a session document.

    Built per flow by `pcapscan.datagrams.DatagramRouter`, fed one datagram
    at a time in capture order, and asked once at the end for its documents.
    """

    name = 'quic'
    # A hint used only to order the detectors. Detection is by content: 1% of
    # this corpus's port-443 flows are not what the port says, and QUIC on a
    # non-standard port still has to be found.
    ports = frozenset({443, 80})

    @staticmethod
    def detect(payload, key):
        """
        Does this flow's first datagram open with a QUIC long header?

        Three things must hold together, and it is the combination that makes
        this safe to run on every new UDP flow: the form and fixed bits, a
        version number this recognises, and -- for the packet types that
        carry one -- a declared payload length that lands inside the datagram.
        Random bytes clear the first test once in four; they clear all three
        about once in 2**30.

        Short-header (1-RTT) packets are deliberately *not* accepted. A
        1-RTT packet is a two-bit form field followed by an opaque connection
        ID of a length only the receiving endpoint knows, and there is
        nothing in it to recognise. A flow whose capture begins after the
        handshake is therefore not claimed, and lands in
        `udp_flows_unrecognised` -- which is the honest outcome, and is
        counted rather than guessed at.
        """
        return parse_long_header(payload, 0) is not None

    def __init__(self):
        self.client_key = None            # the client -> server direction
        self.first_ts = None
        self.last_ts = None
        self.version = None
        self.label = None
        self.versions_offered = None
        self.odcid = None                 # what the Initial keys come from
        self.client_cid = None
        self.server_cid = None
        self.retry = None
        self.counts = collections.Counter()
        self.crypto = {True: CryptoStream(), False: CryptoStream()}
        self._largest_pn = {True: -1, False: -1}
        self._keys = {}                   # (dcid, version, role) -> keys
        self._pinned = False              # a tag has verified; stop searching

    # -- intake -----------------------------------------------------------
    def push(self, timestamp, payload, key, datagram):
        """Walk one datagram's worth of coalesced QUIC packets."""
        if self.first_ts is None:
            self.first_ts = timestamp
            # The flow's first datagram is the client's, because that is what
            # opened the flow in the router. Corrected below if a tag says
            # otherwise, which is the only evidence worth trusting.
            self.client_key = key
        self.last_ts = timestamp
        self.counts['datagrams'] += 1

        from_client = key == self.client_key
        offset = 0
        walked = 0
        while offset < len(payload) and walked < MAX_PACKETS_PER_DATAGRAM:
            if not payload[offset] & 0x80:
                # A short header runs to the end of the datagram by
                # definition -- there is no length field -- so nothing can
                # follow it and there is nothing here to read.
                self.counts['one_rtt'] += 1
                break
            header = parse_long_header(payload, offset)
            if header is None:
                self.counts['unparsed'] += 1
                break
            if walked:
                self.counts['coalesced'] += 1
            walked += 1
            from_client = self._note(payload, header, key, from_client)
            if header.end <= offset:
                break                     # cannot happen; cannot loop either
            offset = header.end
        if offset < len(payload) and walked >= MAX_PACKETS_PER_DATAGRAM:
            self.counts['packets_over_cap'] += 1

    def _note(self, payload, header, key, from_client):
        """Record one packet, and decrypt it if it is an Initial."""
        self.counts[header.kind] += 1
        if self.version is None and header.kind != 'version_negotiation':
            self.version, self.label = header.version, header.label
        # Latched from the flow's *current* belief about direction, which
        # the AEAD tag in `_decrypt` may still overturn. When it does,
        # `_flip_cids` swaps these, because a record calling the server's
        # SCID `client_cid` is a wrong answer that looks like a right one.
        if from_client:
            self.client_cid = self.client_cid or header.scid or None
        else:
            self.server_cid = self.server_cid or header.scid or None

        if header.kind == 'version_negotiation':
            self.versions_offered = offered_versions(payload, header)
            return from_client
        if header.kind == 'retry':
            # The server rejected the client's connection ID and handed back
            # a token. What matters downstream is that the client's *next*
            # Initial uses the Retry's Source Connection ID as its
            # destination, so the Initial keys change mid-flow -- which is
            # why `_candidates` always offers a packet's own DCID.
            self.retry = {'token_bytes': len(header.token),
                          'new_dcid': header.scid.hex()}
            return from_client
        if header.kind != 'initial':
            return from_client
        if not HAVE_CRYPTO:
            self.counts['undecryptable_no_cryptography'] += 1
            return from_client
        if header.version not in INITIAL_SALT:
            # A draft or reserved version. Recognised, counted, and honestly
            # not readable: its salt is not the one published in RFC 9001.
            self.counts['undecryptable_version'] += 1
            PARSE_STATS['quic_unsupported_version'] += 1
            return from_client
        return self._decrypt(payload, header, key, from_client)

    def _decrypt(self, payload, header, key, from_client):
        """
        Try this Initial against every plausible (connection ID, role) pair.

        The AEAD tag is the oracle. It is a 128-bit check, so a pair that
        verifies is the right one and a pair that does not is wrong -- which
        makes this able to answer a question the framing cannot: which end of
        the flow sent this datagram. `pcapscan.datagrams` preserves direction
        but a capture that starts mid-flow, or a NAT rebinding, can still put
        the server's packet first. Until a tag has verified, both roles are
        tried and whichever works defines the client direction for the flow.
        """
        roles = (from_client,) if self._pinned else (from_client,
                                                     not from_client)
        for dcid in self._candidates(header, from_client):
            for role in roles:
                keys = self._derive(dcid, header.version, role)
                opened = decrypt_packet(payload, header, keys,
                                        self._largest_pn[role])
                if opened is None:
                    continue
                packet_number, plaintext = opened
                if not self._pinned:
                    # The tag has spoken. If it disagrees with the flow's
                    # direction guess, the guess loses.
                    if role != from_client:
                        self.client_key = (key if role
                                           else _reverse(key))
                        self.counts['direction_corrected'] += 1
                        self._flip_cids()
                    self.odcid = dcid
                    self._pinned = True
                self._largest_pn[role] = max(self._largest_pn[role],
                                             packet_number)
                self.counts['initials_decrypted'] += 1
                stream = self.crypto[role]
                for crypto_offset, data in iter_crypto_frames(plaintext):
                    stream.add(crypto_offset, data)
                return role
        self.counts['undecryptable'] += 1
        PARSE_STATS['quic_initial_undecryptable'] += 1
        return from_client

    def _flip_cids(self):
        """
        Swap the connection IDs after the tag overturns the direction guess.

        `_note` records them before anything has been decrypted, because a
        version-negotiation or Retry packet may be all a flow ever carries.
        That means they are recorded against a guess, and when the guess is
        wrong they are the wrong way round.
        """
        self.client_cid, self.server_cid = self.server_cid, self.client_cid

    def _candidates(self, header, from_client):
        """
        Connection IDs the Initial keys might come from, best guess first.

        A client's Initial declares the original DCID directly, so its own
        header is the answer. A server's Initial declares the client's Source
        Connection ID instead, so it can only be read once a client Initial
        has been seen -- and if the capture holds none, it cannot be read at
        all. That is a fact about the capture, and it is counted as
        `undecryptable` rather than hidden.

        `header.dcid` is therefore offered twice: first when this datagram is
        believed to be the client's, and again last as a fallback whatever
        the belief. The fallback is what saves a capture that starts between
        the client's Initial and the server's reply: the server's datagram
        arrives first, `pcapscan.datagrams` reasonably calls *it* the client,
        and every real client Initial afterwards arrives with
        `from_client=False`. Without the second offer the candidate list for
        those is empty and a perfectly readable ClientHello is counted
        undecryptable -- measured, on a real corpus flow, as
        `initials_decrypted` 1 -> 0. Trying it costs one key derivation and
        one AEAD check on a server Initial, where it is the client's SCID and
        simply will not verify; the 128-bit tag is what makes a wrong guess
        cheap to make.
        """
        out = []
        for candidate in (header.dcid if from_client else None,
                          self.odcid,
                          bytes.fromhex(self.retry['new_dcid'])
                          if self.retry else None,
                          header.dcid):
            if candidate is not None and candidate not in out:
                out.append(candidate)
        return out

    def _derive(self, dcid, version, from_client):
        """Cached `initial_keys`: one derivation per connection per side."""
        cache_key = (dcid, version, from_client)
        keys = self._keys.get(cache_key)
        if keys is None:
            if len(self._keys) >= 8:
                # Four connection IDs, two sides. More than that means the
                # flow is feeding new IDs to make this derive forever.
                self._keys.clear()
            keys = initial_keys(dcid, version, from_client)
            self._keys[cache_key] = keys
        return keys

    # -- output -----------------------------------------------------------
    def finish(self):
        """One document: the TLS facts under `tls`, QUIC under `quic`."""
        session = Session(self.client_key or _UNKNOWN_KEY,
                          self.first_ts if self.first_ts is not None else 0.0)
        session.note(self.last_ts if self.last_ts is not None else 0.0)
        for from_client in (True, False):
            stream = self.crypto[from_client].assemble()
            for message in split_handshake(stream):
                session.add_message(from_client, message)
        # Everything after the Initial flight is protected by the handshake
        # secret, which no capture yields. Saying so is what turns
        # "no certificate" into "certificate not readable" in the record --
        # the same distinction the TCP path draws for TLS 1.3.
        session.encrypted_after_hello = bool(self.counts['handshake']
                                             or self.counts['one_rtt'])
        if session.client_hellos or session.server_hellos:
            document = session.document()
        else:
            # Nothing to say about the TLS, and an empty `tls` block would
            # read as "this handshake negotiated nothing".
            document = {}
        document['quic'] = self.summary()
        return (document,)

    def summary(self):
        """The `quic` block: what is true of the transport, not of the TLS."""
        counts = self.counts
        packets = {name: counts[name] for name
                   in ('initial', 'handshake', 'zero_rtt', 'retry',
                       'version_negotiation', 'one_rtt', 'unparsed')
                   if counts[name]}
        out = {
            'version': ('0x{0:08x}'.format(self.version)
                        if self.version is not None else None),
            'version_name': self.label,
            'datagrams': counts['datagrams'],
            'packets': packets,
            'coalesced_packets': counts['coalesced'],
            'initials_decrypted': counts['initials_decrypted'],
            'initials_undecryptable': (
                counts['undecryptable'] + counts['undecryptable_version']
                + counts['undecryptable_no_cryptography']),
            'crypto_bytes': {'client': self.crypto[True].octets,
                             'server': self.crypto[False].octets},
        }
        if self.odcid is not None:
            # The connection ID the Initial keys came from. Published in the
            # clear by the client, and the one piece of state that makes this
            # decryption reproducible by anyone holding the capture.
            out['initial_dcid'] = self.odcid.hex()
        if self.client_cid:
            out['client_cid'] = self.client_cid.hex()
        if self.server_cid:
            out['server_cid'] = self.server_cid.hex()
        if self.retry is not None:
            out['retry'] = self.retry
        if self.versions_offered:
            out['versions_offered'] = self.versions_offered
        if counts['direction_corrected']:
            out['direction_corrected'] = True
        for name, reason in (
                ('undecryptable_no_cryptography',
                 'cryptography is not installed'),
                ('undecryptable_version',
                 'no published salt for this QUIC version'),
                ('undecryptable', 'no client Initial in the capture')):
            # ...but only when *nothing* was read. One injected or
            # post-Retry Initial that will not open is not a reason to
            # stamp "no client Initial in the capture" on a record that
            # carries a full `tls` block and a hostname; a label that
            # contradicts the data beside it is worse than no label.
            if counts[name] and not counts['initials_decrypted']:
                # Why there is no `tls` block, in the record rather than in a
                # log nobody reads. Same contract as `certificates_der`:
                # degrade with a label.
                out['handshake_unreadable'] = reason
                break
        if self.crypto[True].gap or self.crypto[False].gap:
            out['crypto_incomplete'] = True
        if self.crypto[True].overflowed or self.crypto[False].overflowed:
            out['crypto_capped'] = True
        return out


def _reverse(key):
    """The other direction of a flow key, without importing its type twice."""
    reverse = getattr(key, 'reverse', None)
    return reverse() if reverse is not None else key


# A flow that yielded nothing still needs a key-shaped object to build a
# Session around; the router fills `eth` in from the real flow key anyway.
_UNKNOWN_KEY = DatagramKey('0.0.0.0', 0, '0.0.0.0', 0)

HANDLER = QuicHandler

__all__ = ['CryptoStream', 'HANDLER', 'LongHeader', 'QuicHandler',
           'decode_packet_number', 'decrypt_packet', 'expand_label',
           'hkdf_expand', 'hkdf_extract', 'initial_keys', 'iter_crypto_frames',
           'offered_versions', 'parse_long_header', 'read_varint',
           'remove_header_protection', 'split_handshake', 'version_name']
