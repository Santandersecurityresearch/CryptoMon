"""
SSH enrichment: which implementation is speaking, and how big its host key is.

What the KEXINIT does not carry. `pcapscan.sessions.parse_ssh_stream` reads
the six algorithm name-lists out of a KEXINIT, which is what each side
*offers*. Two things a readiness report needs are not in there at all:

  * **Which implementation.** The banner, and only the banner, identifies it.
    "OpenSSH 8.2" answers "what do we have to upgrade"; `ssh-ed25519` does
    not. It is the same job JA4 does for TLS, done by a string the peer
    volunteers.

  * **How big the server's host key is.** This is the argument
    `pcapscan.certificates` makes about X.509, in a second protocol: "RSA"
    says nothing about quantum vulnerability, "RSA-2048" says everything, and
    the ones that have to be replaced first are not chosen at random. The
    size is nowhere in the KEXINIT -- `ssh-rsa` in ServerHostKeyAlgos is a
    name, not a modulus. It is inside the host key blob the server sends in
    the KEX reply, so reaching it means walking that packet and reading an
    mpint.

**There is no SSH traffic in this repository's fixtures or in the corpus.**
Nothing here was measured on captured traffic, because there was none to
measure. It is written against RFC 4253 (sections 4.2, 5, 6, 6.6), RFC 4419,
RFC 5656, RFC 8332 and RFC 8709, and exercised against packets constructed by
hand in tests/test_ssh_enrichment.py.

Pure functions: bytes in, dict out. No I/O, and nothing here needs a capture.
"""
import base64
import hashlib
import re

from cryptomon.analysis import HYBRID, POST_QUANTUM, classify_algorithm
from cryptomon.utils import PARSE_STATS, printable_text

# RFC 4253 section 4.2: the identification line, CR LF included, is at most
# 255 bytes. Anything longer is not a banner, it is something else arriving
# on port 22, and it is truncated here rather than carried into a CSV column.
MAX_BANNER_LEN = 255

# RFC 4253 section 6 requires support for packets of 35000 bytes. A KEX reply
# is a couple of kilobytes at most; the ceiling exists so that a crafted or
# corrupt length field costs a bounded amount of work, exactly as
# MAX_LIST_ITEMS does in cryptomon.parsers.tls.
MAX_PACKET_LEN = 35000

# Unencrypted packets in one direction before the key exchange finishes:
# KEXINIT, the reply, NEWKEYS, plus slack for EXT_INFO and a GEX round trip.
# After NEWKEYS the stream is ciphertext, and walking it would be reading
# noise as lengths.
MAX_PACKETS = 16

# The longest string this parser will accept off the wire. A 4096-bit RSA
# host key blob is about 540 bytes and its signature about 530.
MAX_STRING_LEN = 8192

# A host key type name. The longest real one is
# `sk-ecdsa-sha2-nistp256@openssh.com` at 34 bytes. This bound is also what
# makes the message-code collision below safe: an mpint misread as a type
# name is hundreds of bytes long and is refused here rather than parsed.
MAX_KEY_TYPE_LEN = 64

# RFC 4253 section 8 / RFC 5656 section 4: the server's reply carrying the
# host key. 31 is SSH_MSG_KEXDH_REPLY and, in an ECDH or curve25519
# exchange, SSH_MSG_KEX_ECDH_REPLY.
SSH_MSG_KEXDH_REPLY = 31
# RFC 4419 section 5: group exchange numbers its own messages in the same
# range, and its *reply* is 33 -- while 31 in that exchange is
# SSH_MSG_KEX_DH_GEX_GROUP, whose payload is `mpint p, mpint g` and holds no
# host key at all. A walk that trusted the code alone would read the prime p
# as a host key blob; see parse_kex_reply.
SSH_MSG_KEX_DH_GEX_REPLY = 33

# Host key types whose size the algorithm name fixes. Everything else has to
# be read off the wire.
#
# nistp521 is 521 bits, not 512: P-521's prime is 2**521 - 1. Rounding it to
# a power of two would be a wrong number reported confidently.
FIXED_KEY_SIZES = {
    'ssh-ed25519': 256,
    'ssh-ed448': 456,
    'ecdsa-sha2-nistp256': 256,
    'ecdsa-sha2-nistp384': 384,
    'ecdsa-sha2-nistp521': 521,
    # FIDO/U2F keys (OpenSSH). The blob carries an extra application string
    # after the key, which changes nothing about the key's size.
    'sk-ssh-ed25519@openssh.com': 256,
    'sk-ecdsa-sha2-nistp256@openssh.com': 256,
}

# RFC 8332. `rsa-sha2-256` and `rsa-sha2-512` name a *signature* algorithm,
# not a key type: they are SHA-2 signatures over an ordinary RSA key, and the
# host key blob on the wire still says `ssh-rsa`. Two consequences worth
# being explicit about: a server advertising only rsa-sha2-* has not stopped
# using RSA, and these names may be seen where a key type is expected, so
# they are parsed as one.
RSA_SIGNATURE_ALGORITHMS = ('rsa-sha2-256', 'rsa-sha2-512')
RSA_KEY_TYPES = ('ssh-rsa',) + RSA_SIGNATURE_ALGORITHMS

# OpenSSH host certificates wrap a key: the blob is type, *nonce*, then the
# base key's fields. Skipping the nonce is the whole difference, and not
# skipping it would read the nonce as `e` and `e` as `n` -- a confidently
# reported key size that is wrong by a factor of thousands.
CERT_SUFFIX = '-cert-v01@openssh.com'

# Not algorithms. RFC 8308 signals extension support with `ext-info-c` /
# `ext-info-s`, and OpenSSH signals its Terrapin countermeasure
# (CVE-2023-48795) with `kex-strict-*-v00@openssh.com`, both by putting a
# pseudo-name in the KEXINIT key-exchange list. Classifying them would add
# two or three entries to the `unknown` bucket on every SSH session, which
# reads as "unrecognised algorithm" when in fact nothing was proposed.
STRICT_KEX_NAMES = ('kex-strict-c-v00@openssh.com',
                    'kex-strict-s-v00@openssh.com')
SIGNALLING_NAMES = ('ext-info-c', 'ext-info-s') + STRICT_KEX_NAMES

_CURVE = re.compile(r'(nistp(?:256|384|521))')
# The software string split. `softwareversion` is one token by RFC 4253 --
# no space, no minus sign -- but it has no internal grammar, so the version
# is taken to start at the first digit that runs to the end of the token.
# That handles OpenSSH_9.6p1, dropbear_2022.83, libssh-0.7.0 and
# OpenSSH_for_Windows_9.5 under one rule rather than four.
_SOFTWARE = re.compile(r'^(.*?)[-_/]?(\d\S*)$')


# --------------------------------------------------------------------------
# the banner
# --------------------------------------------------------------------------
def parse_banner(banner):
    """
    The identification line -> protocol version, software, comment.

    RFC 4253 section 4.2: `SSH-protoversion-softwareversion SP comments CR
    LF`. softwareversion may contain neither a space nor a minus sign, which
    is what makes both splits below unambiguous rather than a guess.

    Accepts bytes or str, because the live path holds raw bytes and
    parse_ssh_stream has already decoded. Always returns the same five keys,
    so that a banner that would not parse is distinguishable from one that
    was never seen: every value is None, and the count is in PARSE_STATS.

    The line is the peer's free text. It is cut to the RFC's 255 bytes
    *before* it is escaped -- the cap belongs to the wire, and escaping
    expands -- and then made printable, because a banner ends up in a CSV
    cell, a log line and a terminal, and cryptomon.utils.printable_text
    exists because a control character in one of those is not cosmetic.
    """
    out = {'banner': None, 'protocol_version': None, 'software': None,
           'software_version': None, 'comment': None}
    if banner is None:
        return out
    if isinstance(banner, (bytes, bytearray, memoryview)):
        text = bytes(banner).decode('ascii', 'replace')
    else:
        text = str(banner)
    # The banner ends at the first CR or LF; anything after it is the binary
    # protocol, and a caller handing over a whole stream should not have to
    # know that.
    text = re.split(r'[\r\n]', text, maxsplit=1)[0]
    if len(text) > MAX_BANNER_LEN:
        PARSE_STATS['ssh_banner_too_long'] += 1
        text = text[:MAX_BANNER_LEN]
    text = printable_text(text, 'nonprintable_ssh')
    out['banner'] = text
    if not text.startswith('SSH-'):
        PARSE_STATS['ssh_banner_malformed'] += 1
        return out
    protocol, dash, rest = text[4:].partition('-')
    if not dash:
        PARSE_STATS['ssh_banner_malformed'] += 1
        return out
    out['protocol_version'] = protocol
    software, _, comment = rest.partition(' ')
    out['comment'] = comment or None
    if not software:
        PARSE_STATS['ssh_banner_malformed'] += 1
        return out
    match = _SOFTWARE.match(software)
    if match and match.group(1):
        out['software'] = match.group(1)
        out['software_version'] = match.group(2)
    else:
        # No version in it at all (`SSH-2.0-Go`), or nothing but a version.
        # Recording the whole token as the name is honest; inventing a split
        # is not.
        out['software'] = software
    return out


# --------------------------------------------------------------------------
# the host key
# --------------------------------------------------------------------------
def _read_string(data, offset, end):
    """
    One SSH string (RFC 4253 section 5): uint32 length, then that many bytes.

    Returns (None, end) rather than raising or short-reading. Every length
    field here is the peer's choice, so the claimed length is checked against
    both the ceiling and what is actually present before a single byte of it
    is trusted.
    """
    if offset + 4 > end:
        return None, end
    length = int.from_bytes(bytes(data[offset:offset + 4]), 'big')
    if length > MAX_STRING_LEN or offset + 4 + length > end:
        return None, end
    return bytes(data[offset + 4:offset + 4 + length]), offset + 4 + length


def mpint_bits(raw):
    """
    The bit length of an mpint's value (RFC 4253 section 5).

    An mpint is a two's complement big-endian integer, so a positive number
    whose top bit would be set carries a leading zero byte to keep it
    positive. That is the normal case for an RSA modulus and for a DSA prime
    -- both have their top bit set by construction -- which makes
    `len(raw) * 8` wrong by exactly 8 on essentially every key in existence,
    and 2056-bit RSA is not a thing.
    """
    if not raw:
        return 0
    value = int.from_bytes(bytes(raw), 'big', signed=True)
    if value < 0:
        # A negative modulus or prime is not a key. The magnitude is still
        # reported, because refusing the whole blob over it would lose the
        # key type too, but the anomaly is counted.
        PARSE_STATS['ssh_negative_mpint'] += 1
    return value.bit_length()


def ssh_fingerprint(blob):
    """
    The host key fingerprint as OpenSSH prints it: SHA256:<base64, unpadded>.

    Kept for the same reason pcapscan.certificates keeps one: it identifies
    the key itself rather than its algorithm, it is what an operator can
    compare against known_hosts, and it is a string, so it survives into
    JSON and CSV unchanged.
    """
    digest = hashlib.sha256(bytes(blob)).digest()
    return 'SHA256:' + base64.b64encode(digest).decode('ascii').rstrip('=')


def _blank_key():
    return {'key_type': None, 'key_size': None, 'curve': None,
            'fingerprint_sha256': None, 'verdict': None, 'label': None,
            'error': None}


def _refuse(out, reason, stat):
    """Record why a blob was refused. Never guesses a size to go with it."""
    PARSE_STATS[stat] += 1
    out['error'] = reason
    return out


def parse_host_key(blob):
    """
    A host key blob -> key type, size in bits, curve, fingerprint.

    Never raises, and refuses rather than guessing. The blob is an SSH string
    whose contents are a nested structure beginning with the key type name
    (RFC 4253 section 6.6); which fields follow depends on that name. A blob
    that runs out part way through them is reported with `error` set and
    `key_size` left None, because a truncated capture and a 0-bit key must
    not look the same.
    """
    out = _blank_key()
    blob = bytes(blob or b'')
    end = len(blob)
    raw_type, offset = _read_string(blob, 0, end)
    if raw_type is None or len(raw_type) > MAX_KEY_TYPE_LEN:
        # Also the guard that stops an mpint being parsed as a key: see
        # SSH_MSG_KEX_DH_GEX_REPLY above.
        return _refuse(out, 'not_a_host_key', 'ssh_host_key_malformed')
    key_type = printable_text(raw_type.decode('ascii', 'replace'),
                              'nonprintable_ssh')
    out['key_type'] = key_type
    out['fingerprint_sha256'] = ssh_fingerprint(blob)
    out['verdict'] = classify_algorithm(key_type)

    base_type = key_type
    if key_type.endswith(CERT_SUFFIX):
        base_type = key_type[:-len(CERT_SUFFIX)]
        nonce, offset = _read_string(blob, offset, end)
        if nonce is None:
            return _refuse(out, 'truncated', 'ssh_host_key_truncated')

    if base_type in FIXED_KEY_SIZES:
        if 'ecdsa' in base_type:
            # RFC 5656 section 3.1 repeats the curve identifier inside the
            # blob. It is checked rather than skipped: a blob whose inner
            # curve disagrees with its type name is malformed, and taking
            # the size from the name alone would hide that.
            curve, offset = _read_string(blob, offset, end)
            if curve is None:
                return _refuse(out, 'truncated', 'ssh_host_key_truncated')
            named = _CURVE.search(base_type)
            if not named or curve.decode('ascii', 'replace') != named.group(1):
                return _refuse(out, 'curve_mismatch',
                               'ssh_host_key_curve_mismatch')
        point, offset = _read_string(blob, offset, end)
        if point is None:
            return _refuse(out, 'truncated', 'ssh_host_key_truncated')
        out['key_size'] = FIXED_KEY_SIZES[base_type]
        found = _CURVE.search(base_type)
        out['curve'] = found.group(1) if found else None
    elif base_type in RSA_KEY_TYPES:
        _exponent, offset = _read_string(blob, offset, end)   # e
        modulus, offset = _read_string(blob, offset, end)     # n
        if modulus is None:
            return _refuse(out, 'truncated', 'ssh_host_key_truncated')
        out['key_size'] = mpint_bits(modulus)
    elif base_type == 'ssh-dss':
        # p, q, g, y -- and the size of a DSA key is the size of p (RFC 4253
        # section 6.6). q is 160 bits whatever p is, so reading the wrong
        # field here would report every DSA key as 160-bit.
        prime, offset = _read_string(blob, offset, end)
        if prime is None:
            return _refuse(out, 'truncated', 'ssh_host_key_truncated')
        out['key_size'] = mpint_bits(prime)
    else:
        # Named, counted, and left without a size. An unrecognised key type
        # is a gap in the table above, not a finding about the traffic --
        # the same distinction cryptomon.analysis draws for `unknown`.
        return _refuse(out, 'unknown_key_type', 'ssh_host_key_unknown_type')

    if not out['key_size']:
        return _refuse(out, 'no_key_size', 'ssh_host_key_malformed')
    # The label an inventory counts, shaped like classify_certificate's:
    # "ssh-rsa" is not an answer, "ssh-rsa-2048" is.
    out['label'] = '{0}-{1}'.format(key_type, out['key_size'])
    return out


# --------------------------------------------------------------------------
# finding the reply in a stream
# --------------------------------------------------------------------------
def _iter_packets(data):
    """
    Yield (message code, payload after the code) for each binary packet.

    RFC 4253 section 6: uint32 packet_length, byte padding_length, payload,
    padding. Only valid until NEWKEYS, after which the stream is ciphertext
    -- which is why the walk is capped at MAX_PACKETS rather than run to the
    end of the data. Stops at the first packet that does not fit in what was
    captured, because a handshake split across segments is the normal case
    rather than an anomaly.
    """
    data = bytes(data)
    end = len(data)
    offset = 0
    if data[:4] == b'SSH-':
        newline = data.find(b'\r\n', 0, MAX_BANNER_LEN + 2)
        if newline < 0:
            return
        offset = newline + 2
    seen = 0
    while offset + 6 <= end and seen < MAX_PACKETS:
        seen += 1
        packet_len = int.from_bytes(data[offset:offset + 4], 'big')
        if not 0 < packet_len <= MAX_PACKET_LEN:
            PARSE_STATS['ssh_packet_length_implausible'] += 1
            return
        if offset + 4 + packet_len > end:
            return                       # the packet has not all arrived
        padding = data[offset + 4]
        payload_len = packet_len - padding - 1
        if payload_len < 1:
            PARSE_STATS['ssh_packet_length_implausible'] += 1
            return
        start = offset + 5
        yield data[start], data[start + 1:start + payload_len]
        offset += 4 + packet_len


def parse_kex_reply(data):
    """
    The server's host key, from one direction of an SSH stream.

    `data` may be the whole server-to-client stream -- banner and all -- or
    just the packets; the KEX reply is found by walking the binary packets.

    Codes 31 and 33 are both tried, and the *parse* decides which was real,
    not the code: in a group-exchange key exchange 31 is
    SSH_MSG_KEX_DH_GEX_GROUP, carrying `mpint p, mpint g` and no host key at
    all. Its p is hundreds of bytes long, so parse_host_key refuses it on
    MAX_KEY_TYPE_LEN and the walk carries on to the real reply at 33. The
    first error is kept in case no reply parses, so that "this was not a host
    key" is reported rather than "there was no reply".
    """
    first_error = None
    for code, payload in _iter_packets(data):
        if code not in (SSH_MSG_KEXDH_REPLY, SSH_MSG_KEX_DH_GEX_REPLY):
            continue
        blob, _ = _read_string(payload, 0, len(payload))
        if blob is None:
            PARSE_STATS['ssh_host_key_truncated'] += 1
            continue
        parsed = parse_host_key(blob)
        if parsed['error'] is None:
            parsed['kex_reply_code'] = code
            return parsed
        if first_error is None:
            first_error = parsed
            first_error['kex_reply_code'] = code
    if first_error is not None:
        return first_error
    out = _blank_key()
    out['kex_reply_code'] = None
    out['error'] = 'no_kex_reply'
    return out


# --------------------------------------------------------------------------
# key exchange verdicts
# --------------------------------------------------------------------------
def classify_kex_algorithms(names):
    """
    KEXINIT key-exchange names -> {name: verdict}.

    The verdict comes from cryptomon.analysis.classify_algorithm, which
    already knows the SSH spellings -- sntrup761x25519, mlkem768x25519 and
    the rest -- and is the one place in this project where "does this survive
    Shor" is decided. A second classifier here would be a second place for
    that answer to drift.

    The RFC 8308 and Terrapin pseudo-names are left out: they name no
    algorithm, and counting them as `unknown` would read as "we did not
    recognise this cipher" when in fact nothing was proposed.
    """
    return {name: classify_algorithm(name)
            for name in (names or [])
            if name and name not in SIGNALLING_NAMES}


# --------------------------------------------------------------------------
# the whole session
# --------------------------------------------------------------------------
def describe_ssh_session(banner_bytes, kexinit_lists, kex_reply_bytes=None):
    """
    Everything this module can say about one SSH session, as one dict.

    Shaped to be merged into a session record under `ssh`, beside the six
    KEXINIT name-lists pcapscan.sessions already puts there: no key here
    collides with cryptomon.data.SSH_SECTIONS, and the lists themselves are
    not repeated. Flat and JSON-serialisable -- no bytes, no sets, no tuples
    -- with one name -> verdict mapping, `kex_verdicts`, which is the one
    thing that cannot be flattened without losing which name got which
    answer.

    `kex_post_quantum` says what was **offered**, never what was negotiated.
    One direction's KEXINIT is a list of proposals; the algorithm actually
    used is the first of the client's that the server also named (RFC 4253
    section 7.1), which needs both directions. Reporting an offer as a
    selection is the mistake pcapscan.sessions exists to avoid in TLS.

    `host_key_size` is None both when no reply was in the capture and when
    one was there and would not parse; `host_key_error` separates them.
    """
    out = parse_banner(banner_bytes)
    kexinit_lists = kexinit_lists or {}
    verdicts = classify_kex_algorithms(kexinit_lists.get('KEXalgs'))
    out['kex_verdicts'] = verdicts
    out['kex_post_quantum'] = any(verdict in (POST_QUANTUM, HYBRID)
                                  for verdict in verdicts.values())
    # Whether the peer offered the Terrapin countermeasure (CVE-2023-48795).
    # It travels in the key-exchange list and is excluded from the verdicts
    # above, so this is the only place it would otherwise be lost.
    out['strict_kex'] = any(name in STRICT_KEX_NAMES
                            for name in kexinit_lists.get('KEXalgs') or [])
    out['host_key_algorithms'] = list(
        kexinit_lists.get('ServerHostKeyAlgos') or [])

    key = _blank_key()
    key['kex_reply_code'] = None
    if kex_reply_bytes:
        key = parse_kex_reply(kex_reply_bytes)
    out['host_key_type'] = key['key_type']
    out['host_key_size'] = key['key_size']
    out['host_key_curve'] = key['curve']
    out['host_key_label'] = key['label']
    out['host_key_verdict'] = key['verdict']
    out['host_key_fingerprint_sha256'] = key['fingerprint_sha256']
    out['host_key_error'] = key['error']
    return out
