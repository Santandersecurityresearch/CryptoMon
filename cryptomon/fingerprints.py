"""
JA4 and JA4S: which client, and which server.

cryptomon.analysis answers "what was negotiated". It cannot answer "by
whom", and the second question is what turns a number into an action:
"37% of the sessions on this network offer no post-quantum key share" is a
finding, "and all of it is two builds of one browser" is a ticket.

JA4 (FoxIO, JA4+ v1.0) hashes what a ClientHello *offers* -- version,
ciphers, extensions, signature algorithms -- with everything that varies
per connection deliberately left out: GREASE, the server name, the ALPN
list past its first and last character, and the order of the extensions.
What is left is a property of the TLS stack and its configuration rather
than of the connection, so one build talking to a thousand hosts produces
one string. Measured over the corpus: 1260 sessions, 32 distinct JA4
values, the largest covering 363 of them and the top five covering 1027.
A fingerprint that did not cluster would be a bug, not a finding.

It identifies software, not intent, and it is not authentication: a hello
can be replayed byte for byte and several tools exist that do exactly
that. A match is evidence about a client, never proof about a peer.

Pure functions over values the parser has already decoded -- no I/O, no
pcapscan import -- so the live path and the offline reader compute the
same string from the same code.

Four details of the specification are easy to read past, and getting any
of them wrong yields fingerprints that look right and match nothing anyone
else has recorded. Each is pinned by a golden value in
tests/test_fingerprints.py:

  * The extension *count* includes server_name (0) and ALPN (16); the
    extension *hash* excludes them. The asymmetry is deliberate: the count
    says how talkative the client is, the hash must not change when it
    visits a different host over a different protocol.
  * The signature algorithms are appended to the hashed extension list in
    wire order, not sorted, separated by an underscore. A client's
    preference order is signal; its extension order (which Chrome
    randomises per connection) is not, which is why one is sorted and the
    other is not.
  * The version is the highest value the client *offers* in
    supported_versions, not the legacy version in the handshake header --
    every modern hello says TLS 1.2 there.
  * JA4S hashes the server's extensions in the order they appear and
    excludes nothing. The server chose exactly one cipher, so that one is
    written out in hex rather than hashed.
"""
import hashlib

# Each sha256 is truncated to this many hex characters. 48 bits is not a
# collision-resistant digest and is not meant to be one: the point is a
# fingerprint short enough to read in a log line and paste into a ticket.
HASH_CHARS = 12

# Printed in place of a hash when there is nothing to hash. Not the hash of
# the empty string -- "this client offered no ciphers" is worth being able
# to see at a glance, and a real-looking digest would hide it.
EMPTY_HASH = '0' * HASH_CHARS

# JA4 covers TCP ('t'), QUIC ('q') and DTLS ('d'). This monitor reassembles
# TCP streams; QUIC is UDP and never reaches this code, so the transport
# character is a constant here rather than a parameter that could only ever
# take one value.
TRANSPORT_TCP = 't'

# The two code points the client fingerprint singles out. Defined here
# rather than imported from cryptomon.parsers.tls because that module
# imports this one -- and because these two are part of the *fingerprint
# specification*, not of the parser's list of extensions it understands.
EXT_SERVER_NAME = 0
EXT_ALPN = 16

VERSION_LABELS = {
    0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10',
    0x0300: 's3', 0x0200: 's2', 0x0100: 's1',
}

# The same versions as cryptomon.utils.get_tls_version names them, so that a
# caller holding a parsed record but no code points still gets the right two
# characters. tls['tls_versions'] is the supported_versions list when that
# extension was present and the legacy version otherwise, which is the same
# precedence the specification asks for.
VERSION_CODEPOINTS_BY_NAME = {
    'TLSv1.3': 0x0304, 'TLSv1.2': 0x0303,
    'TLSv1.1': 0x0302, 'TLSv1.0': 0x0301,
}

# Printed for a version this table does not name. Counting it as TLS 1.0, or
# as the highest we do know, would put a guess into an identifier that other
# people's databases are keyed on.
UNKNOWN_VERSION = '00'

# 0-9, A-Z, a-z: the bytes the ALPN rule calls alphanumeric.
_ALPHANUMERIC = frozenset(
    list(range(0x30, 0x3a)) + list(range(0x41, 0x5b))
    + list(range(0x61, 0x7b)))


def _is_grease(codepoint):
    """
    True for the sixteen GREASE code points (RFC 8701), given an integer.

    cryptomon.utils.is_grease answers the same question for a pair of bytes.
    A fingerprint deals in whole code points, and importing the byte-pair
    form would pull the ciphersuite tables in behind it for no gain: the
    predicate is one comparison and one mask either way.
    """
    high, low = codepoint >> 8, codepoint & 0xFF
    return high == low and (high & 0x0F) == 0x0A


def _hex(codepoint):
    return '{:04x}'.format(codepoint & 0xFFFF)


def _count(values):
    """Two digits, saturating. A hello with 100 ciphers is not a browser."""
    return '{:02d}'.format(min(len(values), 99))


def _truncated_hash(values, trailing=None):
    """
    sha256 of the comma-joined values, truncated, with an optional second
    comma-joined list after an underscore.
    """
    if not values:
        # No extensions means no signature algorithms either:
        # signature_algorithms is itself extension 13, and it is not one of
        # the two the hash leaves out. So nothing is being dropped here.
        return EMPTY_HASH
    text = ','.join(values)
    if trailing:
        text = text + '_' + ','.join(trailing)
    return hashlib.sha256(text.encode('ascii')).hexdigest()[:HASH_CHARS]


def alpn_label(value):
    """
    The two characters JA4 uses for an ALPN value.

    First and last character of the first protocol name: 'h2' -> 'h2',
    'http/1.1' -> 'h1', a one-character name -> that character twice, no
    ALPN at all -> '00'.

    Non-alphanumeric bytes fall back to the hex form of the whole value --
    0xab 0xcd is 'abcd', so 'ad'. That branch is the written specification
    rather than something measured: every one of the 1337 ALPN values in
    the corpus, across 698 lists, is 'h2' or 'http/1.1'. Worth knowing
    that FoxIO's own Python implementation substitutes '9' for a non-ASCII
    byte instead, so the two published sources disagree on this branch;
    the written algorithm is the one other people's databases were built
    from, so it is the one followed.

    Takes bytes, or a str for a caller working from a parsed record. The
    bytes are the sender's choice and are not decoded: a name that is not
    ASCII is exactly the case the hex branch exists for.
    """
    if value is None:
        return '00'
    if isinstance(value, str):
        value = value.encode('latin-1', 'replace')
    if not value:
        return '00'
    if value[0] in _ALPHANUMERIC and value[-1] in _ALPHANUMERIC:
        return chr(value[0]) + chr(value[-1])
    digits = ''.join('{:02x}'.format(byte) for byte in value)
    return digits[0] + digits[-1]


def version_label(versions=None, legacy=None, names=None):
    """
    The two characters JA4 uses for the TLS version.

    The highest non-GREASE value in supported_versions if the hello carried
    that extension, otherwise the legacy version from the handshake header.
    The order matters: a TLS 1.3 client writes 0x0303 in the header for the
    benefit of middleboxes, so reading only the header would report every
    connection in the corpus as TLS 1.2.
    """
    offered = [v for v in (versions or []) if not _is_grease(v)]
    if not offered and names:
        if isinstance(names, str):
            names = [names]
        offered = [VERSION_CODEPOINTS_BY_NAME[name] for name in names
                   if name in VERSION_CODEPOINTS_BY_NAME]
    if not offered and legacy is not None:
        offered = [legacy]
    if not offered:
        return UNKNOWN_VERSION
    return VERSION_LABELS.get(max(offered), UNKNOWN_VERSION)


def _first_alpn(tls, raw):
    values = raw.get('alpn')
    if values is None:
        values = tls.get('alpn')
    return values[0] if values else None


def ja4(tls, raw_codepoints=None):
    """
    The JA4 fingerprint of a ClientHello, or None if it cannot be computed.

    `tls` is the dict parse_handshake builds. `raw_codepoints` carries the
    values that dict holds only by name -- the ciphersuites and the
    signature algorithms, which JA4 hashes as hex.

    Without those there is no honest answer, so the answer is None. Mapping
    a name back to a code point would only work for the suites this
    installation's table happens to list, and a hash that quietly omitted
    the rest would fingerprint the table rather than the client: two
    deployments would then disagree about the same packet, which is the one
    thing an identifier may not do.
    """
    raw = raw_codepoints or {}
    ciphers = raw.get('ciphers')
    if ciphers is None:
        return None
    extensions = raw.get('extensions')
    if extensions is None:
        extensions = tls.get('extensions') or []

    kept_ciphers = [c for c in ciphers if not _is_grease(c)]
    kept_extensions = [e for e in extensions if not _is_grease(e)]
    sigalgs = [_hex(s) for s in (raw.get('sigalgs') or [])
               if not _is_grease(s)]

    prefix = '{0}{1}{2}{3}{4}{5}'.format(
        TRANSPORT_TCP,
        version_label(raw.get('versions'), raw.get('legacy_version'),
                      tls.get('tls_versions')),
        'd' if EXT_SERVER_NAME in kept_extensions else 'i',
        _count(kept_ciphers),
        _count(kept_extensions),
        alpn_label(_first_alpn(tls, raw)))
    hashed_extensions = sorted(
        _hex(e) for e in kept_extensions
        if e not in (EXT_SERVER_NAME, EXT_ALPN))
    return '{0}_{1}_{2}'.format(
        prefix,
        _truncated_hash(sorted(_hex(c) for c in kept_ciphers)),
        _truncated_hash(hashed_extensions, sigalgs))


def ja4s(tls, raw_codepoints=None):
    """
    The JA4S fingerprint of a ServerHello, or None without the raw cipher.

    Servers are far less varied than clients -- most answer with two or
    three extensions and one of a handful of suites, and the corpus holds
    45 distinct JA4S against 1170 ServerHellos -- so JA4S is weak alone
    and strong paired with the JA4 of the hello it answered: one server
    answering two clients differently is the interesting shape. Nothing
    here pairs them; pcapscan.sessions holds both halves.

    The extension list is *not* sorted and *not* filtered of server_name or
    ALPN. A server's extension order is its own, not the client's, so it
    carries information a sort would throw away. (Servers do not send
    GREASE, and none of the 1170 ServerHellos in the corpus carries a
    GREASE extension, so filtering it costs nothing and guards the one
    hello that would.)
    """
    raw = raw_codepoints or {}
    cipher = raw.get('cipher')
    if cipher is None:
        return None
    extensions = raw.get('extensions')
    if extensions is None:
        extensions = tls.get('extensions') or []
    kept = [e for e in extensions if not _is_grease(e)]
    prefix = '{0}{1}{2}{3}'.format(
        TRANSPORT_TCP,
        version_label(raw.get('versions'), raw.get('legacy_version'),
                      tls.get('tls_versions')),
        _count(kept),
        alpn_label(_first_alpn(tls, raw)))
    return '{0}_{1}_{2}'.format(
        prefix, _hex(cipher), _truncated_hash([_hex(e) for e in kept]))


def ja3(tls, raw_codepoints=None):
    """
    The JA3 fingerprint of a ClientHello (Althouse et al., 2017), or None.

    Kept only because the tooling around it is everywhere -- Zeek, Suricata,
    NetworkMiner, most commercial sensors and a decade of threat-intel feeds
    are keyed on JA3 -- and a record that cannot be joined to what an
    organisation already has is less useful than one that can.

    It is not to be trusted for anything security-bearing, for two reasons
    that have nothing to do with each other. It is an MD5, which is not
    collision-resistant. And it hashes the extensions *in wire order*,
    which stopped being a property of the client when Chrome began
    shuffling its extension order on every connection (Chrome 110, 2023).

    The corpus shows exactly that, and it is the reason this function's
    output is labelled rather than trusted: 393 distinct JA3 values across
    the same 1260 client hellos that produce 32 distinct JA4 values, and
    of those 393, 340 belong to a single client -- the 340 Chrome sessions
    that share one JA4 have 340 different JA3s, one per connection. Every
    other client in the corpus has exactly one JA3 per JA4. JA3 is
    identifying the connection; JA4 is identifying the client.
    """
    raw = raw_codepoints or {}
    ciphers = raw.get('ciphers')
    if ciphers is None:
        return None
    extensions = raw.get('extensions')
    if extensions is None:
        extensions = tls.get('extensions') or []
    fields = [
        str(raw.get('legacy_version') or 0),
        '-'.join(str(c) for c in ciphers if not _is_grease(c)),
        '-'.join(str(e) for e in extensions if not _is_grease(e)),
        '-'.join(str(g) for g in (raw.get('groups') or [])
                 if not _is_grease(g)),
        '-'.join(str(f) for f in (raw.get('ec_point_formats') or [])),
    ]
    return hashlib.md5(','.join(fields).encode('ascii')).hexdigest()
