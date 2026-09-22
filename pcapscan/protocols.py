"""
What a TCP stream carries, decided from its bytes rather than from its port.

The live path picks traffic by port number: `cryptomon/bpf.py` forwards
frames on 443, 990, 3389, 8080 and 8443 to the TLS parser and 22 to the SSH
one, and nothing else is ever looked at. The offline path is barely better --
`pcapscan.sessions` tests three bytes with `looks_like_tls` and matches a
literal `SSH-` prefix. Both are wrong in the two directions issue #13 names:
TLS on any other port is invisible, and traffic on 443 that is not TLS is
buffered and parsed for nothing.

Both failures are measurable, and `scan_capture` is what measures them. Over
the 1,560 TCP flows in the capture corpus:

* 13 flows carry TLS on a port the kernel filter does not watch -- 12 on
  53443 and one on 888 -- so the live path would never be handed them.
* 14 of the 1,370 flows on port 443 are not TLS, and only 5 of those carried
  any payload at all: one TURN-over-TCP conversation and four whose sole
  captured byte was a TCP keepalive.

That is a small number, and it is the result. This exists so that "we monitor
the TLS on this network" can be measured rather than assumed, and on this
corpus the measurement is reassuring. An estate with a mail server, a
management VLAN or a reverse proxy on an unusual port will not read the same,
and the same code answers the question there.

Three things shape the design.

**The port is never the signal.** `port_hint` is accepted and used for
exactly two things, both spelled out at `detect()`: telling SMTP from FTP
when a `220` greeting names neither, and deciding whether a detection sits on
a port the kernel filter watches -- which is a *finding*, not evidence. It
never changes which protocol is reported and never raises a confidence. A
port that agrees with the bytes adds nothing the bytes did not already say,
and a port that disagrees is precisely the case this exists to catch.

**Every detection carries its reason.** A bare `'tls'` cannot be checked by
whoever reads the report. "byte 0 is 0x16 (handshake), version 3.3, record
length 517 within the 18432 ceiling, holding a 512-byte client_hello that
fills it exactly" can. The reason string is built from the evidence that was
actually tested, so it also records which tests were *not* possible -- a
direction that stopped after six bytes says so.

**Refuse rather than guess.** A buffer that begins like a TLS record and then
contradicts itself is not reported as low-confidence TLS; it is refused and
counted in `cryptomon.utils.PARSE_STATS`. Wire bytes are attacker-controlled,
so the cheapest way to make this lie is to send something that half-matches.
"""
import collections
from typing import NamedTuple

from cryptomon.parsers.framing import decode_frame
from cryptomon.utils import PARSE_STATS
from pcapscan.reader import Reader
from pcapscan.reassembly import Reassembler, TCP_ACK, TCP_SYN, flow_key
from pcapscan.records import (CONTENT_ALERT, CONTENT_APPLICATION_DATA,
                              CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE,
                              CONTENT_TYPES, HS_CLIENT_HELLO, HS_NAMES,
                              HS_SERVER_HELLO, MAX_MESSAGE_LEN,
                              MAX_RECORD_LEN, MESSAGE_HDR_LEN, RECORD_HDR_LEN)

# --------------------------------------------------------------------------
# how much of a direction to look at
# --------------------------------------------------------------------------
# Measured, not chosen. Every literal this module matches sits in the first
# two dozen bytes except the HTTP request line, whose `HTTP/1.` token is the
# thing that makes an HTTP request certain rather than likely. Across the
# corpus the deepest that token sits is offset 294 -- one Office 365 GET with
# a long query string -- so 320 bytes catches every request line the corpus
# contains with room for a slightly longer one. At 320 bytes per direction a
# 2048-flow scan holds 1.3MB, which is the whole reason this is a head and
# not a stream.
DEFAULT_HEAD_BYTES = 320

# A hard ceiling on what `detect` will look at however much it is handed.
# Callers pass a slice of a reassembled stream and the stream cap is 16KB;
# this stops a caller that forgets the slice from making detection cost
# proportional to the connection.
MAX_HEAD_BYTES = 4096

# Below a full record header nothing here can test a length against a buffer,
# and a claim resting on two or three bytes is the kind of claim this module
# exists to replace.
MIN_HEAD_BYTES = RECORD_HDR_LEN


# --------------------------------------------------------------------------
# confidence
# --------------------------------------------------------------------------
# Four rungs, not a continuum, so that a caller can set one threshold and
# state what it means. The rungs rank evidence; they are not probabilities
# and should not be multiplied or averaged.
#
#   CERTAIN  every field that could have disagreed agreed: a literal unique
#            to the protocol, or a header whose lengths check out against the
#            buffer and against each other.
#   STRONG   a protocol-specific literal, with one check that the available
#            bytes did not allow.
#   LIKELY   a well-formed header that a different protocol could in
#            principle produce.
#   WEAK     suggestive only. Reported so that it is visible, never acted on.
#
# CERTAIN does not mean unforgeable. Anything here can be forged by sending
# the bytes; it means nothing in the bytes contradicts the claim.
CERTAIN = 1.0
STRONG = 0.9
LIKELY = 0.6
WEAK = 0.3


# --------------------------------------------------------------------------
# the ports the live path watches
# --------------------------------------------------------------------------
# A copy of the port list in cryptomon/bpf.py, which is a C source string and
# so cannot be imported as data. tests/test_protocols.py asserts that every
# port here appears in `bpf_text` and that every port `bpf_text` compares
# against appears here, so the copy cannot drift without a test failing.
EBPF_TLS_PORTS = frozenset({443, 990, 3389, 8080, 8443})
EBPF_SSH_PORTS = frozenset({22})
EBPF_WATCHED_PORTS = EBPF_TLS_PORTS | EBPF_SSH_PORTS

# Which watched set a protocol belongs to, for deciding whether the live
# filter would ever have seen a flow carrying it.
_WATCHED_FOR = {'tls': EBPF_TLS_PORTS, 'ssh': EBPF_SSH_PORTS}

# Plaintext protocols that negotiate an in-band upgrade to TLS. Detecting one
# of these is not the end of the story: a STARTTLS/STLS/AUTH TLS command is
# answered with a success line and the *next* byte of the stream is a TLS
# ClientHello. Nothing in this repository looks for that yet -- the live
# filter never sees port 25 or 143 at all, and the offline path classifies a
# direction once, from its first bytes, and never revisits it. Recording the
# protocol here is what makes that gap findable; closing it means re-running
# `detect` at the offset just past the server's success response.
STARTTLS_CAPABLE = frozenset({'smtp', 'imap', 'pop3', 'ftp'})


class Detection(NamedTuple):
    """
    What one direction is carrying, and why that was concluded.

    `reason` is the deliverable as much as `protocol` is: a report that says
    "TLS on port 53443" invites the question "says who", and the reason
    answers it in terms of bytes and offsets that a reader can check against
    the capture.
    """
    protocol: str
    confidence: float
    reason: str
    port_hint: int = None
    # True when the live eBPF filter would never have been handed this flow.
    # Set only for protocols the filter claims to cover -- an SMTP flow on
    # port 25 is not "missed", it was never in scope.
    unwatched_port: bool = False

    @property
    def starttls_capable(self):
        """Could TLS begin partway through this stream?"""
        return self.protocol in STARTTLS_CAPABLE

    def __str__(self):
        return '{0} ({1:.1f}): {2}'.format(self.protocol, self.confidence,
                                           self.reason)


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------
_CONTENT_NAMES = {
    CONTENT_CHANGE_CIPHER_SPEC: 'change_cipher_spec',
    CONTENT_ALERT: 'alert',
    CONTENT_HANDSHAKE: 'handshake',
    CONTENT_APPLICATION_DATA: 'application_data',
}

# Walking more than this many records buys nothing -- two consecutive valid
# headers is already the strongest length evidence a 320-byte head can hold
# -- and bounds the loop against a head full of zero-length records.
MAX_RECORD_CHAIN = 8


class _Chain(NamedTuple):
    """The result of walking record headers from the start of a head."""
    records: int        # consecutive headers that validated
    refuted: bool       # a record ended inside the head, and what followed
                        # was not another record header
    offset: int         # where the walk stopped


def _walk_record_chain(head):
    """
    Follow record headers from offset 0 for as long as the head allows.

    This is where "the record length is consistent with the buffer" is
    actually tested. A length field that points at the next valid record
    header is evidence no single header can give; a length field that points
    at bytes which cannot be a record header is a contradiction, and a
    contradiction is worth more than either -- it is what lets `0x16 0x03
    0x03` followed by six bytes of something else be refused outright
    instead of reported as weak TLS.
    """
    offset = 0
    records = 0
    while records < MAX_RECORD_CHAIN and offset + RECORD_HDR_LEN <= len(head):
        if (head[offset] not in CONTENT_TYPES or head[offset + 1] != 3
                or head[offset + 2] > 4):
            return _Chain(records, records > 0, offset)
        length = (head[offset + 3] << 8) | head[offset + 4]
        if length > MAX_RECORD_LEN:
            return _Chain(records, records > 0, offset)
        records += 1
        offset += RECORD_HDR_LEN + length
        if offset > len(head):
            # The record claims more than was captured. Unrefuted, and that
            # is all -- a truncated claim is not a confirmed one.
            return _Chain(records, False, len(head))
    if offset < len(head) and head[offset] not in CONTENT_TYPES:
        # Room for at least one more byte but not a whole header. One byte is
        # enough to refute: it has to be a content type.
        return _Chain(records, True, offset)
    return _Chain(records, False, offset)


def _detect_tls(head):
    """
    A TLS record, and if the bytes allow it, the handshake message inside.

    A bare record header is four independent constraints -- content type,
    major version, minor version, length ceiling -- which random bytes clear
    about one time in 600,000. That is good enough to be worth reporting and
    not good enough to act on, because real non-TLS protocols are not random:
    anything whose second and third bytes are a small version number is a
    candidate. A ClientHello is different in kind. Its record length, its
    three-byte message length and its legacy version are three numbers that
    have to agree with each other and with the buffer, and nothing that is
    not TLS produces that by accident.
    """
    if len(head) < RECORD_HDR_LEN:
        return None
    content_type = head[0]
    if content_type not in CONTENT_TYPES:
        return None
    major, minor = head[1], head[2]
    if major != 3 or minor > 4:
        return None
    length = (head[3] << 8) | head[4]
    if length > MAX_RECORD_LEN:
        # The single most likely way to make this module lie: send 0x16 0x03
        # 0x03 and then anything. Refused rather than downgraded, because a
        # low-confidence wrong answer still puts a row in the report.
        PARSE_STATS['detect_tls_record_too_long'] += 1
        return None

    evidence = [
        'byte 0 is 0x{0:02x} ({1})'.format(content_type,
                                           _CONTENT_NAMES[content_type]),
        'bytes 1-2 are version 3.{0}'.format(minor),
        'record length {0} <= {1}'.format(length, MAX_RECORD_LEN),
    ]
    hello = (_handshake_evidence(head, length)
             if content_type == CONTENT_HANDSHAKE else None)

    chain = _walk_record_chain(head)
    if chain.refuted:
        # The record said where the next one starts and it is not there.
        #
        # Usually that settles it -- the stream is not TLS and the header was
        # a coincidence. Not always, and the corpus contains the exception:
        # nine Teams connections to Microsoft's media relay on port 443 open
        # with a complete, syntactically perfect TLS 1.0 handshake -- a
        # 41-byte ClientHello offering exactly one cipher suite,
        # TLS_DH_anon_WITH_RC4_128_MD5, answered by a matching ServerHello --
        # and then switch straight to MS-TURN framing with no key exchange
        # and no ChangeCipherSpec. The handshake is decoration for whatever
        # sits in front of port 443.
        #
        # Refusing that outright loses a finding worth having: a hello
        # offering anonymous RC4 is exactly what a crypto monitor should
        # surface, and a report that silently dropped it would be the more
        # misleading of the two. So a refuted chain still reports TLS when
        # the first record holds a genuine hello -- at WEAK, with the break
        # offset in the reason, so that nothing downstream mistakes it for a
        # negotiated session.
        PARSE_STATS['detect_tls_chain_refuted'] += 1
        if hello is None or hello[1] < STRONG or hello[2]:
            return None
        evidence += hello[0]
        evidence.append(
            'but the record chain breaks at offset {0}, where the bytes are '
            'not a record header: a well-formed hello in a stream that is '
            'not TLS framing throughout'.format(chain.offset))
        return Detection('tls', WEAK, '; '.join(evidence))

    if chain.records > 1:
        evidence.append(
            '{0} consecutive record headers, each where the previous '
            'length said it would be'.format(chain.records))
        confidence = STRONG
    elif RECORD_HDR_LEN + length > len(head):
        evidence.append(
            'record runs past the {0} bytes examined, so its length is '
            'unrefuted'.format(len(head)))
        confidence = LIKELY
    else:
        confidence = LIKELY

    if hello is not None:
        more, hello_confidence, contradicted = hello
        evidence += more
        # A contradiction inside the handshake header outranks anything the
        # record chain said; agreement only ever adds.
        confidence = (hello_confidence if contradicted
                      else max(confidence, hello_confidence))
    elif content_type != CONTENT_HANDSHAKE and confidence < STRONG:
        # A stream that opens on application data or an alert is a capture
        # that started mid-connection, which is common and unremarkable --
        # but there is no handshake to corroborate it, so it stays below the
        # threshold a caller would act on.
        evidence.append('no handshake to corroborate: capture probably '
                        'started mid-connection')

    return Detection('tls', confidence, '; '.join(evidence))


def _handshake_evidence(head, record_length):
    """
    Evidence from the handshake message header, when the head reaches it.

    Returns (clauses, confidence, contradicted) or None when the head stops
    before the message header. `contradicted` marks the one case where the
    handshake bytes argue *against* the record header rather than for it, and
    so must be allowed to lower a confidence the record chain raised.
    """
    body = head[RECORD_HDR_LEN:]
    if len(body) < MESSAGE_HDR_LEN:
        return None
    msg_type = body[0]
    msg_len = (body[1] << 16) | (body[2] << 8) | body[3]
    if msg_type not in HS_NAMES or msg_len > MAX_MESSAGE_LEN:
        # A handshake record whose first message header is not one. Real in
        # TLS 1.2 -- the encrypted Finished still carries content type 22 --
        # so this is not a refusal, just an absence of corroboration.
        return (['first handshake byte {0} is not a known message '
                 'type'.format(msg_type)], LIKELY, False)
    name = HS_NAMES[msg_type]
    clauses = ['handshake type {0} ({1}) of {2} bytes'.format(
        msg_type, name, msg_len)]
    exact = msg_len + MESSAGE_HDR_LEN == record_length
    if exact:
        clauses.append('which fills the {0}-byte record exactly'.format(
            record_length))
    elif msg_len + MESSAGE_HDR_LEN > record_length:
        clauses.append('spanning further records')
    else:
        clauses.append('leaving {0} bytes of the record for further '
                       'messages'.format(
                           record_length - msg_len - MESSAGE_HDR_LEN))
    # The hello's own legacy_version, two bytes past the message header. In
    # every TLS version in use it is 3.1-3.3 even when the real version is
    # negotiated in an extension, so it is a third independent number that
    # has to line up. Only a hello has it: a Certificate or a
    # ServerHelloDone begins with something else entirely, and reading two
    # bytes of DER as a version would refuse real TLS.
    if msg_type in (HS_CLIENT_HELLO, HS_SERVER_HELLO) \
            and len(body) >= MESSAGE_HDR_LEN + 2:
        legacy_major = body[MESSAGE_HDR_LEN]
        legacy_minor = body[MESSAGE_HDR_LEN + 1]
        if legacy_major != 3 or legacy_minor > 4:
            # Three agreeing fields and one that does not: not TLS framing.
            return (['handshake legacy version {0}.{1} is not a TLS '
                     'version'.format(legacy_major, legacy_minor)],
                    WEAK, True)
        clauses.append('legacy version {0}.{1}'.format(legacy_major,
                                                       legacy_minor))
        return (clauses, CERTAIN if exact else STRONG, False)
    return (clauses, STRONG if exact else LIKELY, False)


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------
# RFC 4253 section 4.2: the identification string is "SSH-protoversion-
# softwareversion" and a server that implements both versions announces
# 1.99. Anything else is SSH-1, which this project does not parse and which
# is worth naming as such rather than silently ignoring.
SSH_MODERN = (b'SSH-2.0-', b'SSH-1.99-')
SSH_PREFIX = b'SSH-'
MAX_SSH_BANNER = 255            # RFC 4253 section 4.2


def _detect_ssh(head):
    if not head.startswith(SSH_PREFIX):
        return None
    line_end = head.find(b'\n', 0, MAX_SSH_BANNER + 2)
    banner = head[:line_end] if line_end >= 0 else head[:MAX_SSH_BANNER]
    printable = _ascii_text(banner.rstrip(b'\r'))
    for prefix in SSH_MODERN:
        if head.startswith(prefix):
            return Detection('ssh', CERTAIN,
                             'identification string {0!r}, protocol version '
                             '{1}'.format(printable,
                                          prefix[4:-1].decode('ascii')))
    # SSH- with something else after it. Almost certainly SSH-1.x, which no
    # parser here handles; reported so that a network still running it is
    # visible rather than filed under "unidentified".
    PARSE_STATS['detect_ssh_legacy_version'] += 1
    return Detection('ssh', STRONG,
                     'identification string {0!r}, but the protocol version '
                     'is not 2.0 or 1.99'.format(printable))


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
# RFC 9110 methods, plus the two Outlook Anywhere verbs. The corpus exercises
# only GET, POST and HEAD; the rest cost a set membership test each and the
# alternative is an HTTP flow filed as unidentified because somebody used
# PROPFIND.
HTTP_METHODS = frozenset({
    b'GET', b'HEAD', b'POST', b'PUT', b'DELETE', b'CONNECT', b'OPTIONS',
    b'TRACE', b'PATCH',
    b'PROPFIND', b'PROPPATCH', b'MKCOL', b'COPY', b'MOVE', b'LOCK',
    b'UNLOCK', b'REPORT', b'SEARCH',
    b'RPC_IN_DATA', b'RPC_OUT_DATA',
})
HTTP1_VERSIONS = (b'HTTP/1.0', b'HTTP/1.1')

# RFC 9112 sets no limit on a request line and every server sets its own;
# 8KB is the usual one. The head is already far shorter than that, so this
# only bounds the search when a caller passes something larger.
MAX_REQUEST_LINE = 8192

# RFC 9112 section 2.2 requires CRLF and permits a recipient to accept a bare
# LF. Accepted here for the same reason: a stream that ends its request line
# with LF alone is still unambiguously HTTP, and refusing it would file it
# under "unidentified" on the strength of one missing byte.
def _first_line(head, limit=MAX_REQUEST_LINE):
    """The first line, without its terminator, and whether it was complete."""
    window = head[:limit]
    end = window.find(b'\n')
    if end < 0:
        return window, False
    line = window[:end]
    if line.endswith(b'\r'):
        line = line[:-1]
    return line, True


# The HTTP/2 connection preface (RFC 9113 section 3.4). Twenty-four bytes
# chosen by the working group precisely so that no other protocol produces
# them, which makes it the single strongest literal in this module.
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


def _detect_http2(head):
    if head.startswith(H2_PREFACE):
        return Detection('http2', CERTAIN,
                         'the {0}-byte HTTP/2 connection preface '
                         '(RFC 9113 3.4)'.format(len(H2_PREFACE)))
    if len(head) < len(H2_PREFACE) and H2_PREFACE.startswith(head):
        # Only reachable for a direction that stopped inside the preface.
        return Detection('http2', LIKELY,
                         'the first {0} bytes of the HTTP/2 connection '
                         'preface; the direction ends there'.format(len(head)))
    return None


def _detect_http1(head):
    line, complete = _first_line(head)
    if line.startswith(b'HTTP/1.'):
        # A status line. `HTTP/1.` at offset 0 is not something another
        # protocol emits, so the only question is how much of the line is
        # there to check.
        version, _, rest = line.partition(b' ')
        if version in HTTP1_VERSIONS and rest[:3].isdigit():
            return Detection('http', CERTAIN,
                             'status line {0!r}: version {1} then a '
                             'three-digit status code'.format(
                                 _ascii_text(line[:64]),
                                 version.decode('ascii')))
        return Detection('http', STRONG,
                         'starts with {0!r}, but the status line is '
                         'incomplete or malformed'.format(
                             _ascii_text(line[:64])))

    method, space, target = line.partition(b' ')
    if not space or method not in HTTP_METHODS:
        return None
    if not target:
        return None
    version = target.rpartition(b' ')[2]
    if complete and version in HTTP1_VERSIONS:
        return Detection('http', CERTAIN,
                         'request line {0!r}: method, target and '
                         '{1}'.format(_ascii_text(line[:64]),
                                      version.decode('ascii')))
    if not _is_printable_ascii(target):
        # `GET ` followed by control bytes is not a request target. Refused:
        # a three-letter prefix on its own decides nothing.
        PARSE_STATS['detect_http_target_not_text'] += 1
        return None
    if complete:
        # A complete line with a method and a target but no HTTP/1.x on the
        # end. That is HTTP/0.9, or HTTP/2, or a protocol borrowing the
        # shape; not enough to name.
        PARSE_STATS['detect_http_no_version'] += 1
        return Detection('http', WEAK,
                         'request line {0!r} names a method and a target '
                         'but no HTTP version'.format(_ascii_text(line[:64])))
    return Detection('http', LIKELY,
                     'starts with method {0} and a printable target, but the '
                     'request line does not end within the {1} bytes '
                     'examined'.format(method.decode('ascii'), len(head)))


# --------------------------------------------------------------------------
# the plaintext protocols that can become TLS mid-stream
# --------------------------------------------------------------------------
# Each of these opens with a server greeting on a single line, which is the
# only part cheap enough to be worth matching: the client's first command is
# EHLO or USER or a tagged CAPABILITY and says far less.
def _detect_greeting(head, port_hint):
    line, complete = _first_line(head, 512)
    upper = line.upper()

    if head.startswith(b'+OK') and head[3:4] in (b'', b' ', b'\r', b'\n'):
        # POP3 has exactly two status indicators, +OK and -ERR, and no other
        # protocol in common use opens a connection with a plus sign.
        return Detection('pop3', STRONG if complete else LIKELY,
                         'POP3 +OK greeting {0!r}'.format(
                             _ascii_text(line[:96])))

    if head.startswith(b'* OK'):
        if b'IMAP' in upper:
            return Detection('imap', CERTAIN,
                             'IMAP untagged OK greeting naming IMAP: '
                             '{0!r}'.format(_ascii_text(line[:96])))
        return Detection('imap', STRONG if complete else LIKELY,
                         'untagged `* OK` greeting {0!r}, which is IMAP '
                         'framing'.format(_ascii_text(line[:96])))

    if head[:3] == b'220' and head[3:4] in (b' ', b'-'):
        # SMTP and FTP share the 220 service-ready code, and telling them
        # apart from the digits alone is impossible. Nearly every real
        # greeting names itself.
        smtp = b'SMTP' in upper            # also matches ESMTP
        ftp = b'FTP' in upper
        if smtp and not ftp:
            return Detection('smtp', STRONG,
                             '220 service-ready greeting naming SMTP: '
                             '{0!r}'.format(_ascii_text(line[:96])))
        if ftp and not smtp:
            return Detection('ftp', STRONG,
                             '220 service-ready greeting naming FTP: '
                             '{0!r}'.format(_ascii_text(line[:96])))
        # The one place in this module where the port decides anything. The
        # bytes have already established "a 220 service-ready greeting"; all
        # the port does is pick which of the two services that is, and the
        # result is reported at WEAK with the port named in the reason so
        # that nobody mistakes it for byte evidence.
        guess = {21: 'ftp', 25: 'smtp', 465: 'smtp', 587: 'smtp'}.get(
            port_hint)
        if guess is None:
            PARSE_STATS['detect_ambiguous_220_greeting'] += 1
            return None
        return Detection(guess, WEAK,
                         '220 service-ready greeting {0!r} naming neither '
                         'SMTP nor FTP; read as {1} only because the server '
                         'port is {2}'.format(_ascii_text(line[:96]), guess,
                                              port_hint))
    return None


# --------------------------------------------------------------------------
# STUN / TURN
# --------------------------------------------------------------------------
# Not in the issue, and here because of what the corpus said: the only
# non-TLS conversation on port 443 across ~125,000 frames is Teams relaying
# media over TURN. Without this the headline "how much of port 443 is not
# TLS" answer is "one flow, unidentified", which invites the reader to assume
# a detector failure. It costs a four-byte compare.
STUN_COOKIE = b'\x21\x12\xa4\x42'       # RFC 5389 section 6
STUN_HDR_LEN = 20


def _detect_stun(head):
    if len(head) < STUN_HDR_LEN or head[4:8] != STUN_COOKIE:
        return None
    if head[0] & 0xC0:
        return None                      # the two most significant bits are 0
    length = (head[2] << 8) | head[3]
    if length % 4:
        return None                      # RFC 5389: always a multiple of four
    return Detection('stun', CERTAIN,
                     'the RFC 5389 magic cookie 0x2112a442 at offset 4, '
                     'message type 0x{0:04x}, body length {1} '
                     '(a multiple of four)'.format(
                         (head[0] << 8) | head[1], length))


# --------------------------------------------------------------------------
# detect
# --------------------------------------------------------------------------
# In priority order, used only to break a tie between two detectors that
# returned the same confidence. Every detector is run on every head rather
# than the first match winning, so that ordering cannot quietly decide an
# answer: the bytes do, through the confidence, and the order is a tiebreak
# of last resort. The detectors are a handful of comparisons each and all but
# one bail on the first byte, so running them all is not measurably slower
# than stopping early.
_DETECTORS = (
    ('tls', lambda head, port: _detect_tls(head)),
    ('ssh', lambda head, port: _detect_ssh(head)),
    ('http', lambda head, port: _detect_http1(head)),
    ('http2', lambda head, port: _detect_http2(head)),
    ('greeting', _detect_greeting),
    ('stun', lambda head, port: _detect_stun(head)),
)


def detect(head, port_hint=None):
    """
    Identify the protocol from the leading bytes of one direction.

    Returns a `Detection(protocol, confidence, reason)` or None. `head` is
    the first bytes of one reassembled stream direction -- pass at least
    `MIN_HEAD_BYTES` and no more than `DEFAULT_HEAD_BYTES` is needed.

    `port_hint` is the *server* port of the flow. It is used for two things
    and nothing else:

    * breaking the tie between SMTP and FTP when a `220` greeting names
      neither, which the bytes genuinely cannot do, and which is reported at
      WEAK with the port named in the reason;
    * setting `unwatched_port`, which is a finding about the live filter
      rather than evidence about the stream.

    It never selects a protocol, never overrides one the bytes chose, and
    never raises a confidence. That is the whole point of the module: the
    live path already trusts the port, and this exists to measure what that
    costs.

    Never raises. Every refusal is counted in `cryptomon.utils.PARSE_STATS`.
    """
    try:
        head = bytes(head)[:MAX_HEAD_BYTES]
    except TypeError:
        # A caller handed over something that is not a buffer. Counted rather
        # than raised because this sits on a path that walks whole captures.
        PARSE_STATS['detect_head_not_bytes'] += 1
        return None
    if not isinstance(port_hint, int) or isinstance(port_hint, bool) \
            or not 0 < port_hint < 65536:
        port_hint = None
    if len(head) < MIN_HEAD_BYTES:
        PARSE_STATS['detect_head_too_short'] += 1
        return None

    best = None
    for index, (_name, detector) in enumerate(_DETECTORS):
        found = detector(head, port_hint)
        if found is None:
            continue
        if best is None or (found.confidence, -index) > (best[0].confidence,
                                                         -best[1]):
            best = (found, index)
    if best is None:
        PARSE_STATS['detect_unidentified'] += 1
        return None

    found = best[0]
    watched = _WATCHED_FOR.get(found.protocol)
    unwatched = bool(watched is not None and port_hint is not None
                     and port_hint not in watched)
    return found._replace(port_hint=port_hint, unwatched_port=unwatched)


def _ascii_text(data):
    """A short quotable rendering of a protocol line. Never raises."""
    return data.decode('ascii', 'replace').replace('�', '.')


def _is_printable_ascii(data):
    return all(0x20 <= byte < 0x7F for byte in data)


# --------------------------------------------------------------------------
# scanning a capture
# --------------------------------------------------------------------------
# The session builder holds 16KB per direction because it has to walk a whole
# handshake. A scan holds a head, so it can afford a far larger flow table --
# and it needs one: the largest capture in the corpus opens 705 connections.
DEFAULT_SCAN_MAX_FLOWS = 8192

# A capture with a million flows should still produce a summary. The
# per-flow list stops here; the counters do not, so the totals stay right
# even when the detail is truncated.
DEFAULT_MAX_FINDINGS = 100000


class Finding(NamedTuple):
    """One TCP conversation, and what each direction said it was."""
    key: object                 # FlowKey, client -> server where known
    server_port: int
    protocol: str               # None when neither direction was identified
    confidence: float
    reason: str
    unwatched_port: bool
    oriented_by: str            # 'syn' or 'ports'
    to_server: object = None    # Detection for the client's direction
    to_client: object = None    # Detection for the server's direction


class ScanResult(NamedTuple):
    """Everything one scan concluded, plus what it refused."""
    findings: list
    by_port: collections.Counter        # (server_port, protocol) -> flows
    unidentified: collections.Counter   # head prefix -> directions
    stats: collections.Counter

    def table(self):
        """(server_port, protocol, flows) rows, commonest first."""
        rows = [(port, protocol, count)
                for (port, protocol), count in self.by_port.items()]
        rows.sort(key=lambda row: (-row[2], row[0], str(row[1])))
        return rows

    def tls_on_unwatched_ports(self):
        """
        Flows the live eBPF filter would never have been handed.

        The number issue #13 is asking for: TLS the port-based filter cannot
        see, because it is not on 443, 990, 3389, 8080 or 8443.
        """
        return [f for f in self.findings if f.unwatched_port]

    def not_tls_on_watched_ports(self):
        """
        Flows the live filter does forward, carrying something else.

        The other half of the cost: every one of these is a flow the kernel
        hands to userspace and the TLS parser then discards.
        """
        return [f for f in self.findings
                if f.server_port in EBPF_TLS_PORTS and f.protocol != 'tls']


# How much of an unidentified head to keep for the report. Enough to
# recognise a protocol by eye -- SMB2's `\xfeSMB`, LDAP's BER tag, DCE/RPC's
# version byte all land inside eight -- and short enough that the counter
# cannot become a copy of the capture.
UNIDENTIFIED_PREFIX = 8


def scan_capture(path, head_bytes=DEFAULT_HEAD_BYTES,
                 max_flows=DEFAULT_SCAN_MAX_FLOWS,
                 max_findings=DEFAULT_MAX_FINDINGS):
    """
    Walk a capture and report what protocols are present on which ports.

    This is what makes the claim measurable rather than asserted. It costs
    one reassembler bounded at `head_bytes` per direction, and abandons a
    direction the moment its protocol is settled, so a capture full of bulk
    transfer is scanned at roughly the cost of reading it.

    Returns a `ScanResult`. Each `Finding` is one conversation: the two
    directions are detected separately -- a server's ServerHello and a
    client's ClientHello are different evidence and both are kept -- and the
    flow takes whichever direction argued its case better.
    """
    reassembler = Reassembler(max_stream_bytes=head_bytes,
                              max_flows=max_flows)
    stats = collections.Counter()
    unidentified = collections.Counter()
    # Which direction of each conversation opened it. A SYN without an ACK is
    # the client, and that is the only way to know the server port for
    # certain; `_orient_by_ports` is the fallback and is counted separately
    # so a reader can see how much of the port table rests on a guess.
    clients = {}

    with Reader(path) as reader:
        for packet in reader:
            frame = decode_frame(packet.data, packet.linktype)
            if frame is None:
                stats['frames_undecodable'] += 1
                continue
            stats['frames'] += 1
            key = flow_key(frame.endpoints)
            if frame.flags & TCP_SYN and not frame.flags & TCP_ACK:
                clients[_pair(key)] = key
            update = reassembler.push(packet.timestamp, packet.data, frame)
            if update is None or not update.new_bytes:
                continue
            if update.stream.full:
                # The whole head has arrived. Nothing later can change the
                # answer, so decide now and stop buffering the connection.
                _examine(update.stream, reassembler, update.key, clients)
        stats.update({'capture_' + name: value
                      for name, value in reader.stats.items()})

    # Directions that never filled a head -- a short request, a connection
    # that was reset -- get their one look here, with whatever did arrive.
    streams = {}
    for stream in reassembler:
        _examine(stream, reassembler, stream.key, clients)
        streams[stream.key] = stream

    findings = _pair_directions(streams, clients, stats, unidentified,
                                max_findings)
    by_port = collections.Counter(
        (f.server_port, f.protocol) for f in findings)
    stats['flows'] = len(findings)
    stats.update({'reassembly_' + name: value
                  for name, value in reassembler.summary().items()})
    return ScanResult(findings, by_port, unidentified, stats)


def _pair(key):
    """A conversation, without a direction."""
    return frozenset((key, key.reverse()))


def _examine(stream, reassembler, key, clients):
    """
    Decide what one direction is carrying -- once, from its whole head.

    Called when the head is full, meaning `head_bytes` have arrived and this
    module is never going to look at more, and once at the end of the capture
    for every direction that never filled one.

    Deliberately not incremental, which the first version of this was. A
    detection made on a partial head can be *contradicted* by the bytes that
    follow, and the Teams pseudo-handshake `_detect_tls` describes is exactly
    that shape: a CERTAIN ClientHello in the first segment, refuted fifty
    bytes later. Keeping the best detection so far reported nine of those
    flows as certain TLS, and a direct call to `detect()` on the same
    direction said WEAK -- two answers from one module. Examining once, when
    the head is complete, is what makes them the same answer. It costs 320
    bytes per direction held slightly longer, which is nothing to hurry for.
    """
    if stream.state.get('examined') or not stream.data:
        return
    stream.state['examined'] = True
    # Kept in the stream's own scratch space because `abandon()` throws the
    # bytes away, and the head of a direction nothing recognised is exactly
    # what makes the report auditable rather than merely confident.
    stream.state['head_prefix'] = bytes(stream.data[:UNIDENTIFIED_PREFIX])
    client = clients.get(_pair(key))
    if client is None:
        client = _orient_by_ports(key)
    found = detect(stream.data, client.dport)
    if found is not None:
        stream.state['detection'] = found
    reassembler.abandon(key)


def _pair_directions(streams, clients, stats, unidentified, max_findings):
    """Turn per-direction detections into one Finding per conversation."""
    findings = []
    done = set()
    for key, stream in streams.items():
        pair = _pair(key)
        if pair in done:
            continue
        done.add(pair)

        client = clients.get(pair)
        if client is not None:
            oriented_by = 'syn'
        else:
            client = _orient_by_ports(key)
            oriented_by = 'ports'
            stats['flows_oriented_by_ports'] += 1
        forward = streams.get(client)
        backward = streams.get(client.reverse())

        payload_seen = False
        for direction in (forward, backward):
            if direction is None:
                continue
            prefix = direction.state.get('head_prefix')
            payload_seen = payload_seen or prefix is not None
            if prefix and not direction.state.get('detection'):
                unidentified[prefix] += 1

        # `if forward` would be wrong and was, on the first run of this over
        # the corpus: Stream defines __len__, and a direction whose bytes
        # have been released is a perfectly good object that tests false.
        # That run reported 100 of the 1356 TLS flows on port 443 and filed
        # the other 1256 -- every one cheap enough to settle and abandon --
        # as unidentified. Same shape as the truthiness bug recorded in
        # SessionBuilder.__init__, which is how it was found.
        to_server = forward.state.get('detection') if forward is not None \
            else None
        to_client = backward.state.get('detection') if backward is not None \
            else None
        best = max((d for d in (to_server, to_client) if d is not None),
                   key=lambda d: d.confidence, default=None)
        if best is None:
            # "Nothing was recognised" and "there was nothing to recognise"
            # are different claims, and conflating them would inflate the
            # count of traffic this module cannot read. A connection that
            # was refused, or reset, or whose data the capture simply did
            # not include, carries no bytes to identify.
            if payload_seen:
                stats['flows_payload_unidentified'] += 1
                why = 'payload seen in {0} direction(s), none identified' \
                    .format(sum(1 for d in (forward, backward)
                                if d is not None
                                and d.state.get('head_prefix')))
            else:
                stats['flows_without_payload'] += 1
                why = 'no payload was captured in either direction'
        if len(findings) >= max_findings:
            stats['findings_truncated'] += 1
            continue
        findings.append(Finding(
            key=client,
            server_port=client.dport,
            protocol=best.protocol if best else None,
            confidence=best.confidence if best else 0.0,
            reason=best.reason if best else why,
            # Recomputed from both ports rather than taken from the
            # Detection, which only ever saw the server's. bpf.py matches on
            # `dport == 443 || sport == 443`, so a flow is invisible to the
            # live filter only when *neither* end is on a watched port --
            # and mirroring that exactly is the difference between a
            # measurement and an argument.
            unwatched_port=_unwatched(best, client),
            oriented_by=oriented_by,
            to_server=to_server,
            to_client=to_client,
        ))
    return findings


def _unwatched(detection, key):
    """Would the kernel filter have refused to forward this flow?"""
    if detection is None:
        return False
    watched = _WATCHED_FOR.get(detection.protocol)
    if watched is None:
        return False
    return key.sport not in watched and key.dport not in watched


def _orient_by_ports(key):
    """
    Guess which way round a conversation runs, with no SYN to say.

    The same rule `pcapscan.sessions` uses: the client is the side with the
    higher port. Right for every well-known service and wrong for a service
    on an ephemeral port talking to another one -- which is why the choice is
    counted, so that a surprising port in the table can be checked against
    how many flows on it were guessed at rather than observed.
    """
    return key if key.sport > key.dport else key.reverse()
