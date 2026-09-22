"""
Deciding what a stream carries from its bytes, not from its port.

Two kinds of test here, and the split matters.

**Constructed inputs**, for the protocols the capture corpus does not
contain. Measured over ~125,000 frames the corpus holds TLS, HTTP/1.1, STUN
and one Microsoft pseudo-TLS handshake, and no SSH, no HTTP/2 and no SMTP,
IMAP, POP3 or FTP at all -- not one `220 ` greeting anywhere. Those detectors
therefore have exactly the coverage written here, and saying so is more
useful than implying the corpus exercised them.

**Real captures**, for TLS, where the corpus is the whole point: the
committed stream fixtures are complete conversations, and a detector that
cannot name them has no business reporting on anything.

The negative tests carry the most weight. A protocol detector that says
"probably TLS" about everything is worse than no detector, because it moves
the wrong answer from the port number -- where everybody knows to distrust it
-- into a field labelled `confidence`. So: random bytes, zeros, a single
byte, nothing at all, and the specific attack of sending three bytes that
look like a TLS record header and then anything at all.
"""
import pathlib
import random
import re
import struct

import pytest

from cryptomon.utils import PARSE_STATS, reset_parse_stats
from pcapscan.protocols import (CERTAIN, DEFAULT_HEAD_BYTES,
                                EBPF_WATCHED_PORTS, LIKELY, STRONG, WEAK,
                                Detection, detect, scan_capture)

from fuzzing import corpora, mutate, seeded

pytestmark = pytest.mark.smoke

HERE = pathlib.Path(__file__).resolve().parent
STREAMS = HERE / "fixtures" / "streams"

# Budget for the mutation pass. Small enough for the merge gate, large enough
# that a bound that stopped holding would show up; tests/tools/fuzz.py is
# where a real campaign belongs.
FUZZ_CASES = 600


# --------------------------------------------------------------------------
# minimal, hand-built examples of each protocol
# --------------------------------------------------------------------------
def record(content_type, body, version=(3, 3)):
    return (bytes([content_type, version[0], version[1],
                   len(body) >> 8, len(body) & 0xFF]) + body)


def message(msg_type, body):
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def client_hello(version=(3, 3), legacy=b'\x03\x03'):
    """The smallest legal ClientHello: one cipher suite, no extensions."""
    body = (legacy + bytes(32)             # legacy_version, random
            + b'\x00'                      # session id: empty
            + b'\x00\x02\x13\x01'          # one cipher suite
            + b'\x01\x00')                 # one compression method
    return record(22, message(1, body), version)


def server_hello():
    body = (b'\x03\x03' + bytes(32) + b'\x00' + b'\x13\x01' + b'\x00')
    return record(22, message(2, body))


SSH_BANNER = b'SSH-2.0-OpenSSH_9.6\r\n'
HTTP_REQUEST = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
HTTP_RESPONSE = (b'HTTP/1.1 200 OK\r\nServer: nginx\r\n'
                 b'Content-Length: 0\r\n\r\n')
H2_PREFACE = (b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
              b'\x00\x00\x00\x04\x00\x00\x00\x00\x00')
SMTP_GREETING = b'220 mail.example.com ESMTP Postfix (Debian)\r\n'
IMAP_GREETING = b'* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n'
POP3_GREETING = b'+OK POP3 server ready <1896.697@example.com>\r\n'
FTP_GREETING = b'220 (vsFTPd 3.0.5)\r\n'
STUN_BINDING = (b'\x00\x01\x00\x08' + b'\x21\x12\xa4\x42' + b'\xab' * 12
                + b'\x00\x25\x00\x04\x00\x00\x00\x00')


@pytest.mark.parametrize("head,protocol", [
    (client_hello(), 'tls'),
    (server_hello(), 'tls'),
    (SSH_BANNER, 'ssh'),
    (HTTP_REQUEST, 'http'),
    (HTTP_RESPONSE, 'http'),
    (H2_PREFACE, 'http2'),
    (SMTP_GREETING, 'smtp'),
    (IMAP_GREETING, 'imap'),
    (POP3_GREETING, 'pop3'),
    (FTP_GREETING, 'ftp'),
    (STUN_BINDING, 'stun'),
])
def test_each_protocol_is_named_from_its_bytes(head, protocol):
    """
    The whole contract, one line per protocol, with no port in sight.

    Every one of these is what the first bytes of a real connection look
    like. If any stops being recognised, the live path's port list becomes
    the only thing selecting traffic again, which is issue #13.
    """
    found = detect(head)
    assert found is not None, 'nothing detected'
    assert found.protocol == protocol
    assert found.confidence >= STRONG


def test_a_client_hello_is_stronger_evidence_than_a_bare_record():
    """
    A record header is four small constraints that non-TLS traffic can meet
    by accident. A hello adds two lengths and a version that all have to
    agree with each other, which nothing else produces. Collapsing the two
    into one confidence would mean a report could not tell "a handshake was
    captured" from "a byte happened to be 0x17".
    """
    hello = detect(client_hello())
    bare = detect(record(23, bytes(32)))
    assert hello.confidence == CERTAIN
    assert bare.protocol == 'tls'
    assert bare.confidence < hello.confidence
    assert 'no handshake to corroborate' in bare.reason


def test_a_reason_is_evidence_a_reader_can_check():
    """
    A bare 'tls' cannot be audited; the offsets and values can. This is the
    difference between a report someone acts on and one they have to take on
    trust, and it is why Detection carries a reason at all.
    """
    found = detect(client_hello())
    for fragment in ('0x16', 'handshake', '3.3', 'client_hello',
                     'fills the', 'record exactly'):
        assert fragment in found.reason, found.reason


def test_two_chained_records_corroborate_a_stream_with_no_handshake():
    """
    A capture that begins mid-connection has only application data to go on.
    One such record is weak; a second one starting exactly where the first
    said it would is a length field checked against the buffer, and that is
    what lifts a mid-stream capture out of 'unidentified'. Thirteen flows in
    the corpus rest on precisely this, including the only TLS found on port
    888.
    """
    one = detect(record(23, bytes(32)))
    two = detect(record(23, bytes(32)) + record(23, bytes(48)))
    assert two.confidence > one.confidence
    assert '2 consecutive record headers' in two.reason


def test_ssh_1_is_named_rather_than_ignored():
    """
    No parser here handles SSH-1, but a network still running it is a
    finding, and filing it under 'unidentified' would hide it.
    """
    reset_parse_stats()
    found = detect(b'SSH-1.5-OpenSSH_2.9\r\n')
    assert found.protocol == 'ssh'
    assert found.confidence == STRONG
    assert PARSE_STATS['detect_ssh_legacy_version']


def test_a_starttls_capable_protocol_says_so():
    """
    Each of these can turn into TLS partway through the stream, which is
    where the live filter -- which never sees port 25 or 143 at all -- and
    the offline path -- which classifies a direction once, from its first
    bytes -- would both miss it. Detecting them is what makes that gap
    findable.
    """
    assert detect(SMTP_GREETING).starttls_capable
    assert detect(IMAP_GREETING).starttls_capable
    assert not detect(client_hello()).starttls_capable
    assert not detect(HTTP_REQUEST).starttls_capable


# --------------------------------------------------------------------------
# negatives: what must never be claimed
# --------------------------------------------------------------------------
@pytest.mark.parametrize("head", [
    b'',
    b'\x16',
    b'\x16\x03',
    b'\x16\x03\x03',
    bytes(DEFAULT_HEAD_BYTES),
    b'\x00' * 4,
    b'\xff' * 64,
    b'\x05\x00\x0b\x07\x10\x00\x00\x00',    # DCE/RPC bind, from the corpus
    b'\x00\x00\x00\xf8\xfeSMB\x40\x00',     # SMB2, from the corpus
    b'0\x84\x00\x00\x01Y\x02\x02\n\x03',    # LDAP BER, from the corpus
])
def test_nothing_is_claimed_without_evidence(head):
    """
    The inputs a detector is most likely to get wrong: too short to test
    anything, uniform, and three real protocols from the corpus that this
    module deliberately does not name. Reporting any of them as a protocol
    would put a fabricated row in a report that is meant to be attestable.
    """
    assert detect(head) is None
    assert detect(head, 443) is None


def test_a_tls_prefix_with_an_absurd_length_is_refused():
    """
    The cheapest way to make this module lie: send 0x16 0x03 0x03 and then
    whatever you like. The record length is the first field that can be
    checked against something other than itself, so it is the first refusal
    -- and a refusal, not a low confidence, because a wrong answer at 0.3
    still puts a row in the report.
    """
    reset_parse_stats()
    assert detect(b'\x16\x03\x03\xff\xff' + b'A' * 64) is None
    assert PARSE_STATS['detect_tls_record_too_long'] == 1


def test_a_record_that_leads_nowhere_is_refused():
    """
    A well-formed record header whose length points at bytes that cannot be
    another record header. The length has been checked against the buffer and
    failed, which is stronger evidence than the header was ever going to be.
    """
    reset_parse_stats()
    head = record(22, b'not a handshake message at all') + b'\xde\xad\xbe\xef'
    assert detect(head) is None
    assert PARSE_STATS['detect_tls_chain_refuted'] == 1


def test_a_real_hello_in_a_stream_that_is_not_tls_is_reported_weakly():
    """
    The exception found in the corpus, and the reason the previous test is
    not simply 'refuse on a broken chain'.

    Nine Teams connections to Microsoft's media relay on port 443 open with a
    complete, syntactically perfect TLS 1.0 handshake -- a 41-byte
    ClientHello offering only TLS_DH_anon_WITH_RC4_128_MD5 -- and then drop
    into MS-TURN framing with no key exchange and no ChangeCipherSpec. A
    hello offering anonymous RC4 is exactly what a crypto monitor should
    surface, so refusing it outright would be the more misleading answer. It
    is reported, at the bottom rung, with the break offset in the reason.
    """
    head = client_hello() + b'\x02\x00\x00\x44\x00\x03\x00\x30!\x12\xa4B'
    found = detect(head, 443)
    assert found.protocol == 'tls'
    assert found.confidence == WEAK
    assert 'breaks at offset 50' in found.reason
    assert 'not TLS framing throughout' in found.reason


def test_an_ambiguous_220_greeting_is_refused_rather_than_guessed():
    """
    SMTP and FTP share the 220 service-ready code and a greeting that names
    neither cannot be told apart from the bytes. Picking one would be the
    port-guessing this module exists to replace, done in a different place.
    """
    reset_parse_stats()
    assert detect(b'220 service ready\r\n') is None
    assert PARSE_STATS['detect_ambiguous_220_greeting'] == 1


def test_random_bytes_are_not_a_protocol():
    """
    The check that the whole design rests on. A detector loose enough to
    match noise would report a protocol for every flow on the network and
    the report would be worthless. Seeded, so a failure is reproducible.
    """
    rnd = random.Random('protocols-negative')
    claims = []
    for _ in range(2000):
        head = bytes(rnd.randrange(256)
                     for _ in range(rnd.randrange(5, DEFAULT_HEAD_BYTES)))
        found = detect(head, rnd.choice((None, 80, 443, 8443)))
        if found is not None:
            claims.append(found)
    assert not [c for c in claims if c.confidence > LIKELY], claims[:3]
    assert len(claims) < 20, len(claims)


# --------------------------------------------------------------------------
# the port is never the signal
# --------------------------------------------------------------------------
def test_http_on_443_is_reported_as_http():
    """
    The case issue #13 is about, in miniature. The live filter forwards this
    flow because of its port and the TLS parser then finds nothing in it.
    Trusting the port here would reproduce that mistake offline.
    """
    found = detect(HTTP_REQUEST, 443)
    assert found.protocol == 'http'
    assert found.confidence == CERTAIN


def test_tls_on_an_unusual_port_is_reported_as_tls():
    found = detect(client_hello(), 53443)
    assert found.protocol == 'tls'
    assert found.unwatched_port is True


def test_tls_on_a_watched_port_is_not_flagged():
    assert detect(client_hello(), 443).unwatched_port is False
    assert detect(client_hello(), 8443).unwatched_port is False


def test_a_port_the_filter_does_not_cover_is_not_a_missed_flow():
    """
    `unwatched_port` means "the kernel filter would never have been handed
    this", which is a claim about TLS and SSH. An HTTP flow on port 9999 was
    never in scope, and flagging it would inflate the number this PR rests
    on.
    """
    assert detect(HTTP_REQUEST, 9999).unwatched_port is False


@pytest.mark.parametrize("head", [client_hello(), SSH_BANNER, HTTP_REQUEST,
                                  STUN_BINDING, POP3_GREETING])
def test_the_port_hint_changes_neither_protocol_nor_confidence(head):
    """
    The one invariant that keeps this module honest. A port that agrees with
    the bytes adds nothing the bytes did not already say, and a port that
    disagrees is the finding. Either way it must not move the answer -- the
    only exception is the 220 greeting, which has its own test.
    """
    without = detect(head)
    for port in (21, 22, 25, 80, 443, 8443, 53443, 65535):
        with_port = detect(head, port)
        assert with_port.protocol == without.protocol
        assert with_port.confidence == without.confidence
        assert with_port.reason == without.reason


def test_the_port_only_breaks_the_smtp_ftp_tie():
    """
    The single place a port decides anything, reported at the bottom rung
    with the port named in the reason so nobody mistakes it for evidence.
    """
    ambiguous = b'220 service ready\r\n'
    assert detect(ambiguous, 25).protocol == 'smtp'
    assert detect(ambiguous, 21).protocol == 'ftp'
    assert detect(ambiguous, 25).confidence == WEAK
    assert 'server port is 25' in detect(ambiguous, 25).reason
    # ...and only where the bytes are genuinely silent. A banner that names
    # itself is not up for negotiation.
    assert detect(FTP_GREETING, 25).protocol == 'ftp'
    assert detect(SMTP_GREETING, 21).protocol == 'smtp'


def test_the_watched_port_list_matches_the_ebpf_program():
    """
    EBPF_WATCHED_PORTS is a copy of a list that lives in a C source string
    and cannot be imported as data. This is what stops the copy drifting: a
    port added to bpf.py without being added here would silently inflate the
    count of TLS the live path is said to miss, which is the number this
    whole PR rests on.
    """
    from cryptomon.bpf import bpf_text
    in_program = {int(port)
                  for port in re.findall(r'[ds]port == (\d+)', bpf_text)}
    assert in_program == set(EBPF_WATCHED_PORTS)


# --------------------------------------------------------------------------
# real captures
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["tls12_certificate",
                                  "tls12_split_certificate",
                                  "tls13_hello_retry"])
def test_tls_is_named_in_a_real_conversation(name):
    """
    The committed stream fixtures are whole TCP conversations with a SYN, so
    the client direction is known rather than guessed. Each must come out as
    one flow, certainly TLS, on the port it really used.
    """
    result = scan_capture(STREAMS / f"{name}.pcap")
    assert len(result.findings) == 1
    found = result.findings[0]
    assert found.protocol == 'tls'
    assert found.confidence == CERTAIN
    assert found.server_port == 443
    assert found.oriented_by == 'syn'
    # Both halves are detected separately: a ClientHello and the ServerHello
    # answering it are different evidence and a report that kept only one
    # could not say which side was seen.
    assert found.to_server is not None and found.to_client is not None
    assert result.table() == [(443, 'tls', 1)]


def test_a_direction_whose_bytes_were_released_still_reports_its_protocol():
    """
    The regression this scan was first written with, and worth a test of its
    own because it is silent.

    `scan_capture` abandons a direction the moment its head is complete,
    which frees the bytes but leaves the Stream in the flow table. `Stream`
    defines `__len__`, so a released one is a perfectly good object that
    tests false -- and `if stream:` therefore discarded the detection for
    every flow cheap enough to settle early. Measured over the corpus, that
    reported 100 of the 1356 TLS flows on port 443 and filed the other 1256
    as unidentified.

    A 16-byte head guarantees every direction here fills and is released.
    """
    result = scan_capture(STREAMS / "tls12_certificate.pcap", head_bytes=16)
    assert [f.protocol for f in result.findings] == ['tls']
    assert result.findings[0].confidence == CERTAIN


def test_a_scan_counts_what_it_could_not_name():
    """
    A port table that lists only what was recognised invites the reader to
    assume the rest was nothing. The counters say how many flows carried
    payload nobody named, and keep the head of each so the claim can be
    checked.
    """
    result = scan_capture(STREAMS / "tls13_hello_retry.pcap")
    assert result.stats['flows'] == len(result.findings)
    assert not result.unidentified            # this capture is all TLS
    assert result.stats['frames'] > 0


def test_an_unusual_port_is_reported_as_unwatched(tmp_path):
    """
    The finding issue #13 asks for, end to end: a real ClientHello on a port
    the kernel filter does not watch has to come out of a scan flagged, not
    merely present. In the corpus this is thirteen flows -- twelve on 53443
    and one on 888 -- and a regression here would report zero without
    failing anything else.
    """
    capture = tmp_path / "odd_port.pcap"
    capture.write_bytes(one_packet_capture(client_hello(), dport=53443))
    result = scan_capture(capture)
    assert [f.protocol for f in result.findings] == ['tls']
    assert result.tls_on_unwatched_ports() == result.findings
    assert result.findings[0].server_port == 53443

    # ...and the same hello on 443 is not flagged, so the count means
    # something.
    watched = tmp_path / "normal_port.pcap"
    watched.write_bytes(one_packet_capture(client_hello(), dport=443))
    assert scan_capture(watched).tls_on_unwatched_ports() == []


def test_a_scan_reports_non_tls_on_a_watched_port(tmp_path):
    """
    The other half of the cost the live filter pays: every flow here is one
    the kernel forwards to userspace for the TLS parser to discard. In the
    corpus it is one TURN-over-TCP conversation on 443, which is small -- and
    a measured small number is the result, not a reason to stop measuring.
    """
    capture = tmp_path / "stun_on_443.pcap"
    capture.write_bytes(one_packet_capture(STUN_BINDING, dport=443))
    result = scan_capture(capture)
    waste = result.not_tls_on_watched_ports()
    assert [f.protocol for f in waste] == ['stun']


def one_packet_capture(payload, dport, sport=51000):
    """
    A one-frame pcap carrying `payload` over Ethernet/IPv4/TCP.

    Built from struct rather than scapy: these are smoke tests, and the
    fixtures that do need scapy already skip without it. The SYN is included
    so the scan orients on it rather than on the ports, which is the whole
    point when the server port is the thing under test.
    """
    frames = [_frame(payload, sport, dport, flags=0x02, seq=0),
              _frame(payload, sport, dport, flags=0x18, seq=1)]
    out = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        out += struct.pack('<IIII', 1700000000 + index, 0,
                           len(frame), len(frame))
        out += frame
    return out


def _frame(payload, sport, dport, flags, seq):
    body = payload if flags & 0x08 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, 0, 5 << 4, flags,
                      65535, 0, 0) + body
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)))
    return b'\x02' + bytes(5) + b'\x02' + bytes(5) + b'\x08\x00' + ip + tcp


# --------------------------------------------------------------------------
# it never raises
# --------------------------------------------------------------------------
@pytest.fixture(scope='module')
def seeds():
    return corpora()


def test_detection_survives_mutated_real_streams(seeds):
    """
    `detect` runs over every direction of every flow in a capture, so an
    exception on one hostile head stops a whole scan. Seeded from real
    reassembled streams and perturbed, because uniform random bytes fail the
    first comparison and never reach the length arithmetic.
    """
    rnd = seeded('protocols')
    ports = (None, 0, 22, 443, 65535, 65536, -1)
    for index in range(FUZZ_CASES):
        head = mutate(rnd.choice(seeds['streams'])[:DEFAULT_HEAD_BYTES], rnd)
        found = detect(head, ports[index % len(ports)])
        if found is None:
            continue
        assert isinstance(found, Detection)
        assert isinstance(found.protocol, str) and found.protocol
        assert WEAK <= found.confidence <= CERTAIN
        assert found.reason


@pytest.mark.parametrize("port_hint", [None, 443, True, -1, 1 << 40,
                                       'https', 3.5, object()])
def test_a_nonsense_port_hint_is_ignored_rather_than_raised(port_hint):
    """
    The hint reaches this from a flow table built out of capture bytes, so it
    is as attacker-influenced as the head is. It is advisory in every case,
    which makes discarding a bad one the right answer.
    """
    assert detect(client_hello(), port_hint).protocol == 'tls'


@pytest.mark.parametrize("head", [None, 42, 'a string', [1, 2, 3],
                                  bytearray(b'\x16\x03\x03\x00\x05hello'),
                                  memoryview(b'GET / HTTP/1.1\r\n\r\n')])
def test_a_head_that_is_not_bytes_is_refused_not_raised(head):
    """
    Counted rather than raised, because this sits on a path that walks whole
    captures: one bad call should cost one flow, not the scan.
    """
    found = detect(head)
    assert found is None or isinstance(found, Detection)


def test_detect_is_pure(seeds):
    """
    Two calls, one answer. The detector holds no state, so a scan's result
    cannot depend on the order the flows happened to arrive in -- which is
    what makes a capture scanned twice produce the same report.
    """
    rnd = seeded('purity')
    for _ in range(100):
        head = mutate(rnd.choice(seeds['streams'])[:DEFAULT_HEAD_BYTES], rnd)
        assert detect(head, 443) == detect(head, 443)
