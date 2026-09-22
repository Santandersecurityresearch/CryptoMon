"""
Fuzzing the parsers, and the invariants that make a crash the lesser worry.

Every byte this project reads is chosen by somebody else. The live path takes
whatever arrives on the wire; the CLI takes whatever capture file it is
handed; and PR-28 will take whatever a browser uploads. Wave 4 roughly
tripled the parsing surface -- TCP reassembly, TLS record walking,
handshake-message splitting, X.509 chain walking -- so this is the check on
all of it.

**An exception is the cheap failure.** It is loud, it is caught by the
callers, and it costs one handshake. The expensive failures are the quiet
ones: a buffer cap that does not hold, a bound that is off by a negative
number, a parse that returns something structurally impossible. So most of
what follows asserts invariants rather than absence of exceptions, and the
two bugs this found were both of that kind:

  * `decode_frame` could return `payload_offset > payload_end` for a frame
    that ends inside its own TCP header. Slicing with that is harmlessly
    empty, which is why nobody noticed; subtracting is a negative length.
  * `describe_certificate`, documented as "never raises", raised. cryptography
    decodes lazily, so `_name(certificate.subject)` evaluates `.subject` --
    and raises -- before the guard inside `_name` is ever entered.

A third, in the CSV exporter, was found by fuzzing whole capture files: a
corrupt pcap timestamp gives a year `datetime` cannot represent, and the
export died after every packet had already parsed.

The budgets here are small enough for the merge gate. `tests/tools/fuzz.py`
runs the same engine for as long as you like.
"""
import io
import pytest

from cryptomon.analysis import analyse
from cryptomon.parsers.framing import decode_frame
from cryptomon.parsers.tls import parse_hello_message, parse_tls
from pcapscan.certificates import MAX_CHAIN_LENGTH, parse_certificate_message
from pcapscan.export import write_csv, write_json, write_ndjson
from pcapscan.reader import CaptureError, Reader
from pcapscan.reassembly import FlowKey, Stream
from pcapscan.records import MAX_RECORD_LEN, HandshakeStream
from pcapscan.sessions import SessionBuilder, parse_ssh_stream

from fuzzing import corpora, mutate, seeded

pytestmark = pytest.mark.smoke

# Small enough that the merge gate stays under a second, large enough that a
# regression in any of the bounds shows up. tests/tools/fuzz.py is where a
# real campaign belongs.
CASES = 400

LINKTYPES = (1, 0, 12, 101, 105, 108, 113, 228, 229, 276)


@pytest.fixture(scope='module')
def seeds():
    return corpora()


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------
def test_decode_frame_offsets_are_always_a_usable_range(seeds):
    """
    The invariant that was not holding.

    A frame declaring a 32-byte TCP header but ending after 58 bytes gave
    payload_offset 66 and payload_end 58. `raw[66:58]` is empty and harmless;
    `payload_end - payload_offset` is -8, and any caller that computes a
    length from those two numbers gets nonsense. It now refuses the frame,
    which costs nothing: no frame in the 160,221-frame corpus is affected.
    """
    rnd = seeded('framing')
    for _ in range(CASES):
        raw = mutate(rnd.choice(seeds['frames']), rnd)
        frame = decode_frame(raw, rnd.choice(LINKTYPES))
        if frame is None:
            continue
        assert 0 <= frame.payload_offset <= frame.payload_end <= len(raw)
        assert frame.version in (4, 6)
        assert 0 <= frame.seq <= 0xFFFFFFFF
        assert 0 <= frame.flags <= 0xFF
        assert set(frame.endpoints) == {'src', 'dst'}


def test_an_unreadable_frame_is_refused_rather_than_guessed(seeds):
    """Truncated to any length, a frame either decodes correctly or not at all."""
    frame_bytes = seeds['frames'][0]
    for cut in range(0, len(frame_bytes), 7):
        frame = decode_frame(frame_bytes[:cut], 1)
        if frame is not None:
            assert frame.payload_offset <= frame.payload_end <= cut


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------
def test_parse_tls_never_raises_and_never_half_answers(seeds):
    rnd = seeded('parse_tls')
    for _ in range(CASES):
        raw = mutate(rnd.choice(seeds['frames']), rnd)
        parsed = parse_tls(raw)
        if not parsed:
            continue
        # A result is either a whole hello or nothing. There is no state in
        # between that a consumer could mistake for one.
        assert parsed['ptype'] in ('client', 'server')
        assert isinstance(parsed['tls'], dict)
        assert isinstance(parsed['eth'], dict)


def test_parse_hello_message_never_raises(seeds):
    rnd = seeded('hello')
    for _ in range(CASES):
        body = mutate(rnd.choice(seeds['hellos']), rnd)
        parsed = parse_hello_message(rnd.choice([1, 2]), body)
        if parsed:
            assert isinstance(parsed['tls'].get('extensions'), list)


def test_every_algorithm_list_stays_a_list_of_strings(seeds):
    """
    A downstream consumer indexes these. A bytes object or a tuple slipping
    into `groups` would be found by a dashboard, in production, rather than
    here.
    """
    rnd = seeded('lists')
    for _ in range(CASES):
        parsed = parse_hello_message(1, mutate(rnd.choice(seeds['hellos']), rnd))
        tls = parsed.get('tls') or {}
        for field in ('ciphersuites', 'groups', 'sigalgs'):
            for value in tls.get(field) or []:
                assert isinstance(value, str)


# --------------------------------------------------------------------------
# record and message framing
# --------------------------------------------------------------------------
def test_chunking_a_stream_cannot_change_what_it_contains(seeds):
    """
    The strongest property in this file.

    Segment boundaries fall wherever TCP puts them, so the same bytes arrive
    split differently on every run. If feeding a stream in 97-byte pieces
    produced different handshake messages from feeding it whole, the parser
    would be reporting a property of the network rather than of the traffic --
    and it would do so intermittently, which is the worst way to find out.
    """
    rnd = seeded('chunking')
    for _ in range(CASES // 2):
        blob = mutate(rnd.choice(seeds['streams']), rnd)
        whole = HandshakeStream().feed(blob)

        chunked, walker, offset = [], HandshakeStream(), 0
        while offset < len(blob):
            width = rnd.randrange(1, 257)
            chunked += walker.feed(blob[offset:offset + width])
            offset += width

        assert [(m.msg_type, m.body) for m in whole] == \
               [(m.msg_type, m.body) for m in chunked]


def test_a_handshake_stream_holds_a_bounded_amount(seeds):
    """
    A crafted length field must cost a bounded wait, not an unbounded buffer.
    """
    rnd = seeded('bounds')
    for _ in range(CASES // 2):
        blob = mutate(rnd.choice(seeds['streams']), rnd)
        walker = HandshakeStream()
        messages = walker.feed(blob)
        assert walker.pending_bytes <= len(blob) + MAX_RECORD_LEN
        for message in messages:
            assert len(message.body) <= walker.max_message_len


def test_an_unusable_stream_stays_unusable(seeds):
    """Once the record boundary is lost, nothing later is trustworthy."""
    rnd = seeded('unusable')
    for _ in range(CASES // 4):
        walker = HandshakeStream()
        walker.feed(mutate(rnd.choice(seeds['streams']), rnd))
        if not walker.usable:
            assert walker.feed(seeds['streams'][0]) == []


# --------------------------------------------------------------------------
# reassembly
# --------------------------------------------------------------------------
def test_a_stream_never_exceeds_its_caps(seeds):
    """
    Memory is the property that matters here: this runs over files chosen by
    somebody else, and the ceiling is what makes that safe.
    """
    rnd = seeded('reassembly')
    for _ in range(CASES // 2):
        blob = mutate(rnd.choice(seeds['streams']), rnd)
        stream = Stream(FlowKey('10.0.0.1', 1, '10.0.0.2', 443), 2048, 6)
        base = rnd.randrange(1 << 32)
        for offset in range(0, len(blob), 150):
            # Deliberately disordered, overlapping and wrapping.
            seq = (base + rnd.choice([offset, offset - 70, offset + 900, 0])) \
                & 0xFFFFFFFF
            stream.add(seq, blob[offset:offset + 150],
                       rnd.choice([0x18, 0x02, 0x11, 0x04]), 0.0)
        assert len(stream.data) <= 2048
        assert len(stream.pending) <= 6
        assert sum(len(v) for v in stream.pending.values()) < 1 << 20


# --------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------
def test_describe_certificate_really_never_raises(seeds):
    """
    It is documented as never raising, and it did.

    cryptography decodes a certificate lazily, so `load_der_x509_certificate`
    succeeding says nothing about whether `.subject` will. The guard has to be
    on the attribute access, and on every attribute access, because any of
    them can be the next one.
    """
    pytest.importorskip("cryptography")
    rnd = seeded('certificates')
    for _ in range(CASES // 2):
        body = mutate(rnd.choice(seeds['certificates']), rnd)
        chain = parse_certificate_message(body)
        assert len(chain) <= MAX_CHAIN_LENGTH
        for certificate in chain:
            assert len(certificate['fingerprint_sha256']) == 64
            assert isinstance(certificate.get('undecodable_fields', []), list)


def test_a_certificate_that_half_decodes_says_which_half(seeds):
    """
    "We could not read the subject" and "this certificate has no subject" are
    different statements. A report that conflated them would be worth less
    than one that admits the gap.
    """
    pytest.importorskip("cryptography")
    rnd = seeded('partial')
    partial = 0
    for _ in range(CASES * 2):
        body = mutate(rnd.choice(seeds['certificates']), rnd)
        for certificate in parse_certificate_message(body):
            for field in certificate.get('undecodable_fields', []):
                assert certificate[field] is None
                partial += 1
    assert partial, "no partially-decodable certificate was generated"


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------
def test_wire_text_is_always_printable(seeds):
    """
    A server_name is attacker-controlled bytes, and every consumer of it --
    a CSV column, a JSON document, the report page, a log line, a terminal --
    assumes it is a hostname.

    Found by fuzzing, and only on Python 3.10: a corrupted extension
    carrying a carriage return made the CSV writer raise "need to escape,
    but no escapechar set", where 3.11 quotes the field instead. The same
    input therefore crashed one interpreter and wrote a corrupt row on the
    other, which is a worse pair than either alone.
    """
    from cryptomon.utils import printable_text

    rnd = seeded('text')
    for _ in range(CASES):
        parsed = parse_hello_message(1, mutate(rnd.choice(seeds['hellos']),
                                               rnd))
        hostname = (parsed.get('tls') or {}).get('hostname')
        if hostname is None:
            continue
        assert all(0x20 <= ord(c) <= 0x7e for c in hostname), repr(hostname)

    # Escaped rather than stripped: the escape is reversible, and a peer
    # sending something that is not a hostname is itself the finding.
    assert printable_text('ok.example.com') == 'ok.example.com'
    assert printable_text('bad\r\nhost') == 'bad\\x0d\\x0ahost'
    assert printable_text('nul\x00here') == 'nul\\x00here'


def test_parse_ssh_stream_never_raises(seeds):
    rnd = seeded('ssh')
    for _ in range(CASES):
        parsed = parse_ssh_stream(mutate(rnd.choice(seeds['streams']), rnd))
        assert isinstance(parsed, dict)
        for value in parsed.values():
            assert isinstance(value, (str, list))


# --------------------------------------------------------------------------
# the whole pipeline, on whole capture files
# --------------------------------------------------------------------------
def test_a_corrupt_capture_file_never_takes_down_the_pipeline():
    """
    The surface an upload form exposes: reader, reassembly, records, parsers,
    analysis and every exporter, over a file somebody else chose.

    This is where the CSV timestamp bug surfaced. Every packet in the capture
    had parsed; the export then died on `datetime.fromtimestamp` because a
    corrupted four-byte timestamp field is a year outside what datetime can
    represent.
    """
    from fuzzing import capture_files

    rnd = seeded('pipeline')
    files = capture_files()
    refused = analysed = 0
    for _ in range(CASES // 4):
        blob = mutate(rnd.choice(files), rnd)
        builder = SessionBuilder()
        try:
            with Reader(io.BytesIO(blob)) as reader:
                for packet in reader:
                    frame = decode_frame(packet.data, packet.linktype)
                    if frame is not None:
                        builder.push(packet.timestamp, packet.data, frame)
        except CaptureError:
            refused += 1
            continue
        records = list(builder.finish())
        summary = analyse(records)
        assert summary.readiness()['sessions'] == len(records)
        # Every key in the summary has to be a string, or `json.dumps` with
        # sort_keys cannot order it. One unreadable certificate used to put
        # a None key in `certificate_keys` and take the whole export down.
        for name, value in summary.as_dict().items():
            if isinstance(value, dict):
                assert all(isinstance(k, str) for k in value), name
        write_ndjson(records, io.StringIO())
        write_csv(records, io.StringIO())
        write_json(records, io.StringIO(), summary)
        analysed += 1
    # Both outcomes have to occur, or the corpus is not exercising the split.
    assert refused, "nothing was refused -- is the mutation reaching the header?"
    assert analysed, "nothing survived -- the mutation is too destructive"
