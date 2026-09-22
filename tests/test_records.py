"""
TLS record and handshake-message framing.

Everything here is constructed: records of chosen lengths, fed in chosen
pieces. Real captures prove that the walk works on real traffic (see
test_reassembly.py); these prove it works on the shapes real traffic only
occasionally produces, and on the ones an attacker would produce deliberately.
"""
import pytest

from pcapscan.records import (CONTENT_ALERT, CONTENT_APPLICATION_DATA,
                              CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE,
                              HandshakeStream, MAX_MESSAGE_LEN,
                              looks_like_tls, plausible_handshake)

pytestmark = pytest.mark.smoke

CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, FINISHED = 1, 2, 11, 20


def record(content_type, body, version=(3, 3)):
    return (bytes([content_type, version[0], version[1],
                   len(body) >> 8, len(body) & 0xFF]) + body)


def message(msg_type, body):
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def hello(msg_type=CLIENT_HELLO, size=200):
    """A handshake message of a given size, contents irrelevant here."""
    return message(msg_type, bytes(range(256)) * (size // 256) + bytes(size % 256))


# --------------------------------------------------------------------------
# the two framings, and the four ways they can disagree
# --------------------------------------------------------------------------
def test_one_message_in_one_record():
    stream = HandshakeStream()
    got = stream.feed(record(CONTENT_HANDSHAKE, hello(size=100)))
    assert [(m.msg_type, len(m.body)) for m in got] == [(CLIENT_HELLO, 100)]


def test_several_messages_in_one_record():
    """
    ServerHello, Certificate, ServerKeyExchange and ServerHelloDone routinely
    arrive in a single record. Treating a record as a message finds the first
    and loses the rest.
    """
    body = (hello(SERVER_HELLO, 80) + hello(CERTIFICATE, 300)
            + hello(14, 0))
    got = HandshakeStream().feed(record(CONTENT_HANDSHAKE, body))
    assert [(m.msg_type, len(m.body)) for m in got] == [
        (SERVER_HELLO, 80), (CERTIFICATE, 300), (14, 0)]


def test_one_message_across_several_records():
    """
    A certificate chain is several kilobytes and a record holds at most 16KB
    in theory, far less in practice; chains routinely span four or five.
    """
    msg = hello(CERTIFICATE, 3000)
    stream = HandshakeStream()
    assert stream.feed(record(CONTENT_HANDSHAKE, msg[:1000])) == []
    assert stream.feed(record(CONTENT_HANDSHAKE, msg[1000:2500])) == []
    got = stream.feed(record(CONTENT_HANDSHAKE, msg[2500:]))
    assert [(m.msg_type, len(m.body)) for m in got] == [(CERTIFICATE, 3000)]


def test_a_record_arriving_in_pieces():
    """Segment boundaries fall wherever TCP puts them, not on record edges."""
    blob = record(CONTENT_HANDSHAKE, hello(size=400))
    stream = HandshakeStream()
    out = []
    for i in range(0, len(blob), 37):       # a deliberately awkward stride
        out += stream.feed(blob[i:i + 37])
    assert [(m.msg_type, len(m.body)) for m in out] == [(CLIENT_HELLO, 400)]


def test_a_record_before_the_handshake_does_not_hide_it():
    """
    The measured 7% gap in the live path. bpf.py forwards a frame only when
    its payload *starts* with a handshake record, so a segment carrying
    anything ahead of the handshake is never seen at all.
    """
    blob = (record(CONTENT_CHANGE_CIPHER_SPEC, b'\x01')
            + record(CONTENT_HANDSHAKE, hello(size=120)))
    got = HandshakeStream().feed(blob)
    assert [(m.msg_type, len(m.body)) for m in got] == [(CLIENT_HELLO, 120)]


# --------------------------------------------------------------------------
# where the plaintext ends
# --------------------------------------------------------------------------
def test_application_data_ends_the_walk():
    stream = HandshakeStream()
    stream.feed(record(CONTENT_HANDSHAKE, hello(size=50))
                + record(CONTENT_APPLICATION_DATA, b'\x00' * 40))
    assert stream.encrypted
    assert not stream.usable
    assert stream.feed(record(CONTENT_HANDSHAKE, hello(size=50))) == []


def test_tls12_finished_after_change_cipher_spec_is_not_parsed():
    """
    In TLS 1.2 the record after ChangeCipherSpec is the encrypted Finished.
    Its content type still says 22, so a walker that trusts the type alone
    reads ciphertext as a handshake message and reports whatever it finds.
    """
    ciphertext = bytes([0x9e, 0xf3, 0x21, 0x44]) + b'\xa7' * 36
    stream = HandshakeStream()
    stream.feed(record(CONTENT_HANDSHAKE, hello(SERVER_HELLO, 76))
                + record(CONTENT_CHANGE_CIPHER_SPEC, b'\x01')
                + record(CONTENT_HANDSHAKE, ciphertext))
    assert stream.cipher_changed
    assert stream.encrypted
    assert not stream.compat_ccs


def test_tls13_plaintext_hello_after_change_cipher_spec_is_parsed():
    """
    TLS 1.3 sends a dummy ChangeCipherSpec purely so middleboxes see a
    familiar packet sequence (RFC 8446 D.4), and the handshake continues in
    the clear. Reading that CCS the TLS 1.2 way loses the second ClientHello
    of every HelloRetryRequest exchange -- 108 hellos across the capture
    corpus, and the ones that matter most, because an HRR is the server
    refusing the group the client offered.
    """
    stream = HandshakeStream()
    got = stream.feed(record(CONTENT_HANDSHAKE, hello(CLIENT_HELLO, 1700))
                      + record(CONTENT_CHANGE_CIPHER_SPEC, b'\x01')
                      + record(CONTENT_HANDSHAKE, hello(CLIENT_HELLO, 520)))
    assert [len(m.body) for m in got] == [1700, 520]
    assert stream.cipher_changed and stream.compat_ccs
    assert not stream.encrypted


def test_plausible_handshake_rejects_ciphertext():
    assert not plausible_handshake(b'')
    assert not plausible_handshake(bytes([0xff, 0, 0, 1]))     # unknown type
    assert not plausible_handshake(bytes([CLIENT_HELLO, 0xff, 0xff, 0xff]))
    assert plausible_handshake(bytes([CLIENT_HELLO, 0, 2, 0]))


# --------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------
def test_a_stream_that_is_not_tls_is_marked_malformed():
    stream = HandshakeStream()
    assert stream.feed(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n') == []
    assert stream.malformed
    assert not stream.usable


def test_resynchronisation_is_not_attempted():
    """
    Once the record boundary is lost, every later offset is a guess. Guessing
    would invent handshakes that were never sent, which is worse than
    reporting nothing -- this tool's output is meant to be attestable.
    """
    stream = HandshakeStream()
    # One good record, then bytes that are not a record header. A walker that
    # scanned forward for the next plausible header would find the valid
    # record in the second feed and report it as though the stream were
    # intact.
    got = stream.feed(record(CONTENT_HANDSHAKE, hello(size=40))
                      + b'\xff' * 8)
    assert [m.msg_type for m in got] == [CLIENT_HELLO]
    assert stream.malformed
    assert stream.feed(record(CONTENT_HANDSHAKE, hello(size=40))) == []


def test_an_absurd_message_length_is_refused():
    """
    The handshake length field is three bytes, so it can claim 16MB. Waiting
    for that to arrive is a denial of service by arithmetic.
    """
    claim = bytes([CLIENT_HELLO, 0xFF, 0xFF, 0xFF])
    stream = HandshakeStream()
    assert stream.feed(record(CONTENT_HANDSHAKE, claim + b'\x00' * 10)) == []
    assert stream.malformed
    assert MAX_MESSAGE_LEN < (1 << 24)


def test_an_absurd_record_length_is_refused():
    blob = bytes([CONTENT_HANDSHAKE, 3, 3, 0xFF, 0xFF]) + b'\x00' * 8
    stream = HandshakeStream()
    assert stream.feed(blob) == []
    assert stream.malformed


def test_alerts_are_kept():
    stream = HandshakeStream()
    stream.feed(record(CONTENT_HANDSHAKE, hello(size=40))
                + record(CONTENT_ALERT, bytes([2, 40])))
    assert [(a.level, a.description) for a in stream.alerts] == [(2, 40)]


def test_pending_bytes_are_visible():
    """A half-arrived record is held, and saying how much is held is honest."""
    stream = HandshakeStream()
    stream.feed(record(CONTENT_HANDSHAKE, hello(size=500))[:100])
    assert stream.pending_bytes == 100


# --------------------------------------------------------------------------
# the cheap "is this even TLS" test
# --------------------------------------------------------------------------
@pytest.mark.parametrize("data,expected", [
    (b'', True),                                  # nothing yet: keep it
    (bytes([CONTENT_HANDSHAKE, 3, 1]), True),
    (bytes([CONTENT_HANDSHAKE, 3, 4]), True),
    (bytes([CONTENT_APPLICATION_DATA, 3, 3]), True),
    (b'GET', False),
    (b'SSH', False),
    (bytes([CONTENT_HANDSHAKE, 2, 0]), False),    # SSLv2-ish, not handled
])
def test_looks_like_tls(data, expected):
    assert looks_like_tls(data) is expected
