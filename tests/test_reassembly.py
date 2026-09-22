"""
TCP reassembly: ordering, bounds, and what it recovers.

The unit tests drive `Stream` directly with chosen sequence numbers, because
the interesting cases -- a hole that is filled later, a retransmission that
overlaps, a sequence number that wraps at 2**32 -- do not appear reliably in
any capture small enough to commit.

The recall tests run whole conversations from `tests/fixtures/streams/`
through the real pipeline and compare against the single-frame path. Those
fixtures exist because `tests/fixtures/*.pcap` cannot demonstrate reassembly:
they were built with `tcp.desegment_tcp_streams:FALSE`, so every frame in
them is self-contained by construction and the reassembler finds exactly what
the single-frame parser already found.
"""
import pathlib

import pytest

from cryptomon.parsers.framing import decode_frame
from cryptomon.parsers.tls import parse_hello_message, parse_tls
from pcapscan.reader import Reader
from pcapscan.reassembly import (DEFAULT_MAX_STREAM_BYTES, FlowKey,
                                 Reassembler, Stream, flow_key, seq_diff)
from pcapscan.records import HandshakeStream, looks_like_tls

pytestmark = pytest.mark.smoke

STREAMS = pathlib.Path(__file__).resolve().parent / "fixtures" / "streams"

PSH_ACK = 0x18
SYN = 0x02
FIN = 0x01
RST = 0x04

KEY = FlowKey('10.0.0.1', 1234, '10.0.0.2', 443)


def stream(max_bytes=DEFAULT_MAX_STREAM_BYTES, max_pending=32):
    return Stream(KEY, max_bytes, max_pending)


# --------------------------------------------------------------------------
# ordering
# --------------------------------------------------------------------------
def test_in_order_segments_concatenate():
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    assert s.add(1001, b'abc', PSH_ACK, 0.1) == b'abc'
    assert s.add(1004, b'def', PSH_ACK, 0.2) == b'def'
    assert bytes(s.data) == b'abcdef'


def test_the_syn_consumes_one_sequence_number():
    """
    Data starts at ISN+1. Off by one here shifts the whole stream, which
    turns the first byte of a TLS record header into the last byte of
    nothing and makes every subsequent length wrong.
    """
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    assert s.base_seq == 1001
    assert s.add(1001, b'hello', PSH_ACK, 0.1) == b'hello'


def test_out_of_order_waits_then_drains():
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    s.add(1001, b'aaa', PSH_ACK, 0.1)
    assert s.add(1007, b'ccc', PSH_ACK, 0.2) == b''      # hole at 1004
    assert len(s.pending) == 1
    assert s.add(1004, b'bbb', PSH_ACK, 0.3) == b'bbbccc'
    assert bytes(s.data) == b'aaabbbccc'
    assert s.pending == {}


def test_several_held_segments_drain_in_order():
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    s.add(1001, b'11', PSH_ACK, 0.1)
    for seq, payload in [(1007, b'44'), (1003, b'22'), (1009, b'55')]:
        s.add(seq, payload, PSH_ACK, 0.2)
    assert s.add(1005, b'33', PSH_ACK, 0.3) == b'334455'
    assert bytes(s.data) == b'1122334455'


def test_a_pure_retransmission_is_dropped_not_duplicated():
    """
    The live path counts frames, so a retransmitted ClientHello becomes two
    database records describing one handshake. Here the bytes are already
    held, so the copy adds nothing.
    """
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    s.add(1001, b'hello', PSH_ACK, 0.1)
    assert s.add(1001, b'hello', PSH_ACK, 0.2) == b''
    assert bytes(s.data) == b'hello'
    assert s.retransmits == 1


def test_a_partial_overlap_keeps_only_the_new_tail():
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    s.add(1001, b'abcdef', PSH_ACK, 0.1)
    assert s.add(1004, b'defghi', PSH_ACK, 0.2) == b'ghi'
    assert bytes(s.data) == b'abcdefghi'
    assert s.overlaps == 1


def test_a_capture_starting_mid_stream_still_works():
    """
    No SYN: a capture begun after the connection opened, which is most
    captures taken on a running system. The first byte seen becomes the
    base, and `missing_start` says the beginning is not there.
    """
    s = stream()
    assert s.add(50000, b'payload', PSH_ACK, 0.1) == b'payload'
    assert s.missing_start
    assert bytes(s.data) == b'payload'


def test_sequence_numbers_wrap_at_two_to_the_thirty_two():
    """
    Raw `<` comparison is wrong once per 4GB per flow. A long capture from a
    busy link does reach that, and the failure is silent: the segment after
    the wrap looks like an ancient retransmission and is dropped.
    """
    s = stream()
    s.add(0xFFFFFFFE, b'', SYN, 0.0)
    assert s.add(0xFFFFFFFF, b'be', PSH_ACK, 0.1) == b'be'
    assert s.add(0x00000001, b'fore', PSH_ACK, 0.2) == b'fore'
    assert bytes(s.data) == b'before'


@pytest.mark.parametrize("a,b,expected", [
    (5, 3, 2),
    (3, 5, -2),
    (1, 0xFFFFFFFF, 2),
    (0xFFFFFFFF, 1, -2),
])
def test_seq_diff_is_signed_and_wraps(a, b, expected):
    assert seq_diff(a, b) == expected


# --------------------------------------------------------------------------
# bounds
# --------------------------------------------------------------------------
def test_a_direction_stops_at_its_cap():
    """
    Everything this tool wants is in the first few kilobytes. Past the cap a
    stream is bulk transfer, and buffering it buys nothing but memory.
    """
    s = stream(max_bytes=100)
    s.add(1000, b'', SYN, 0.0)
    assert len(s.add(1001, b'x' * 250, PSH_ACK, 0.1)) == 100
    assert s.full
    assert len(s.data) == 100
    assert s.add(1251, b'more', PSH_ACK, 0.2) == b''


def test_held_segments_are_capped():
    s = stream(max_pending=4)
    s.add(1000, b'', SYN, 0.0)
    s.add(1001, b'a', PSH_ACK, 0.1)
    for i in range(10):
        s.add(1100 + i * 10, b'zzz', PSH_ACK, 0.2)
    assert len(s.pending) == 4
    assert s.dropped_pending == 6


def test_a_held_segment_is_not_stored_twice():
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    s.add(1001, b'a', PSH_ACK, 0.1)
    s.add(1100, b'zzz', PSH_ACK, 0.2)
    s.add(1100, b'zzz', PSH_ACK, 0.3)
    assert len(s.pending) == 1


def test_the_flow_table_evicts_the_least_recently_used():
    r = Reassembler(max_flows=2)
    for port in (1, 2, 3):
        key = FlowKey('10.0.0.1', port, '10.0.0.2', 443)
        s = r._new_stream(key)
        s.add(1000, b'data', PSH_ACK, float(port))
    assert len(r) == 2
    assert r.stats['evicted'] == 1


def test_abandon_frees_the_bytes_and_says_so():
    r = Reassembler()
    key = FlowKey('10.0.0.1', 1, '10.0.0.2', 443)
    s = r._new_stream(key)
    s.add(1000, b'x' * 500, PSH_ACK, 0.0)
    assert len(s.data) == 500
    r.abandon(key)
    assert len(s.data) == 0
    assert s.abandoned
    assert r.stats['abandoned'] == 1
    assert r.summary()['held_bytes'] == 0


def test_flags_are_recorded():
    s = stream()
    s.add(1000, b'', SYN, 0.0)
    s.add(1001, b'x', FIN, 0.1)
    assert s.syn_seen and s.fin_seen and not s.rst_seen
    s.add(1002, b'', RST, 0.2)
    assert s.rst_seen


def test_flow_key_reverses():
    assert KEY.reverse() == FlowKey('10.0.0.2', 443, '10.0.0.1', 1234)
    assert KEY.reverse().reverse() == KEY


def test_flow_key_reads_either_address_family():
    v6 = flow_key({'src': {'ipv6': '::1', 'port': 5},
                   'dst': {'ipv6': '::2', 'port': 443}})
    assert v6 == FlowKey('::1', 5, '::2', 443)


# --------------------------------------------------------------------------
# what it recovers, on real conversations
# --------------------------------------------------------------------------
def walk(path):
    """Run one capture through reader -> reassembly -> records -> parser."""
    reassembler = Reassembler()
    single, messages = [], []
    for packet in Reader(path):
        frame = decode_frame(packet.data, packet.linktype)
        if frame is None:
            continue
        payload = packet.data[frame.payload_offset:frame.payload_end]
        # The eBPF filter's own gate, mirrored: it forwards a frame only when
        # the payload starts with a handshake record.
        if (len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 3
                and payload[2] in (1, 2, 3, 4)):
            parsed = parse_tls(packet.data)
            if parsed.get('ptype'):
                single.append((parsed['ptype'], parsed.get('tls', {})))
        update = reassembler.push(packet.timestamp, packet.data, frame)
        if update is None:
            continue
        held = update.stream
        if 'hs' not in held.state:
            if not held.data:
                continue
            if not looks_like_tls(bytes(held.data[:3])):
                reassembler.abandon(update.key)
                continue
            held.state['hs'] = HandshakeStream()
        walker = held.state['hs']
        for message in walker.feed(update.new_bytes):
            messages.append(message)
        if not walker.usable and not held.abandoned:
            reassembler.abandon(update.key)
    return single, messages, reassembler


def names(messages):
    return [m.name for m in messages]


@pytest.mark.parametrize("name", ["tls12_certificate",
                                  "tls12_split_certificate"])
def test_a_certificate_chain_is_recovered_whole(name):
    """
    The live path has never seen a whole certificate. A chain is several
    kilobytes, a segment is about 1.4KB, so `cert_guess` was always looking
    at a fragment -- which is why it guesses.
    """
    single, messages, _ = walk(STREAMS / f"{name}.pcap")
    assert 'certificate' in names(messages)
    certificate = next(m for m in messages if m.name == 'certificate')
    assert len(certificate.body) > 2000
    # The whole chain: a 3-byte list length, then each cert with its own.
    declared = int.from_bytes(certificate.body[:3], 'big')
    assert declared == len(certificate.body) - 3
    assert not any(tls.get('certificate') for _ptype, tls in single)


@pytest.mark.parametrize("name", ["tls12_certificate",
                                  "tls12_split_certificate"])
def test_the_single_frame_path_reports_a_truncated_hello(name):
    """
    Not "misses the hello" -- reports one, incompletely, without saying so.
    The ClientHello in these captures is about 1.9KB and the first segment
    carries 1238 bytes of it, so the live path parses a fragment and records
    whichever extensions happened to fit.
    """
    single, messages, _ = walk(STREAMS / f"{name}.pcap")
    live = [tls for ptype, tls in single if ptype == 'client']
    assert live, "the live path did report a client hello"

    whole = next(m for m in messages if m.name == 'client_hello')
    assert len(whole.body) > 1800
    reassembled = parse_hello_message(whole.msg_type, whole.body)['tls']
    hostname = reassembled['hostname']
    assert hostname == 'badssl.com' or hostname.endswith('.badssl.com')
    # The fragment cannot carry as many ciphersuites and groups as the whole
    # message, and it is the extensions at the end that get lost.
    assert len(reassembled.get('groups', [])) >= len(live[0].get('groups', []))


def test_hello_retry_request_keeps_both_exchanges():
    """
    The capture that makes the case for this whole change.

    The client offers X25519Kyber768Draft00 -- a post-quantum hybrid. The
    server refuses it with a HelloRetryRequest naming secp256r1, and the
    client comes back with secp256r1. A tool that sees only the first hello
    reports "post-quantum key exchange offered" and never records that it was
    turned down, which is the opposite of what happened.
    """
    _single, messages, _ = walk(STREAMS / "tls13_hello_retry.pcap")
    assert names(messages) == ['client_hello', 'server_hello',
                               'client_hello', 'server_hello']
    groups = [parse_hello_message(m.msg_type, m.body)['tls'].get('kex_group')
              for m in messages]
    assert groups == ['X25519Kyber768Draft00', 'secp256r1',
                      'secp256r1', 'secp256r1']


def test_reassembly_stays_within_its_memory_ceiling():
    for path in sorted(STREAMS.glob("*.pcap")):
        _single, _messages, reassembler = walk(path)
        summary = reassembler.summary()
        ceiling = reassembler.max_flows * 2 * reassembler.max_stream_bytes
        assert summary['held_bytes'] <= ceiling
        assert summary['open_streams'] <= reassembler.max_flows


def test_the_stream_fixtures_are_whole_conversations():
    """
    Guards the fixtures themselves. If someone regenerates them with the
    single-frame filter, every recall test above starts passing vacuously.
    """
    for path in sorted(STREAMS.glob("*.pcap")):
        with Reader(path) as reader:
            flags = [decode_frame(p.data, p.linktype) for p in reader]
        assert any(f is not None and f.flags & SYN for f in flags), (
            f"{path.name} has no SYN, so it is not a whole conversation")
        assert any(f is not None and f.payload_end == f.payload_offset
                   for f in flags), (
            f"{path.name} has no pure-ACK frames, so it has been filtered")
