"""
The streaming capture reader.

Two kinds of check here, and the distinction matters.

*Against an oracle:* every committed fixture is read twice, once by
`pcapscan.reader` and once by scapy, and the frames must come out byte for
byte identical with matching timestamps. scapy is an independent
implementation by people who are not us, which is the only reason its
agreement is worth anything.

*Against constructed files:* the corpus is pcapng little-endian plus classic
pcap little-endian, and that is all it is. A big-endian capture, nanosecond
timestamps, several interfaces with different link types, a second section, a
truncated tail -- none of those can be tested against files we happen to have,
so they are built here, byte by byte, from the format specification.
"""
import gzip
import io
import struct

import pytest

from cryptomon.parsers.framing import (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL,
                                       LINKTYPE_LINUX_SLL2, LINKTYPE_LOOP,
                                       LINKTYPE_NULL, LINKTYPE_RAW,
                                       decode_frame)
from pcapscan.reader import CaptureError, Packet, Reader, read_packets

from conftest import FIXTURES, read_frames

# Everything in this file is constructed or reads a committed fixture; none
# of it needs tshark, so it belongs in the merge gate.
pytestmark = pytest.mark.smoke

FRAME_A = bytes.fromhex('020000000002020000000001080045000028') + b'\x00' * 22
FRAME_B = bytes.fromhex('020000000001020000000002080045000030') + b'\x01' * 30


# --------------------------------------------------------------------------
# builders -- classic pcap
# --------------------------------------------------------------------------
def build_pcap(frames, endian='<', nsec=False, linktype=LINKTYPE_ETHERNET,
               snaplen=262144):
    magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
    out = struct.pack(endian + 'IHHiIII', magic, 2, 4, 0, 0, snaplen, linktype)
    scale = 1000000000 if nsec else 1000000
    for i, frame in enumerate(frames):
        out += struct.pack(endian + 'IIII', 1733875200 + i, scale // 2,
                           len(frame), len(frame))
        out += frame
    return out


# --------------------------------------------------------------------------
# builders -- pcapng
# --------------------------------------------------------------------------
def _block(endian, block_type, body):
    total = len(body) + 12
    return (struct.pack(endian + 'II', block_type, total) + body
            + struct.pack(endian + 'I', total))


def _shb(endian):
    body = struct.pack(endian + 'IHHq', 0x1A2B3C4D, 1, 0, -1)
    return _block(endian, 0x0A0D0D0A, body)


def _idb(endian, linktype, tsresol=6):
    body = struct.pack(endian + 'HHI', linktype, 0, 262144)
    body += struct.pack(endian + 'HH', 9, 1) + bytes([tsresol]) + b'\x00' * 3
    body += struct.pack(endian + 'HH', 0, 0)
    return _block(endian, 0x00000001, body)


def _epb(endian, interface_id, ticks, frame):
    pad = (-len(frame)) % 4
    body = struct.pack(endian + 'IIIII', interface_id, ticks >> 32,
                       ticks & 0xFFFFFFFF, len(frame), len(frame))
    return _block(endian, 0x00000006, body + frame + b'\x00' * pad)


def build_pcapng(sections, endian='<'):
    """`sections` is a list of (linktypes, [(interface_id, ticks, frame)])."""
    out = b''
    for linktypes, packets in sections:
        out += _shb(endian)
        for linktype in linktypes:
            out += _idb(endian, linktype)
        for interface_id, ticks, frame in packets:
            out += _epb(endian, interface_id, ticks, frame)
    return out


def write(tmp_path, name, blob):
    path = tmp_path / name
    path.write_bytes(blob)
    return path


# --------------------------------------------------------------------------
# the oracle: scapy reads the committed corpus the same way we do
# --------------------------------------------------------------------------
def fixture_paths():
    return sorted(FIXTURES.glob("*.pcap")) + sorted(
        (FIXTURES / "synthetic").glob("*.pcap"))


@pytest.mark.parametrize("path", fixture_paths(), ids=lambda p: p.name)
def test_matches_scapy_frame_for_frame(path):
    scapy_all = pytest.importorskip("scapy.all")
    with Reader(path) as reader:
        mine = list(reader)
    with scapy_all.PcapReader(str(path)) as oracle:
        theirs = [(bytes(pkt), float(pkt.time)) for pkt in oracle]

    assert len(mine) == len(theirs), "frame count differs from scapy"
    for ours, (raw, when) in zip(mine, theirs):
        assert ours.data == raw
        assert abs(ours.timestamp - when) < 1e-6


def test_frames_are_numbered_from_one_like_tshark():
    name = sorted(p.stem for p in FIXTURES.glob("*.pcap"))[0]
    with Reader(FIXTURES / f"{name}.pcap") as reader:
        indexes = [p.index for p in reader]
    assert indexes == list(range(1, len(indexes) + 1))
    # read_frames() keys its dict the same way; the reader has to agree with
    # it or every oracle comparison in the suite is off by one.
    assert max(read_frames(name, ebpf_gate=False)) == indexes[-1]


# --------------------------------------------------------------------------
# containers
# --------------------------------------------------------------------------
@pytest.mark.parametrize("endian", ['<', '>'])
@pytest.mark.parametrize("nsec", [False, True])
def test_both_byte_orders_and_both_resolutions(tmp_path, endian, nsec):
    """
    A capture from a big-endian host, or one with nanosecond timestamps, is
    the same capture. Reading the magic as decoration rather than as an
    instruction gives garbage lengths in one case and timestamps a thousand
    years out in the other.
    """
    blob = build_pcap([FRAME_A, FRAME_B], endian=endian, nsec=nsec)
    with Reader(write(tmp_path, "c.pcap", blob)) as reader:
        packets = list(reader)
    assert [p.data for p in packets] == [FRAME_A, FRAME_B]
    assert packets[0].timestamp == pytest.approx(1733875200.5)
    assert packets[1].timestamp == pytest.approx(1733875201.5)


def test_gzip_is_detected_by_magic_not_by_extension(tmp_path):
    blob = build_pcap([FRAME_A])
    path = write(tmp_path, "not-obviously-compressed.pcap",
                 gzip.compress(blob))
    with Reader(path) as reader:
        assert [p.data for p in reader] == [FRAME_A]


def test_pcapng_round_trips(tmp_path):
    blob = build_pcapng([([LINKTYPE_ETHERNET],
                          [(0, 1733875200000000, FRAME_A),
                           (0, 1733875201000000, FRAME_B)])])
    with Reader(write(tmp_path, "c.pcapng", blob)) as reader:
        packets = list(reader)
    assert [p.data for p in packets] == [FRAME_A, FRAME_B]
    assert packets[0].timestamp == pytest.approx(1733875200.0)


def test_each_interface_keeps_its_own_link_type(tmp_path):
    """
    The bug this exists to prevent: reading only the first IDB and applying
    its link type to the whole file. `tcpdump -i any` plus a physical
    interface in one pcapng gives SLL2 and Ethernet side by side, and
    decoding the SLL2 frames at Ethernet offsets shifts every subsequent
    field by six bytes -- without failing.
    """
    sll2 = struct.pack('>HHIHBB', 0x0800, 0, 1, 1, 0, 6) + b'\x00' * 8
    sll2_frame = sll2 + FRAME_A[14:]
    blob = build_pcapng([([LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL2],
                          [(0, 0, FRAME_A), (1, 0, sll2_frame)])])
    with Reader(write(tmp_path, "mixed.pcapng", blob)) as reader:
        packets = list(reader)
    assert [p.linktype for p in packets] == [LINKTYPE_ETHERNET,
                                             LINKTYPE_LINUX_SLL2]


def test_a_new_section_resets_the_interface_table(tmp_path):
    blob = build_pcapng([
        ([LINKTYPE_ETHERNET], [(0, 0, FRAME_A)]),
        ([LINKTYPE_LINUX_SLL], [(0, 0, FRAME_B)]),
    ])
    with Reader(write(tmp_path, "two.pcapng", blob)) as reader:
        packets = list(reader)
        sections = reader.stats['sections']
    assert sections == 2
    assert [p.linktype for p in packets] == [LINKTYPE_ETHERNET,
                                             LINKTYPE_LINUX_SLL]


def test_pcapng_timestamp_resolution_is_per_interface(tmp_path):
    endian = '<'
    blob = _shb(endian) + _idb(endian, LINKTYPE_ETHERNET, tsresol=9)
    blob += _epb(endian, 0, 1733875200500000000, FRAME_A)
    with Reader(write(tmp_path, "nano.pcapng", blob)) as reader:
        packet = next(iter(reader))
    assert packet.timestamp == pytest.approx(1733875200.5)


# --------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------
def test_truncated_tail_stops_cleanly_and_is_counted(tmp_path):
    """
    An interrupted tcpdump leaves a file cut mid-record. That is an ordinary
    file, so the frames before the cut are still worth having -- but a run
    that silently lost the tail must not look like a complete one.
    """
    blob = build_pcap([FRAME_A, FRAME_B])
    with Reader(write(tmp_path, "cut.pcap", blob[:-10])) as reader:
        packets = list(reader)
        stats = dict(reader.stats)
    assert [p.data for p in packets] == [FRAME_A]
    assert stats['truncated_tail'] == 1


def test_absurd_caplen_is_refused_without_allocating(tmp_path):
    header = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    blob = header + struct.pack('<IIII', 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    with Reader(write(tmp_path, "huge.pcap", blob)) as reader:
        assert list(reader) == []
        assert reader.stats['oversize_refused'] == 1


def test_a_file_that_is_not_a_capture_raises(tmp_path):
    with pytest.raises(CaptureError):
        Reader(write(tmp_path, "readme.txt", b"this is not a capture at all"))


def test_an_empty_file_raises(tmp_path):
    with pytest.raises(CaptureError):
        Reader(write(tmp_path, "empty.pcap", b""))


def test_unknown_pcapng_blocks_are_skipped_and_counted(tmp_path):
    endian = '<'
    blob = _shb(endian) + _idb(endian, LINKTYPE_ETHERNET)
    blob += _block(endian, 0x00000005, b'\x00' * 8)     # interface statistics
    blob += _epb(endian, 0, 0, FRAME_A)
    with Reader(write(tmp_path, "stats.pcapng", blob)) as reader:
        packets = list(reader)
        skipped = reader.stats['unknown_blocks']
    assert [p.data for p in packets] == [FRAME_A]
    assert skipped == 1


# --------------------------------------------------------------------------
# streaming, and the file handle
# --------------------------------------------------------------------------
def test_reading_does_not_materialise_the_file(tmp_path):
    """
    The whole reason this is not `rdpcap`. Iteration must yield the first
    frame before the last one has been read, which a list-building reader
    cannot do.
    """
    blob = build_pcap([FRAME_A] * 500)
    with Reader(write(tmp_path, "many.pcap", blob)) as reader:
        iterator = iter(reader)
        next(iterator)
        assert reader.stats['packets'] == 1     # not 500
        next(iterator)
        assert reader.stats['packets'] == 2


def test_read_packets_closes_the_file(tmp_path):
    path = write(tmp_path, "c.pcap", build_pcap([FRAME_A]))
    assert [p.data for p in read_packets(path)] == [FRAME_A]


def test_accepts_an_open_binary_stream(tmp_path):
    blob = build_pcap([FRAME_A])
    with Reader(io.BufferedReader(io.BytesIO(blob))) as reader:
        assert [p.data for p in reader] == [FRAME_A]


def test_packet_is_a_plain_tuple():
    """Downstream unpacks these millions of times; it stays a NamedTuple."""
    assert issubclass(Packet, tuple)


# --------------------------------------------------------------------------
# link types: the same datagram, framed six ways
# --------------------------------------------------------------------------
def _ip_tcp():
    """A minimal IPv4/TCP datagram, used to frame the same bytes six ways."""
    ip = bytes.fromhex('450000300000400040060000'
                       'c0a80001c0a80002')
    tcp = struct.pack('>HHIIBBHHH', 1234, 443, 0, 0, 5 << 4, 0x18, 8192, 0, 0)
    return ip + tcp + b'payload!'


@pytest.mark.parametrize("linktype,prefix", [
    (LINKTYPE_ETHERNET, bytes(12) + b'\x08\x00'),
    (LINKTYPE_RAW, b''),
    (LINKTYPE_NULL, struct.pack('<I', 2)),
    (LINKTYPE_LOOP, struct.pack('>I', 2)),
    (LINKTYPE_LINUX_SLL, struct.pack('>HHH', 0, 1, 6) + bytes(8) + b'\x08\x00'),
    (LINKTYPE_LINUX_SLL2,
     b'\x08\x00' + bytes(2) + struct.pack('>IHBB', 1, 1, 0, 6) + bytes(8)),
])
def test_every_link_type_reaches_the_same_endpoints(linktype, prefix):
    frame = prefix + _ip_tcp()
    decoded = decode_frame(frame, linktype)
    assert decoded is not None, f"linktype {linktype} did not decode"
    assert decoded.endpoints['src'] == {'ipv4': '192.168.0.1', 'port': 1234}
    assert decoded.endpoints['dst'] == {'ipv4': '192.168.0.2', 'port': 443}
    assert frame[decoded.payload_offset:] == b'payload!'


def test_an_unknown_link_type_is_refused_not_guessed():
    """
    LINKTYPE_IEEE802_11 (105) is a link layer this parser cannot walk.
    Falling back to Ethernet offsets would parse it anyway and report
    whatever landed at +14, which is the failure this whole module exists to
    prevent.
    """
    assert decode_frame(bytes(64), 105) is None
