"""
Tunnel unwrapping: GRE, ERSPAN Types I/II/III, VXLAN, GENEVE and IP-in-IP.

**There is no GRE in the corpus.** Zero packets of IP protocol 47 in all
160,221 frames of `CryptomonData/**`, `tests/fixtures/**` and
`sandbox/*.pcap`; no VXLAN and no GENEVE either. So unlike every other parser
in this suite, nothing here can be judged against traffic somebody recorded.
The fixtures are built to the RFCs by the `build_*` functions below and
committed under `tests/fixtures/tunnels/`, and they show that the parser
agrees with the specification -- not that it agrees with Cisco.

Two things are done about that.

The first is that the fixtures are built to the standards rather than to what
makes the parser pass: the GRE cases enumerate flag combinations the parser
has no special handling for, and ERSPAN Type I is tested by the *absence* of
a header rather than the presence of one.

The second is the test that actually matters.
`tests/fixtures/streams/tls12_certificate.pcap` is a real TLS 1.2
conversation the rest of this suite already has expectations about. Wrapping
every one of its frames in ERSPAN and asserting that the pipeline recovers
the *identical session document* turns "my unwrapper works" into "the tool
sees through the tunnel to exactly what it saw without it". That is much
harder to fake than a round trip through my own encoder, because the document
on the other side is produced by reassembly, record walking, the TLS parser
and the certificate parser, none of which this PR touched.

The builders live here rather than in `tests/tools/` because the fixtures
they produce are committed, and a generator that has drifted from the files
it generated is worse than no generator: the reproducibility test below
regenerates every committed fixture and compares bytes, so the two cannot
part company. Every input is fixed -- addresses, ports, timestamps, sequence
numbers -- because a fixture that regenerates with a fresh timestamp dirties
the tree on every run. That happened in PR-14 and was fixed once already.
"""
import collections
import pathlib
import struct

import pytest

from cryptomon.parsers.framing import (LINKTYPE_ETHERNET, LINKTYPE_IPV4,
                                       LINKTYPE_IPV6, LINKTYPE_RAW,
                                       decode_frame)
from pcapscan.reader import Reader
from pcapscan.sessions import SessionBuilder
from pcapscan.tunnels import MAX_TUNNEL_DEPTH, decode_packet, unwrap

from fuzzing import mutate, seeded

HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
TUNNELS = FIXTURES / "tunnels"
STREAM = FIXTURES / "streams" / "tls12_certificate.pcap"

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
IP_PROTO_TCP = 6
IP_PROTO_IPIP = 4
IP_PROTO_UDP = 17
IP_PROTO_GRE = 47
IP_PROTO_NO_NEXT = 59
GRE_PROTO_ERSPAN_I_II = 0x88BE
GRE_PROTO_ERSPAN_III = 0x22EB
GRE_PROTO_TEB = 0x6558

# The two ends of the fictional mirror session: TEST-NET-1 (RFC 5737), so
# nothing in a committed fixture can be mistaken for a real switch or a real
# destination.
SPAN_SRC = "192.0.2.1"
SPAN_DST = "192.0.2.10"

# 2024-12-11T00:00:00Z, the date the corpus was captured. Fixed so that a
# regenerated fixture is byte-identical to the committed one.
FIXED_TS = 1733875200


# ---------------------------------------------------------------------------
# encoders -- everything the fixtures are built out of
# ---------------------------------------------------------------------------
def ether(payload, ethertype, dst=b"\x02\x00\x00\x00\x00\x02",
          src=b"\x02\x00\x00\x00\x00\x01"):
    return dst + src + struct.pack(">H", ethertype) + payload


def _checksum(header):
    """The one's-complement sum an IPv4 header carries."""
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(">{0}H".format(len(header) // 2), header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(payload, protocol, src=SPAN_SRC, dst=SPAN_DST, ident=0, options=b""):
    """An IPv4 header with a real IHL, total length and checksum."""
    assert len(options) % 4 == 0
    ihl = 5 + len(options) // 4
    head = struct.pack(">BBHHHBBH", 0x40 | ihl,
                       0, 20 + len(options) + len(payload), ident, 0, 64,
                       protocol, 0)
    head += bytes(int(part) for part in src.split("."))
    head += bytes(int(part) for part in dst.split("."))
    head += options
    head = head[:10] + struct.pack(">H", _checksum(head)) + head[12:]
    return head + payload


def ipv6(payload, next_header,
         src=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01",
         dst=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02"):
    return (struct.pack(">IHBB", 0x60000000, len(payload), next_header, 64)
            + src + dst + payload)


def udp(payload, sport, dport):
    # Checksum zero, which IPv4 permits and means "not computed".
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def gre(payload, protocol, checksum=False, key=None, sequence=None,
        routing=False, version=0):
    """
    A GRE header, RFC 2784 with the RFC 2890 optional fields.

    Those optional fields are what makes the header variable-length. The
    order is fixed by the RFC regardless of which are present: checksum and
    reserved1 together, then key, then sequence.
    """
    flags = version & 0x0007
    if checksum:
        flags |= 0x8000
    if routing:
        flags |= 0x4000
    if key is not None:
        flags |= 0x2000
    if sequence is not None:
        flags |= 0x1000
    out = struct.pack(">HH", flags, protocol)
    if checksum or routing:
        out += struct.pack(">HH", 0, 0)
    if key is not None:
        out += struct.pack(">I", key)
    if sequence is not None:
        out += struct.pack(">I", sequence)
    return out + payload


def erspan2_header(session_id=7, vlan_id=0, cos=0, encap=0, truncated=False,
                   index=0, version=1):
    """
    Ver(4) VLAN(12) COS(3) En(2) T(1) SessionID(10)
    | Reserved(12) Index(20)
    """
    word0 = ((version & 0xF) << 28 | (vlan_id & 0xFFF) << 16
             | (cos & 0x7) << 13 | (encap & 0x3) << 11
             | (1 if truncated else 0) << 10 | (session_id & 0x3FF))
    return struct.pack(">II", word0, index & 0xFFFFF)


def erspan3_header(session_id=7, vlan_id=0, cos=0, bso=0, truncated=False,
                   timestamp=0x11223344, sgt=0x0102, frame_type=0,
                   hardware_id=3, granularity=1, subheader=False, version=2):
    """
    Ver(4) VLAN(12) COS(3) BSO(2) T(1) SessionID(10) | Timestamp(32)
    | SGT(16) P(1) FT(5) HwID(6) D(1) Gra(2) O(1) [| sub-header(64)]
    """
    word0 = ((version & 0xF) << 28 | (vlan_id & 0xFFF) << 16
             | (cos & 0x7) << 13 | (bso & 0x3) << 11
             | (1 if truncated else 0) << 10 | (session_id & 0x3FF))
    word2 = ((sgt & 0xFFFF) << 16 | (frame_type & 0x1F) << 10
             | (hardware_id & 0x3F) << 4
             | (granularity & 0x3) << 1 | (1 if subheader else 0))
    out = struct.pack(">III", word0, timestamp, word2)
    if subheader:
        out += b"\xde\xad\xbe\xef\x00\x00\x00\x00"
    return out


def vxlan_header(vni=0x0000AB, valid=True):
    return (struct.pack(">BBBB", 0x08 if valid else 0x00, 0, 0, 0)
            + struct.pack(">I", (vni & 0xFFFFFF) << 8))


def geneve_header(protocol=GRE_PROTO_TEB, vni=0x0000CD, options=b"",
                  version=0):
    assert len(options) % 4 == 0
    first = (version & 0x3) << 6 | (len(options) // 4) & 0x3F
    return (struct.pack(">BBH", first, 0, protocol)
            + struct.pack(">I", (vni & 0xFFFFFF) << 8) + options)


# ---------------------------------------------------------------------------
# whole encapsulated packets
# ---------------------------------------------------------------------------
def wrap_erspan1(frame):
    """Type I: GRE 0x88BE with the sequence flag clear, and no header."""
    return ether(ipv4(gre(frame, GRE_PROTO_ERSPAN_I_II), IP_PROTO_GRE),
                 ETHERTYPE_IPV4)


def wrap_erspan2(frame, sequence=1, **fields):
    return ether(ipv4(gre(erspan2_header(**fields) + frame,
                          GRE_PROTO_ERSPAN_I_II, sequence=sequence),
                      IP_PROTO_GRE), ETHERTYPE_IPV4)


def wrap_erspan3(frame, sequence=1, **fields):
    return ether(ipv4(gre(erspan3_header(**fields) + frame,
                          GRE_PROTO_ERSPAN_III, sequence=sequence),
                      IP_PROTO_GRE), ETHERTYPE_IPV4)


def wrap_gre_teb(frame, **kwargs):
    return ether(ipv4(gre(frame, GRE_PROTO_TEB, **kwargs), IP_PROTO_GRE),
                 ETHERTYPE_IPV4)


def wrap_vxlan(frame, dport=4789, **fields):
    return ether(ipv4(udp(vxlan_header(**fields) + frame, 45678, dport),
                      IP_PROTO_UDP), ETHERTYPE_IPV4)


def wrap_geneve(frame, dport=6081, **fields):
    return ether(ipv4(udp(geneve_header(**fields) + frame, 45678, dport),
                      IP_PROTO_UDP), ETHERTYPE_IPV4)


def wrap_ipip(frame):
    """No shim at all: the outer IP header's payload is the inner one."""
    return ether(ipv4(frame[14:], IP_PROTO_IPIP), ETHERTYPE_IPV4)


def inner_frame(payload=b"\x16\x03\x01\x00\x10" + b"\x01" * 16,
                sport=54321, dport=443, seq=1):
    """A plain Ethernet/IPv4/TCP frame -- what a mirror session carries."""
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x18,
                      8192, 0, 0)
    return ether(ipv4(tcp + payload, IP_PROTO_TCP, src="10.0.0.1",
                      dst="10.0.0.2"), ETHERTYPE_IPV4)


# ---------------------------------------------------------------------------
# capture files
# ---------------------------------------------------------------------------
def write_pcap(records, linktype=LINKTYPE_ETHERNET, snaplen=262144):
    """
    A little-endian microsecond pcap, as bytes. `records` is (sec, usec, data).

    Hand-rolled rather than written through scapy so that the committed
    fixtures depend on nothing but the standard library and cannot shift when
    a library is upgraded underneath them.
    """
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)]
    for sec, usec, data in records:
        out.append(struct.pack("<IIII", sec, usec, len(data), len(data)))
        out.append(bytes(data))
    return b"".join(out)


def read_frames(path):
    """(sec, usec, frame) for every packet, timestamps back as integers."""
    out = []
    with Reader(path) as reader:
        for packet in reader:
            sec = int(packet.timestamp)
            usec = int(round((packet.timestamp - sec) * 1e6))
            if usec == 1000000:        # a float that rounded up past a second
                sec, usec = sec + 1, 0
            out.append((sec, usec, packet.data))
    return out


def build_erspan2_tls12():
    """Every frame of a real TLS 1.2 conversation, mirrored over ERSPAN II."""
    return write_pcap(
        [(sec, usec, wrap_erspan2(frame, sequence=n, session_id=7,
                                  vlan_id=100, index=n))
         for n, (sec, usec, frame) in enumerate(read_frames(STREAM), start=1)])


def build_tunnel_types():
    """One packet per encapsulation, all carrying the identical inner frame."""
    frame = inner_frame()
    cases = [
        wrap_erspan1(frame),
        wrap_erspan2(frame, vlan_id=100, cos=3, session_id=42, index=9),
        wrap_erspan3(frame, vlan_id=100, session_id=42),
        wrap_erspan3(frame, vlan_id=100, session_id=42, subheader=True),
        wrap_erspan3(frame[14:], session_id=42, frame_type=2),
        wrap_erspan2(frame, truncated=True, session_id=42),
        wrap_gre_teb(frame),
        wrap_gre_teb(frame, checksum=True, key=0x0A0B0C0D, sequence=5),
        wrap_vxlan(frame),
        wrap_geneve(frame),
        wrap_geneve(frame, options=b"\x00\x01\x00\x00"),
        wrap_ipip(frame),
    ]
    return write_pcap([(FIXED_TS, n, case)
                       for n, case in enumerate(cases, start=1)])


BUILDERS = {
    "erspan2_tls12.pcap": build_erspan2_tls12,
    "tunnel_types.pcap": build_tunnel_types,
}

CATALOGUE = ["erspan1", "erspan2", "erspan3", "erspan3", "erspan3",
             "erspan2", "gre", "gre", "vxlan", "geneve", "geneve", "ipip"]


# ---------------------------------------------------------------------------
# the hook, exactly as proposed for pcapscan/sessions.py and pcapscan/cli.py
# ---------------------------------------------------------------------------
def sessions_of(path):
    """
    Every session document in a capture, with tunnels unwrapped.

    A copy of the change PR-42 asks for in `iter_sessions` and in
    `cli._records`, written out here because those two files are shared and
    this agent does not own them. If it drifts from what lands there, this
    test stops describing the pipeline -- so it is deliberately the whole
    hook and not a paraphrase of it.
    """
    builder = SessionBuilder()
    with Reader(path) as reader:
        for packet in reader:
            decoded = decode_packet(packet.data, packet.linktype,
                                    builder.stats)
            if decoded is None:
                builder.stats['frames_undecodable'] += 1
                continue
            if decoded.frame is None:
                builder.push_datagram(packet.timestamp, decoded.raw,
                                      decoded.datagram)
                continue
            builder.stats['frames'] += 1
            builder.push(packet.timestamp, decoded.raw, decoded.frame)
    return list(builder.finish()), builder.stats


# ---------------------------------------------------------------------------
# GRE: the header length is computed, not known
# ---------------------------------------------------------------------------
GRE_OPTIONS = [
    pytest.param({}, id="bare"),
    pytest.param({"checksum": True}, id="checksum"),
    pytest.param({"key": 0x11223344}, id="key"),
    pytest.param({"sequence": 7}, id="sequence"),
    pytest.param({"checksum": True, "key": 1}, id="checksum-key"),
    pytest.param({"checksum": True, "sequence": 2}, id="checksum-sequence"),
    pytest.param({"key": 3, "sequence": 4}, id="key-sequence"),
    pytest.param({"checksum": True, "key": 5, "sequence": 6}, id="all-three"),
]


@pytest.mark.smoke
@pytest.mark.parametrize("options", GRE_OPTIONS)
def test_gre_header_length_follows_the_flag_bits(options):
    """
    Every combination of the optional fields shifts the inner frame.

    This is where most implementations go wrong. The header is four bytes
    plus whichever of checksum, key and sequence the flags claim, and getting
    it wrong by four bytes does not fail -- it decodes the inner frame at the
    wrong offset and reports something plausible.
    """
    frame = inner_frame()
    result = unwrap(wrap_gre_teb(frame, **options))
    assert result is not None
    assert result.raw == frame
    assert result.linktype == LINKTYPE_ETHERNET
    assert [layer.kind for layer in result.layers] == ["gre"]


@pytest.mark.smoke
def test_gre_carrying_bare_ip_is_given_the_right_link_type():
    """
    GRE may name IPv4 or IPv6 directly, with no Ethernet header underneath.

    Handing framing LINKTYPE_IPV4 rather than synthesising an Ethernet header
    means it reads the bytes that are there instead of bytes this code made
    up -- and an invented MAC address on a session document would be a lie
    the CBOM would then attest to.
    """
    for ethertype, linktype, body in (
            (ETHERTYPE_IPV4, LINKTYPE_IPV4, inner_frame()[14:]),
            (ETHERTYPE_IPV6, LINKTYPE_IPV6, ipv6(b"", IP_PROTO_NO_NEXT))):
        result = unwrap(ether(ipv4(gre(body, ethertype), IP_PROTO_GRE),
                              ETHERTYPE_IPV4))
        assert result is not None, hex(ethertype)
        assert result.linktype == linktype
        assert result.raw == body


@pytest.mark.smoke
def test_gre_version_one_and_source_routing_are_refused():
    """
    PPTP (version 1) carries PPP, not a frame; RFC 1701 routing is withdrawn.

    Both are refused rather than guessed, because both would otherwise put
    the inner-frame offset four or more bytes out and produce a decode that
    looks fine.
    """
    frame = inner_frame()
    stats = collections.Counter()
    assert unwrap(ether(ipv4(gre(frame, 0x880B, version=1), IP_PROTO_GRE),
                        ETHERTYPE_IPV4), stats=stats) is None
    assert unwrap(ether(ipv4(gre(frame, GRE_PROTO_TEB, routing=True),
                             IP_PROTO_GRE), ETHERTYPE_IPV4),
                  stats=stats) is None
    assert stats["tunnel_refused_gre_version"] == 1
    assert stats["tunnel_refused_gre_routing"] == 1


# ---------------------------------------------------------------------------
# ERSPAN: the trap is Type I
# ---------------------------------------------------------------------------
@pytest.mark.smoke
def test_erspan_type_one_has_no_header_and_the_sequence_flag_says_so():
    """
    Type I and Type II differ only in the GRE sequence flag.

    Type I is the whole reason this file is careful. It is GRE protocol
    0x88BE with *no ERSPAN header at all*, and a parser that assumes eight
    bytes of header are always there eats the first eight bytes of the
    mirrored Ethernet frame -- the destination MAC and two bytes of the
    source -- and then decodes what is left. It does not crash. It reports a
    session between two addresses that were never on the wire.
    """
    frame = inner_frame()
    one = unwrap(wrap_erspan1(frame))
    two = unwrap(wrap_erspan2(frame))
    assert one is not None and two is not None
    assert [layer.kind for layer in one.layers] == ["erspan1"]
    assert [layer.kind for layer in two.layers] == ["erspan2"]
    # The point of the exercise: both recover the same frame, byte for byte,
    # although one of them carries eight bytes the other does not.
    assert one.raw == frame
    assert two.raw == frame
    assert decode_frame(one.raw).endpoints == decode_frame(frame).endpoints


@pytest.mark.smoke
def test_reading_a_type_one_frame_as_type_two_really_would_be_wrong():
    """
    What the bug looks like, so the test above is not a tautology.

    Consuming eight bytes that are not a header does not fail -- it yields a
    different frame. This asserts the two readings genuinely diverge, which is
    what makes the sequence-flag rule load-bearing rather than decorative.
    """
    frame = inner_frame()
    correct = unwrap(wrap_erspan1(frame)).raw
    assert correct == frame
    naive = correct[8:]                     # what "always 8 bytes" would give
    misread = decode_frame(naive)
    honest = decode_frame(frame).endpoints
    assert misread is None or misread.endpoints != honest


@pytest.mark.smoke
def test_erspan_type_two_fields_are_read_from_the_right_bits():
    frame = inner_frame()
    result = unwrap(wrap_erspan2(frame, vlan_id=0x0ABC, cos=5, encap=2,
                                 session_id=0x2AA, index=0x0FFFFF))
    assert result is not None
    layer, = result.layers
    assert layer.kind == "erspan2"
    assert layer.detail == {"vlan": 0x0ABC, "cos": 5, "encap": 2,
                            "session_id": 0x2AA, "index": 0x0FFFFF,
                            "sequence": 1}
    assert result.raw == frame


@pytest.mark.smoke
def test_erspan_type_three_reads_its_timestamp_and_optional_subheader():
    """
    Type III is twelve bytes, plus eight more when the O bit is set.

    The optional sub-header is the second variable-length decision in the
    format and the second chance to shift the inner frame, so both cases have
    to recover the same bytes.
    """
    frame = inner_frame()
    plain = unwrap(wrap_erspan3(frame, timestamp=0xCAFEBABE))
    withsub = unwrap(wrap_erspan3(frame, timestamp=0xCAFEBABE,
                                  subheader=True))
    assert plain is not None and withsub is not None
    assert plain.raw == frame == withsub.raw
    assert plain.layers[0].detail["timestamp"] == 0xCAFEBABE
    assert plain.layers[0].detail["subheader"] is False
    assert withsub.layers[0].detail["subheader"] is True
    assert withsub.layers[0].detail["sgt"] == 0x0102


@pytest.mark.smoke
def test_erspan_type_three_can_mirror_a_bare_ip_packet():
    """
    Type III's frame type says whether what follows is a frame or a packet.

    Five bits of the third header word: 0 for Ethernet, 2 for IP. Reading an
    IP mirror as Ethernet shifts every offset by fourteen bytes, which is the
    same failure the rest of this file is about. LINKTYPE_RAW is handed on
    rather than a manufactured Ethernet header, so framing takes the family
    from the IP version nibble and refuses a frame type that lied.
    """
    packet = inner_frame()[14:]                    # bare IPv4, no Ethernet
    result = unwrap(wrap_erspan3(packet, frame_type=2))
    assert result is not None
    assert result.linktype == LINKTYPE_RAW
    assert result.raw == packet
    assert result.layers[0].detail["frame_type"] == 2
    assert decode_frame(result.raw, result.linktype) is not None

    # A frame type that lies: an Ethernet frame announced as IP. The version
    # nibble of a MAC address is not 4 or 6, so framing refuses rather than
    # reporting a session at offsets fourteen bytes out.
    lying = unwrap(wrap_erspan3(inner_frame(), frame_type=2))
    assert lying.linktype == LINKTYPE_RAW
    assert decode_frame(lying.raw, lying.linktype) is None
    assert decode_packet(wrap_erspan3(inner_frame(), frame_type=2)) is None


@pytest.mark.smoke
def test_an_erspan_version_nibble_that_contradicts_the_gre_flags_is_refused():
    """
    The sequence flag said Type II and the version nibble says otherwise.

    Trusting the flag here would consume eight bytes of somebody's
    destination MAC. One frame lost and a counter raised is the cheaper
    outcome than a session document nobody can trace back to a real host.
    """
    stats = collections.Counter()
    frame = inner_frame()
    assert unwrap(wrap_erspan2(frame, version=3), stats=stats) is None
    assert unwrap(wrap_erspan3(frame, version=1), stats=stats) is None
    assert stats["tunnel_refused_erspan_version"] == 2


# ---------------------------------------------------------------------------
# the truncation bit -- labelled missing data
# ---------------------------------------------------------------------------
@pytest.mark.smoke
@pytest.mark.parametrize("wrap", [wrap_erspan2, wrap_erspan3],
                         ids=["type2", "type3"])
def test_the_truncation_bit_survives_to_the_caller(wrap):
    """
    A switch that truncated the mirrored frame says so, and that must not be
    thrown away.

    This project has been bitten twice by *unlabelled* missing data --
    truncated ClientHellos parsed as though whole, and tshark's desegmenter
    giving up in silence -- and both times the cost was an answer that looked
    right. The T bit is the rare case where the missing data comes labelled,
    so discarding the label would be choosing the worse of the two.
    """
    frame = inner_frame()
    whole = unwrap(wrap(frame))
    cut = unwrap(wrap(frame, truncated=True))
    assert whole.truncated is False
    assert cut.truncated is True
    assert cut.layers[0].truncated is True
    # And it reaches the counter the CLI prints, not only the return value.
    stats = collections.Counter()
    decode_packet(wrap(frame, truncated=True), stats=stats)
    decode_packet(wrap(frame), stats=stats)
    assert stats["tunnel_truncated"] == 1
    assert stats["tunnel_frames"] == 2


# ---------------------------------------------------------------------------
# VXLAN and GENEVE
# ---------------------------------------------------------------------------
@pytest.mark.smoke
def test_vxlan_and_geneve_are_unwrapped_from_their_udp_datagrams():
    frame = inner_frame()
    for wrapped, kind, vni in ((wrap_vxlan(frame), "vxlan", 0x0000AB),
                               (wrap_geneve(frame), "geneve", 0x0000CD)):
        result = unwrap(wrapped)
        assert result is not None, kind
        assert result.raw == frame
        assert result.layers[0].kind == kind
        assert result.layers[0].detail["vni"] == vni


@pytest.mark.smoke
def test_the_linux_vxlan_port_is_recognised_too():
    """8472 is what Linux's vxlan driver used before the IANA number."""
    frame = inner_frame()
    assert unwrap(wrap_vxlan(frame, dport=8472)).raw == frame


@pytest.mark.smoke
def test_geneve_options_shift_the_inner_frame():
    """`Opt Len` counts four-byte words and is the whole variable part."""
    frame = inner_frame()
    for words in range(0, 4):
        result = unwrap(wrap_geneve(frame, options=b"\xAB" * (words * 4)))
        assert result is not None, words
        assert result.raw == frame
        assert result.layers[0].detail["options"] == words * 4


@pytest.mark.smoke
def test_a_tunnel_port_carrying_something_else_stays_a_udp_datagram():
    """
    Detection is by content even here. A port only decides whether to look.

    VXLAN and GENEVE are the one place in this project where a port is
    consulted at all, because a VXLAN packet is also a perfectly good UDP
    datagram and "decode first, unwrap on refusal" would never look inside
    it. So the header is validated and the inner frame has to decode -- and
    when it does not, the outer datagram is handed on unharmed rather than
    lost to the UDP router.
    """
    stats = collections.Counter()
    # RFC 7348 requires the I bit; without it a receiver must drop the packet.
    decoded = decode_packet(wrap_vxlan(inner_frame(), valid=False),
                            stats=stats)
    assert decoded is not None
    assert decoded.tunnel is None
    assert decoded.datagram is not None
    assert decoded.datagram.endpoints['dst']['port'] == 4789
    assert stats["tunnel_refused_vxlan_flags"] == 1

    # And something that is not a tunnel at all, on a port nothing watches.
    plain = ether(ipv4(udp(b"hello", 1111, 2222), IP_PROTO_UDP),
                  ETHERTYPE_IPV4)
    decoded = decode_packet(plain)
    assert decoded.tunnel is None and decoded.datagram is not None


@pytest.mark.smoke
def test_untunnelled_packets_are_passed_straight_through():
    """The overwhelming majority of packets. Nothing may change for them."""
    frame = inner_frame()
    decoded = decode_packet(frame)
    assert decoded.tunnel is None
    assert decoded.raw is frame
    assert decoded.frame == decode_frame(frame)
    assert decoded.datagram is None
    assert decode_packet(b"\x00" * 4) is None


# ---------------------------------------------------------------------------
# bounded recursion
# ---------------------------------------------------------------------------
def _nest(frame, depth):
    """`depth` GRE-in-IP headers wrapped around one Ethernet frame."""
    for _ in range(depth):
        frame = wrap_gre_teb(frame)
    return frame


@pytest.mark.smoke
@pytest.mark.parametrize("depth", range(1, MAX_TUNNEL_DEPTH + 1))
def test_nesting_up_to_the_cap_is_unwrapped(depth):
    """
    A tunnel inside a tunnel is legitimate: VXLAN inside GRE, or the mirror
    of a link that was itself carrying one.
    """
    frame = inner_frame()
    result = unwrap(_nest(frame, depth))
    assert result is not None
    assert result.raw == frame
    assert len(result.layers) == depth


@pytest.mark.smoke
def test_nesting_past_the_cap_is_refused_and_counted():
    """
    A tunnel inside itself four hundred times is an attack, not a topology.

    Refused outright rather than returned half-unwrapped: what would come
    back at the cap is another tunnel header, and the caller has no way to
    tell that from a frame.
    """
    stats = collections.Counter()
    deep = _nest(inner_frame(), MAX_TUNNEL_DEPTH + 1)
    assert unwrap(deep, stats=stats) is None
    assert stats["tunnel_depth_exceeded"] == 1
    assert decode_packet(deep, stats=stats) is None


@pytest.mark.smoke
def test_the_cap_bounds_the_work_one_frame_can_ask_for():
    """
    Twenty bytes buys another layer, so the bound has to be on layers.

    An IPv4-in-IPv4 header is twenty bytes, so a 1500-byte frame nests
    seventy-five of them and a jumbo frame four hundred. The cap is what
    stops the work per packet being chosen by whoever wrote the capture.
    """
    body = inner_frame()[14:]
    for _ in range(40):
        body = ipv4(body, IP_PROTO_IPIP)
    stats = collections.Counter()
    assert unwrap(ether(body, ETHERTYPE_IPV4), stats=stats) is None
    assert stats["tunnel_depth_exceeded"] == 1


@pytest.mark.smoke
def test_a_lower_cap_is_honoured():
    """`max_depth` is a parameter, so a caller may be stricter than default."""
    frame = inner_frame()
    assert unwrap(_nest(frame, 2), max_depth=1) is None
    assert unwrap(_nest(frame, 1), max_depth=1).raw == frame


# ---------------------------------------------------------------------------
# the outer headers are the shared walk, not a second copy of it
# ---------------------------------------------------------------------------
@pytest.mark.smoke
def test_the_outer_frame_may_be_vlan_tagged_or_ipv6():
    """
    ERSPAN is often delivered over a tagged uplink, and increasingly over
    IPv6.

    All of these work because the network walk is borrowed from `framing`
    rather than written again here, which is the argument for borrowing it: a
    second copy would be a second place to forget IHL, the VLAN loop or the
    IPv6 extension chain.
    """
    frame = inner_frame()
    body = gre(erspan2_header(session_id=9) + frame,
               GRE_PROTO_ERSPAN_I_II, sequence=1)

    tagged = ether(struct.pack(">HH", 100, ETHERTYPE_IPV4)
                   + ipv4(body, IP_PROTO_GRE), 0x8100)
    assert unwrap(tagged).raw == frame

    qinq = ether(struct.pack(">HHHH", 200, 0x8100, 100, ETHERTYPE_IPV4)
                 + ipv4(body, IP_PROTO_GRE), 0x88A8)
    assert unwrap(qinq).raw == frame

    over_v6 = ether(ipv6(body, IP_PROTO_GRE), ETHERTYPE_IPV6)
    assert unwrap(over_v6).raw == frame

    with_options = ether(ipv4(body, IP_PROTO_GRE,
                              options=b"\x01\x01\x01\x01"), ETHERTYPE_IPV4)
    assert unwrap(with_options).raw == frame


@pytest.mark.smoke
def test_a_non_initial_fragment_of_a_tunnel_is_refused():
    """
    A fragment carries no GRE header, so whatever is at that offset is
    payload dressed up as one. `framing` already refuses these on both
    families, and borrowing its walk is what makes that true here too.
    """
    body = gre(erspan2_header() + inner_frame(), GRE_PROTO_ERSPAN_I_II,
               sequence=1)
    header = bytearray(ipv4(body, IP_PROTO_GRE))
    header[6:8] = struct.pack(">H", 0x0020)      # fragment offset 32 octets
    assert unwrap(ether(bytes(header), ETHERTYPE_IPV4)) is None


# ---------------------------------------------------------------------------
# hostile input
# ---------------------------------------------------------------------------
@pytest.mark.smoke
def test_headers_that_claim_more_than_the_buffer_holds_are_refused():
    """
    Every length in this format is computed from bytes somebody else chose.

    `decode_frame` carries a scar from exactly this class: a frame ending
    inside its own TCP header produced payload_offset past payload_end, and
    subtracting those is a negative length. Each computed offset here is
    checked against what is actually left before it becomes an offset.

    The expected counter is asserted, not just the refusal. Several of these
    would be refused anyway by a later check -- an offset past the end
    produces an empty slice, which is rejected too -- so testing only "is it
    None" would pass with the specific bound removed, and the counter is how
    an operator finds out which malformation they are being sent.
    """
    frame = inner_frame()
    cases = {
        # GRE flags claiming twelve bytes of optional fields that are absent
        "gre_flags_past_end": (
            ether(ipv4(struct.pack(">HH", 0xB000, GRE_PROTO_TEB),
                       IP_PROTO_GRE), ETHERTYPE_IPV4),
            "tunnel_refused_gre_truncated_header"),
        # a GRE header cut in half
        "gre_header_halved": (
            ether(ipv4(b"\x00\x00", IP_PROTO_GRE), ETHERTYPE_IPV4),
            "tunnel_refused_gre_short"),
        # ERSPAN Type II announced, four bytes of header supplied
        "erspan2_short": (
            ether(ipv4(gre(erspan2_header()[:4], GRE_PROTO_ERSPAN_I_II,
                           sequence=1), IP_PROTO_GRE), ETHERTYPE_IPV4),
            "tunnel_refused_erspan_short"),
        # Type III with the O bit set and no room for the sub-header
        "erspan3_subheader_past_end": (
            ether(ipv4(gre(erspan3_header(subheader=True)[:12],
                           GRE_PROTO_ERSPAN_III, sequence=1), IP_PROTO_GRE),
                  ETHERTYPE_IPV4),
            "tunnel_refused_erspan_short"),
        # a tunnel with nothing inside it
        "erspan2_empty": (
            ether(ipv4(gre(erspan2_header(), GRE_PROTO_ERSPAN_I_II,
                           sequence=1), IP_PROTO_GRE), ETHERTYPE_IPV4),
            "tunnel_refused_empty"),
        # GENEVE whose option length runs off the end of the datagram
        "geneve_options_past_end": (
            ether(ipv4(udp(geneve_header(options=b"\x00" * 8)[:10], 45678,
                           6081), IP_PROTO_UDP), ETHERTYPE_IPV4),
            "tunnel_refused_geneve_options"),
        # VXLAN header cut short
        "vxlan_short": (
            ether(ipv4(udp(vxlan_header()[:5], 45678, 4789), IP_PROTO_UDP),
                  ETHERTYPE_IPV4),
            "tunnel_refused_vxlan_short"),
        # GRE carrying something that is not a frame at all
        "gre_unknown_protocol": (
            ether(ipv4(gre(frame, 0x0021), IP_PROTO_GRE), ETHERTYPE_IPV4),
            "tunnel_refused_gre_protocol"),
    }
    for name, (wrapped, counter) in cases.items():
        stats = collections.Counter()
        assert unwrap(wrapped, stats=stats) is None, name
        assert stats[counter] == 1, (name, dict(stats))


@pytest.mark.smoke
def test_an_ip_total_length_that_lies_cannot_reach_past_the_buffer():
    """
    A bad NIC offload writes an IP total length larger than the frame.

    `framing._payload_end` already falls back to the buffer in that case;
    this checks that the fallback is actually reached from here, since the
    inner slice is taken against it.
    """
    frame = inner_frame()
    wrapped = bytearray(wrap_erspan2(frame))
    wrapped[16:18] = struct.pack(">H", 0xFFFF)     # outer IP total length
    result = unwrap(bytes(wrapped))
    assert result is not None
    assert len(result.raw) <= len(wrapped)
    assert result.raw == frame


@pytest.mark.smoke
def test_unwrapping_never_raises_and_never_grows_a_frame():
    """
    Mutated encapsulations, over the house fuzz engine.

    Two invariants rather than absence of exceptions, because an exception is
    the cheap failure here -- it is loud and it costs one frame. The
    expensive failure is an inner frame longer than the outer one, which
    means an offset was computed from a length nobody checked.
    """
    rnd = seeded("tunnels")
    seeds = [wrap_erspan1(inner_frame()), wrap_erspan2(inner_frame()),
             wrap_erspan3(inner_frame(), subheader=True),
             wrap_gre_teb(inner_frame(), checksum=True, key=1, sequence=2),
             wrap_vxlan(inner_frame()), wrap_geneve(inner_frame()),
             wrap_ipip(inner_frame()), _nest(inner_frame(), 3)]
    unwrapped = 0
    for _ in range(600):
        raw = mutate(rnd.choice(seeds), rnd)
        result = unwrap(raw)
        if result is None:
            continue
        unwrapped += 1
        assert isinstance(result.raw, bytes)
        assert len(result.raw) <= len(raw)
        assert 1 <= len(result.layers) <= MAX_TUNNEL_DEPTH
        # Whatever came out must decode or be refused by framing, never
        # produce the impossible offsets that fuzzing found in decode_frame.
        decoded = decode_frame(result.raw, result.linktype)
        if decoded is not None:
            assert 0 <= decoded.payload_offset <= decoded.payload_end \
                <= len(result.raw)
    assert unwrapped, "the mutation destroyed every case -- nothing was tested"


@pytest.mark.smoke
def test_decode_packet_never_raises_on_mutated_captures():
    """The full entry point, over the same mutations, with a live counter."""
    rnd = seeded("tunnels-decode")
    seeds = [wrap_erspan2(inner_frame()), wrap_vxlan(inner_frame()),
             inner_frame()]
    stats = collections.Counter()
    for _ in range(600):
        decoded = decode_packet(mutate(rnd.choice(seeds), rnd), stats=stats)
        if decoded is None:
            continue
        assert (decoded.frame is None) != (decoded.datagram is None)
    assert stats, "no counter moved -- the mutation is not reaching the parser"


# ---------------------------------------------------------------------------
# the claim that matters: the same sessions, through the tunnel
# ---------------------------------------------------------------------------
def test_the_pipeline_sees_through_erspan_to_the_identical_sessions():
    """
    A real TLS 1.2 conversation, mirrored over ERSPAN, must produce exactly
    the document it produces unmirrored.

    Not "a similar document" and not "the same ciphersuite" -- the same
    dictionary. Everything downstream of the unwrap is untouched by this PR,
    so any difference at all is the unwrap having changed the bytes, the
    offsets or the timestamps. This is what distinguishes a tunnel parser
    that works from one that round-trips through its own encoder.
    """
    direct, _ = sessions_of(STREAM)
    through, stats = sessions_of(TUNNELS / "erspan2_tls12.pcap")
    assert direct, "the stream fixture produced no sessions"
    assert direct[0]['tls']['ciphersuite'], "the baseline document is empty"
    assert through == direct
    assert stats["frames_undecodable"] == 0
    assert stats["tunnel_frames"] == stats["frames"]
    assert stats["tunnel_erspan2"] == stats["frames"]


def test_the_committed_type_catalogue_decodes_to_one_frame_each():
    """Every encapsulation in the catalogue recovers the same inner frame."""
    expected = inner_frame()
    kinds = []
    with Reader(TUNNELS / "tunnel_types.pcap") as reader:
        for packet in reader:
            decoded = decode_packet(packet.data, packet.linktype)
            assert decoded is not None, packet.index
            assert decoded.tunnel is not None, packet.index
            kinds.append(decoded.tunnel.layers[0].kind)
            if decoded.tunnel.linktype == LINKTYPE_ETHERNET:
                assert decoded.raw == expected, packet.index
            else:
                assert decoded.raw == expected[14:], packet.index
    assert kinds == CATALOGUE


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_the_committed_fixtures_are_byte_reproducible(name):
    """
    Regenerating a fixture must not change it.

    A fixture that comes back with a fresh timestamp shows up as a diff on
    every run, which happened in PR-14 and cost a day of "what changed?". It
    also means the builders above cannot silently drift away from the files
    they are supposed to have generated.
    """
    assert (TUNNELS / name).read_bytes() == BUILDERS[name]()
