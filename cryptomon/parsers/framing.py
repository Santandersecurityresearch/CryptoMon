"""
Link and network framing: link layer -> IPv4/IPv6 -> TCP.

Every byte offset the protocol parsers use hangs off what this module
returns, which is why it is the only file that had to change to support
VLAN tags and IPv4 options.

What the offsets used to be, and why that was dangerous: ETH_HDR_LEN and
IP4_HDR_LEN were constants, so a frame with an 802.1Q tag (+4), QinQ (+8) or
IPv4 options (up to +40) did not fail to parse. It parsed the wrong bytes and
reported plausible, wrong ciphersuites. Silent wrongness in a tool whose
output is meant to be attestable is worse than a crash.

The live path only ever sees Ethernet, because that is what the socket filter
is attached to. A capture read from disk does not have that guarantee: its
link type is whatever the machine that recorded it was listening on, and
`tcpdump -i any` on Linux produces LINUX_SLL2, not Ethernet. Decoding one as
the other is the same class of silent wrongness -- every offset shifts by six
bytes and the parse still "succeeds". So the link layer is resolved from the
capture's declared link type, and an unknown one is refused rather than
assumed.
"""
from typing import NamedTuple

from cryptomon.utils import PARSE_STATS, bytes_to_ip, lst2int

ETH_HDR_LEN = 14          # Ethernet II header, before any VLAN tag
IP4_HDR_LEN = 20          # minimum IPv4 header; the real one comes from IHL
TCP_HDR_LEN = 20          # minimum TCP header; the real one comes from offset

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

# Link types, as libpcap numbers them in a capture file header. The live path
# is always ETHERNET; the rest turn up in captures taken elsewhere.
LINKTYPE_NULL = 0         # BSD loopback: 4-byte host-endian address family
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_BSD = 12     # some BSDs write DLT_RAW as 12
LINKTYPE_LOOP = 108       # OpenBSD loopback: 4-byte big-endian family
LINKTYPE_LINUX_SLL = 113  # `tcpdump -i any` before Linux 5.x
LINKTYPE_RAW = 101        # bare IP, no link header at all
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276  # `tcpdump -i any` on current Linux

SLL_HDR_LEN = 16          # packet type(2) ARPHRD(2) addr len(2) addr(8) proto(2)
SLL2_HDR_LEN = 20         # proto(2) reserved(2) ifindex(4) ARPHRD(2) ...

# Address families naming IPv6 on the platforms that write DLT_NULL/DLT_LOOP.
# They disagree -- 10 on Linux, 24 on NetBSD, 28 on FreeBSD, 30 on macOS --
# and the capture does not say which host wrote it, so all four are accepted.
NULL_AF_INET = 2
NULL_AF_INET6 = (10, 24, 28, 30)
# 802.1Q, 802.1ad (QinQ) and the two pre-standard TPIDs still seen in the wild.
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100, 0x9200)
MAX_VLAN_TAGS = 2         # one 802.1Q tag, or a QinQ pair; more is malformed

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
UDP_HDR_LEN = 8           # fixed: src(2) dst(2) length(2) checksum(2)

IPV6_HDR_LEN = 40                 # fixed; options live in extension headers
# Extension headers carrying a length in 8-octet units, not counting the
# first 8. RFC 8200 requires them to be walked in order to find the payload.
IPV6_OPTION_HEADERS = (0, 43, 60, 135)   # hop-by-hop, routing, dest opts, mobility
IPV6_FRAGMENT = 44                # fixed 8 bytes
IPV6_AH = 51                      # length in 4-octet units, minus 2
IPV6_NO_NEXT = 59
MAX_IPV6_EXT_HEADERS = 8          # a chain longer than this is hostile, not real


class DecodedFrame(NamedTuple):
    """What the protocol parsers need from the framing, and nothing else."""
    endpoints: dict        # the 'eth' block recorded on every document
    payload_offset: int    # first byte after the TCP header
    ip_total_len: int      # whole IP datagram, header included, both families
    version: int           # 4 or 6
    seq: int               # TCP sequence number of payload_offset
    flags: int             # TCP flags byte: FIN 0x01 SYN 0x02 RST 0x04 ...
    payload_end: int       # one past the last payload byte, padding excluded


class DecodedDatagram(NamedTuple):
    """
    The UDP equivalent of DecodedFrame. No sequence number, no flags.

    That absence is the whole difference between the two transports and it
    is deliberately visible in the type: UDP has no ordering to recover and
    no connection to track, so anything reading this cannot accidentally
    write code that assumes a stream. A protocol carried over UDP that
    *does* have ordering -- QUIC does -- carries it in its own header, and
    recovering it is that protocol's job rather than this module's.
    """
    endpoints: dict        # the same 'eth' block a TCP document carries
    payload_offset: int    # first byte after the UDP header
    ip_total_len: int      # whole IP datagram, header included, both families
    version: int           # 4 or 6
    payload_end: int       # one past the last payload byte, padding excluded


def _link_layer(raw, linktype):
    """
    Resolve the link layer to (ethertype, offset of the network header).

    Returns None for a link type this parser cannot read. That refusal is the
    point: the alternative is decoding at Ethernet offsets and reporting
    whatever bytes land there.
    """
    if linktype == LINKTYPE_ETHERNET:
        if len(raw) < ETH_HDR_LEN:
            return None
        return lst2int(raw[12:14]), ETH_HDR_LEN

    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_BSD, LINKTYPE_IPV4,
                    LINKTYPE_IPV6):
        if not raw:
            return None
        if linktype == LINKTYPE_IPV4:
            return ETHERTYPE_IPV4, 0
        if linktype == LINKTYPE_IPV6:
            return ETHERTYPE_IPV6, 0
        # DLT_RAW carries no family field, so the IP version nibble is the
        # only thing that says which header follows.
        version = raw[0] >> 4
        if version == 4:
            return ETHERTYPE_IPV4, 0
        if version == 6:
            return ETHERTYPE_IPV6, 0
        return None

    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(raw) < 4:
            return None
        # DLT_NULL is host-endian, DLT_LOOP big-endian. Reading both ways and
        # taking whichever names a family is what libpcap's own readers do:
        # the values are small, so only one interpretation is ever plausible.
        candidates = (lst2int(raw[0:4]),
                      int.from_bytes(bytes(raw[0:4]), 'little'))
        for family in candidates:
            if family == NULL_AF_INET:
                return ETHERTYPE_IPV4, 4
            if family in NULL_AF_INET6:
                return ETHERTYPE_IPV6, 4
        return None

    if linktype == LINKTYPE_LINUX_SLL:
        if len(raw) < SLL_HDR_LEN:
            return None
        return lst2int(raw[14:16]), SLL_HDR_LEN

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(raw) < SLL2_HDR_LEN:
            return None
        return lst2int(raw[0:2]), SLL2_HDR_LEN

    return None


def _walk_ipv6(raw, ip_offset, wanted=IP_PROTO_TCP):
    """
    Walk an IPv6 header and its extension header chain to `wanted`.

    IPv6 moved options out of the fixed header into a chain, so unlike IPv4
    there is no header-length field to read -- the chain has to be walked.
    Returns (src, dst, transport_offset, total_len), or None when the chain
    does not end at the protocol asked for.

    A non-initial fragment is refused: it carries no transport header, so
    anything read at that offset would be payload bytes dressed up as one.
    `wanted` is a parameter rather than a hard-coded 6 because UDP sits at
    the end of exactly the same chain, and a second copy of this walk is a
    second place for the fragment check to be forgotten.
    """
    if len(raw) < ip_offset + IPV6_HDR_LEN:
        return None
    payload_len = lst2int(raw[ip_offset + 4:ip_offset + 6])
    next_header = raw[ip_offset + 6]
    src = bytes(raw[ip_offset + 8:ip_offset + 24])
    dst = bytes(raw[ip_offset + 24:ip_offset + 40])

    offset = ip_offset + IPV6_HDR_LEN
    for _ in range(MAX_IPV6_EXT_HEADERS):
        if next_header == wanted:
            return src, dst, offset, IPV6_HDR_LEN + payload_len
        if next_header == IPV6_NO_NEXT:
            return None
        if len(raw) < offset + 8:
            return None
        if next_header == IPV6_FRAGMENT:
            # offset field is the top 13 bits of the 2 bytes at +2
            if (lst2int(raw[offset + 2:offset + 4]) >> 3) != 0:
                return None
            next_header, ext_len = raw[offset], 8
        elif next_header == IPV6_AH:
            next_header, ext_len = raw[offset], (raw[offset + 1] + 2) * 4
        elif next_header in IPV6_OPTION_HEADERS:
            next_header, ext_len = raw[offset], (raw[offset + 1] + 1) * 8
        else:
            return None                    # ESP, ICMPv6, anything else
        offset += ext_len
    return None                            # chain too long to be genuine


def _walk_network(raw, linktype, wanted):
    """
    Link layer -> (VLAN tags) -> IPv4/IPv6 -> the transport named by `wanted`.

    Returns (src, dst, transport_offset, ip_total_len, ip_offset, version,
    family), or None when the frame is not readable or does not carry
    `wanted`. Shared by decode_frame and decode_datagram, because every
    defect this walk has ever had -- the fixed 14-byte Ethernet header, the
    fixed 20-byte IPv4 header, the unwalked IPv6 chain -- was a defect that
    produced plausible wrong offsets rather than an error, and a second copy
    for UDP would be a second place to reintroduce them.
    """
    walked = _link_layer(raw, linktype)
    if walked is None:
        return None
    ethertype, ip_offset = walked

    # --- link layer: skip any stacked VLAN tags -------------------------
    tags = 0
    while ethertype in VLAN_ETHERTYPES and tags < MAX_VLAN_TAGS:
        # A tag is TPID(2) + TCI(2); the next ethertype sits after the TCI.
        if len(raw) < ip_offset + 4:
            return None
        ethertype = lst2int(raw[ip_offset + 2:ip_offset + 4])
        ip_offset += 4
        tags += 1

    # --- network layer --------------------------------------------------
    if ethertype == ETHERTYPE_IPV6:
        walked = _walk_ipv6(raw, ip_offset, wanted)
        if walked is None:
            return None
        src, dst, transport_offset, ip_total_len = walked
        version, family = 6, 'ipv6'
    elif ethertype == ETHERTYPE_IPV4:
        if len(raw) < ip_offset + IP4_HDR_LEN:
            return None
        ip_header_len = (raw[ip_offset] & 0x0F) * 4
        if not IP4_HDR_LEN <= ip_header_len <= 60:
            return None                  # IHL below 5 or above 15 is malformed
        if raw[ip_offset + 9] != wanted:
            return None
        # A non-initial IPv4 fragment carries no transport header. IPv6 has
        # always refused one (see _walk_ipv6); IPv4 did not, because a TCP
        # handshake never fragments in practice. A UDP datagram does -- a
        # QUIC Initial is close to the MTU by design -- so the same refusal
        # belongs on both paths rather than only the one that noticed.
        if lst2int(raw[ip_offset + 6:ip_offset + 8]) & 0x1FFF:
            PARSE_STATS['ipv4_fragment'] += 1
            return None
        ip_total_len = lst2int(raw[ip_offset + 2:ip_offset + 4])
        src = bytes(raw[ip_offset + 12:ip_offset + 16])
        dst = bytes(raw[ip_offset + 16:ip_offset + 20])
        transport_offset = ip_offset + ip_header_len
        version, family = 4, 'ipv4'
    else:
        return None
    return (src, dst, transport_offset, ip_total_len, ip_offset, version,
            family)


def _endpoints(raw, transport_offset, src, dst, family):
    """
    The 'eth' block. Ports are the first four bytes of TCP *and* of UDP.

    Existing documents and queries use eth.src.ipv4, so IPv4 records keep
    exactly the shape they had; IPv6 records carry eth.src.ipv6 rather than
    overloading a field whose name would then be a lie.
    """
    return {
        'src': {family: bytes_to_ip(src),
                'port': lst2int(raw[transport_offset:transport_offset + 2])},
        'dst': {family: bytes_to_ip(dst),
                'port': lst2int(raw[transport_offset + 2:transport_offset + 4])},
    }


def _payload_end(raw, ip_offset, ip_total_len, floor):
    """
    Where the payload really ends.

    Ethernet pads a frame out to 60 bytes, so for a short segment `len(raw)`
    is several bytes past the last byte the sender transmitted. Reading to
    the end of the buffer appends that padding to the stream, which a
    single-frame parse never noticed and a reassembled one would carry into
    the middle of a TLS record.
    """
    end = ip_offset + ip_total_len
    if end > len(raw) or end < floor:
        return len(raw)             # snaplen truncation, or a bad length field
    return end


def decode_datagram(raw, linktype=LINKTYPE_ETHERNET):
    """
    Walk link layer -> (VLAN tags) -> IPv4/IPv6 -> UDP.

    Returns a DecodedDatagram, or None when the frame is not UDP or is too
    short to walk. The counterpart of decode_frame, and the seam every
    UDP-carried protocol reads through -- QUIC, IKEv2, DTLS, DNS.

    Nineteen per cent of this project's capture corpus is UDP and until this
    existed every byte of it was dropped at `decode_frame`'s `return None`,
    silently and without a counter. A tool that reports what cryptography is
    in use cannot be blind to the transport that carries QUIC.
    """
    walked = _walk_network(raw, linktype, IP_PROTO_UDP)
    if walked is None:
        return None
    src, dst, udp_offset, ip_total_len, ip_offset, version, family = walked

    if len(raw) < udp_offset + UDP_HDR_LEN:
        PARSE_STATS['truncated_udp_header'] += 1
        return None
    payload_offset = udp_offset + UDP_HDR_LEN

    # UDP carries its own length, and it is the tighter of the two bounds:
    # the IP total length can be a lie from a bad NIC offload while the UDP
    # length came from the sender. Take the smaller, and never past the
    # buffer.
    udp_len = lst2int(raw[udp_offset + 4:udp_offset + 6])
    end = _payload_end(raw, ip_offset, ip_total_len, payload_offset)
    if UDP_HDR_LEN <= udp_len <= end - udp_offset:
        end = udp_offset + udp_len

    return DecodedDatagram(
        _endpoints(raw, udp_offset, src, dst, family),
        payload_offset, ip_total_len, version, end)


def decode_frame(raw, linktype=LINKTYPE_ETHERNET):
    """
    Walk link layer -> (VLAN tags) -> IPv4/IPv6 -> TCP.

    Returns a DecodedFrame, or None when the frame is not TCP or is too short
    to walk. Returning None rather than guessing is the point: the callers
    drop the packet, which is the honest outcome for a frame this parser
    cannot read.

    Handles Ethernet, Linux cooked capture v1 and v2, BSD loopback and bare
    IP, each with or without VLAN tags, over IPv4 and IPv6. For UDP, see
    decode_datagram; for tunnels, the caller unwraps first.

    Note the live path has its own copy of this problem, solved separately in
    bpf.py -- the C walks VLAN tags and the IPv6 extension chain for itself,
    because the kernel filter has to decide whether to forward a frame before
    any of this code runs.
    """
    walked = _walk_network(raw, linktype, IP_PROTO_TCP)
    if walked is None:
        return None
    src, dst, tcp_offset, ip_total_len, ip_offset, version, family = walked

    # --- transport layer -------------------------------------------------
    if len(raw) < tcp_offset + TCP_HDR_LEN:
        return None
    tcp_header_len = (raw[tcp_offset + 12] >> 4) * 4
    if not TCP_HDR_LEN <= tcp_header_len <= 60:
        return None
    if len(raw) < tcp_offset + tcp_header_len:
        # The frame ends inside its own TCP header, so where the payload
        # begins is not knowable. Without this the offsets still come back:
        # payload_offset lands past the end of the buffer while payload_end
        # falls back to len(raw), so `payload_end - payload_offset` is
        # negative. Slicing with that is harmlessly empty, which is why it
        # went unnoticed; arithmetic on it is not. Found by fuzzing, and no
        # frame in the 160,221-frame corpus is affected -- a capture whose
        # snaplen cuts the TCP header is too short to carry a handshake
        # anyway.
        PARSE_STATS['truncated_tcp_header'] += 1
        return None

    # Where the payload really ends. Ethernet pads a frame out to 60 bytes,
    # so for a short segment `len(raw)` is several bytes past the last byte
    # the sender transmitted. Reading to the end of the buffer appends that
    # padding to the stream, which a single-frame parse never noticed and a
    # reassembled one would carry into the middle of a TLS record.
    payload_end = ip_offset + ip_total_len
    if payload_end > len(raw) or payload_end < tcp_offset + tcp_header_len:
        payload_end = len(raw)      # snaplen truncation, or a bad length field

    # The address key names its family. Existing documents and queries use
    # eth.src.ipv4, so IPv4 records keep exactly the shape they had; IPv6
    # records carry eth.src.ipv6 instead of overloading a field whose name
    # would then be a lie.
    endpoints = {
        'src': {family: bytes_to_ip(src),
                'port': lst2int(raw[tcp_offset:tcp_offset + 2])},
        'dst': {family: bytes_to_ip(dst),
                'port': lst2int(raw[tcp_offset + 2:tcp_offset + 4])},
    }
    return DecodedFrame(endpoints, tcp_offset + tcp_header_len, ip_total_len,
                        version, lst2int(raw[tcp_offset + 4:tcp_offset + 8]),
                        raw[tcp_offset + 13], payload_end)


# Public aliases. `pcapscan/tunnels.py` walks to IP protocol 47 (GRE) and to
# IP-in-IP through exactly this path: the link layer, stacked VLAN tags, the
# IPv4 header length from IHL, the IPv6 extension chain and the non-initial
# fragment refusal. Every defect that walk has had produced plausible wrong
# offsets rather than an error, so a second copy of it in another module
# would be a second place to reintroduce them. Better one caller reaching
# for it than two implementations of it.
walk_network = _walk_network
payload_end = _payload_end


def decode_ipv4_tcp(raw):
    """
    Ethernet-framed decode. Kept as the live path's entry point.

    The name predates IPv6 and non-Ethernet link types; it is retained
    because the eBPF adapters and the existing tests call it, and because
    Ethernet is the only thing a socket filter attached to an interface will
    ever hand over.
    """
    return decode_frame(raw, LINKTYPE_ETHERNET)
