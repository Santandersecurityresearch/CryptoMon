"""
Link and network framing: Ethernet -> IPv4 -> TCP.

Every byte offset the protocol parsers use hangs off what this module
returns, which is why it is the only file that had to change to support
VLAN tags and IPv4 options.

What the offsets used to be, and why that was dangerous: ETH_HDR_LEN and
IP4_HDR_LEN were constants, so a frame with an 802.1Q tag (+4), QinQ (+8) or
IPv4 options (up to +40) did not fail to parse. It parsed the wrong bytes and
reported plausible, wrong ciphersuites. Silent wrongness in a tool whose
output is meant to be attestable is worse than a crash.
"""
from typing import NamedTuple

from cryptomon.utils import bytes_to_ip, lst2int

ETH_HDR_LEN = 14          # Ethernet II header, before any VLAN tag
IP4_HDR_LEN = 20          # minimum IPv4 header; the real one comes from IHL
TCP_HDR_LEN = 20          # minimum TCP header; the real one comes from offset

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
# 802.1Q, 802.1ad (QinQ) and the two pre-standard TPIDs still seen in the wild.
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100, 0x9200)
MAX_VLAN_TAGS = 2         # one 802.1Q tag, or a QinQ pair; more is malformed

IP_PROTO_TCP = 6

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


def _walk_ipv6(raw, ip_offset):
    """
    Walk an IPv6 header and its extension header chain to the TCP header.

    IPv6 moved options out of the fixed header into a chain, so unlike IPv4
    there is no header-length field to read -- the chain has to be walked.
    Returns (src, dst, tcp_offset, total_len), or None when the chain does
    not end at TCP.

    A non-initial fragment is refused: it carries no TCP header, so anything
    read at that offset would be payload bytes dressed up as one.
    """
    if len(raw) < ip_offset + IPV6_HDR_LEN:
        return None
    payload_len = lst2int(raw[ip_offset + 4:ip_offset + 6])
    next_header = raw[ip_offset + 6]
    src = bytes(raw[ip_offset + 8:ip_offset + 24])
    dst = bytes(raw[ip_offset + 24:ip_offset + 40])

    offset = ip_offset + IPV6_HDR_LEN
    for _ in range(MAX_IPV6_EXT_HEADERS):
        if next_header == IP_PROTO_TCP:
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
            return None                    # ESP, ICMPv6, UDP, anything else
        offset += ext_len
    return None                            # chain too long to be genuine


def decode_ipv4_tcp(raw):
    """
    Walk Ethernet -> (VLAN tags) -> IPv4 -> TCP.

    Returns a DecodedFrame, or None when the frame is not IPv4 over TCP or is
    too short to walk. Returning None rather than guessing is the point: the
    callers drop the packet, which is the honest outcome for a frame this
    parser cannot read.

    Handles IPv4 and IPv6, with or without VLAN tags. Not handled: anything
    below Ethernet such as SLL2 or ERSPAN, and IPv6 chains ending anywhere
    but TCP.

    Note the live path has its own copy of this problem. bpf.py derives the
    IPv4 header length correctly (ip->hlen << 2) but hard-codes
    `#define ETH_HLEN 14`, so a VLAN-tagged frame fails its IP_TCP check and
    is never forwarded. Fixing this file makes VLAN traffic readable from a
    capture; making it visible live needs the same change in the C.
    """
    if len(raw) < ETH_HDR_LEN + IP4_HDR_LEN + TCP_HDR_LEN:
        return None

    # --- link layer: skip any stacked VLAN tags -------------------------
    ethertype = lst2int(raw[12:14])
    ip_offset = ETH_HDR_LEN
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
        walked = _walk_ipv6(raw, ip_offset)
        if walked is None:
            return None
        src, dst, tcp_offset, ip_total_len = walked
        version, family = 6, 'ipv6'
    elif ethertype == ETHERTYPE_IPV4:
        if len(raw) < ip_offset + IP4_HDR_LEN:
            return None
        ip_header_len = (raw[ip_offset] & 0x0F) * 4
        if not IP4_HDR_LEN <= ip_header_len <= 60:
            return None                  # IHL below 5 or above 15 is malformed
        if raw[ip_offset + 9] != IP_PROTO_TCP:
            return None
        ip_total_len = lst2int(raw[ip_offset + 2:ip_offset + 4])
        src = bytes(raw[ip_offset + 12:ip_offset + 16])
        dst = bytes(raw[ip_offset + 16:ip_offset + 20])
        tcp_offset = ip_offset + ip_header_len
        version, family = 4, 'ipv4'
    else:
        return None

    # --- transport layer -------------------------------------------------
    if len(raw) < tcp_offset + TCP_HDR_LEN:
        return None
    tcp_header_len = (raw[tcp_offset + 12] >> 4) * 4
    if not TCP_HDR_LEN <= tcp_header_len <= 60:
        return None

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
                        version)
