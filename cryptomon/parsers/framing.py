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

from cryptomon.utils import decimal_to_human, lst2int

ETH_HDR_LEN = 14          # Ethernet II header, before any VLAN tag
IP4_HDR_LEN = 20          # minimum IPv4 header; the real one comes from IHL
TCP_HDR_LEN = 20          # minimum TCP header; the real one comes from offset

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
# 802.1Q, 802.1ad (QinQ) and the two pre-standard TPIDs still seen in the wild.
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100, 0x9200)
MAX_VLAN_TAGS = 2         # one 802.1Q tag, or a QinQ pair; more is malformed

IP_PROTO_TCP = 6


class DecodedFrame(NamedTuple):
    """What the protocol parsers need from the framing, and nothing else."""
    endpoints: dict        # the 'eth' block recorded on every document
    payload_offset: int    # first byte after the TCP header
    ip_total_len: int      # IPv4 total length field


def decode_ipv4_tcp(raw):
    """
    Walk Ethernet -> (VLAN tags) -> IPv4 -> TCP.

    Returns a DecodedFrame, or None when the frame is not IPv4 over TCP or is
    too short to walk. Returning None rather than guessing is the point: the
    callers drop the packet, which is the honest outcome for a frame this
    parser cannot read.

    Not handled here: IPv6 (issue #19, and there are already two unmerged
    implementations of it), and anything below Ethernet such as SLL2 or
    ERSPAN.

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

    if ethertype != ETHERTYPE_IPV4:
        return None

    # --- network layer --------------------------------------------------
    if len(raw) < ip_offset + IP4_HDR_LEN:
        return None
    ip_header_len = (raw[ip_offset] & 0x0F) * 4
    if not IP4_HDR_LEN <= ip_header_len <= 60:
        return None                      # IHL below 5 or above 15 is malformed
    if raw[ip_offset + 9] != IP_PROTO_TCP:
        return None

    ip_total_len = lst2int(raw[ip_offset + 2:ip_offset + 4])
    src = lst2int(raw[ip_offset + 12:ip_offset + 16])
    dst = lst2int(raw[ip_offset + 16:ip_offset + 20])

    # --- transport layer -------------------------------------------------
    tcp_offset = ip_offset + ip_header_len
    if len(raw) < tcp_offset + TCP_HDR_LEN:
        return None
    tcp_header_len = (raw[tcp_offset + 12] >> 4) * 4
    if not TCP_HDR_LEN <= tcp_header_len <= 60:
        return None

    endpoints = {
        'src': {'ipv4': decimal_to_human(str(src)),
                'port': lst2int(raw[tcp_offset:tcp_offset + 2])},
        'dst': {'ipv4': decimal_to_human(str(dst)),
                'port': lst2int(raw[tcp_offset + 2:tcp_offset + 4])},
    }
    return DecodedFrame(endpoints, tcp_offset + tcp_header_len, ip_total_len)
