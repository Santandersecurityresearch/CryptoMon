"""
Link and network framing: Ethernet -> IPv4 -> TCP.

Every byte offset the protocol parsers use hangs off what this module returns,
so when header lengths stop being constants this is the only file that has to
change.
"""
from cryptomon.utils import decimal_to_human, lst2int

ETH_HDR_LEN = 14
IP4_HDR_LEN = 20
TCP_HDR_LEN = 20


def decode_ipv4_tcp(raw):
    """
    Walk an Ethernet / IPv4 / TCP frame.

    Returns (endpoints, payload_offset): the 'eth' block the parsers record,
    and the offset of the first byte after the TCP header.

    The TCP data offset is read from the packet, but ETH_HDR_LEN and
    IP4_HDR_LEN are still constants -- so a VLAN tag (+4), QinQ (+8) or IPv4
    options (up to +40) shift everything and the parsers read the wrong bytes
    without failing. See the xfail cases in tests/test_framing.py. bpf.py
    already gets this right (ip_header_length = ip->hlen << 2); only the
    Python side is fixed.
    """
    net_packet_len = ETH_HDR_LEN + IP4_HDR_LEN
    tcp_hdr_len = ((raw[net_packet_len+12:net_packet_len+13][0] >> 4) * 4)
    src = lst2int(raw[26:30])
    dst = lst2int(raw[30:34])
    endpoints = {
        'src': {'ipv4': decimal_to_human(str(src)),
                'port': lst2int(raw[net_packet_len:net_packet_len+2])},
        'dst': {'ipv4': decimal_to_human(str(dst)),
                'port': lst2int(raw[net_packet_len+2:net_packet_len+4])},
    }
    return endpoints, net_packet_len + tcp_hdr_len
