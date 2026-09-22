"""
Protocol parsers, independent of how the bytes were captured.

Each is a pure function taking raw frame bytes, so the same code serves the
live eBPF path and anything reading a capture from disk.
"""
from cryptomon.parsers.framing import (ETH_HDR_LEN, IP4_HDR_LEN, TCP_HDR_LEN,
                                       decode_ipv4_tcp)
from cryptomon.parsers.ssh import parse_ssh
from cryptomon.parsers.tls import parse_tls

__all__ = ['ETH_HDR_LEN', 'IP4_HDR_LEN', 'TCP_HDR_LEN', 'decode_ipv4_tcp',
           'parse_ssh', 'parse_tls']
