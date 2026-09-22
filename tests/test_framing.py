"""
Link and network framing.

Header lengths are derived from the packet, so a VLAN tag (+4), QinQ (+8) or
IPv4 options (up to +40) no longer shift the TLS record out from under the
parser. The failure mode before this mattered more than the failure: nothing
raised, the parser simply read the wrong bytes and reported plausible, wrong
ciphersuites.

Every fixture here carries the *same* ClientHello, lifted from a real capture,
so any difference in output is the framing and nothing else.
"""
import pathlib

import pytest

from cryptomon import CryptoMon
from cryptomon.parsers.framing import decode_ipv4_tcp
from cryptomon.utils import PARSE_STATS, reset_parse_stats

from conftest import skb

# Merge gate: synthetic frames only, no capture corpus needed.
pytestmark = pytest.mark.smoke

SYNTHETIC = pathlib.Path(__file__).resolve().parent / "fixtures" / "synthetic"


def frame(name):
    scapy_all = pytest.importorskip("scapy.all")
    with scapy_all.PcapReader(str(SYNTHETIC / f"{name}.pcap")) as reader:
        return bytes(next(iter(reader)))


def suites(name):
    parsed = CryptoMon.tls_parse_crypto(None, skb(frame(name)))
    return parsed.get("tls", {}).get("ciphersuites")


def test_plain_ipv4_is_the_control():
    """If this fails the rest tell you nothing."""
    assert suites("plain_ipv4"), "baseline Ethernet/IPv4 ClientHello did not parse"


def test_fixtures_differ_only_in_framing():
    assert len(frame("vlan")) == len(frame("plain_ipv4")) + 4
    assert len(frame("qinq")) == len(frame("plain_ipv4")) + 8
    assert len(frame("ip_options")) == len(frame("plain_ipv4")) + 4


@pytest.mark.parametrize("name", ["vlan", "qinq", "ip_options",
                                  "ipv6", "ipv6_extheader"])
def test_extra_headers_do_not_shift_the_handshake(name):
    """
    802.1Q, QinQ, IPv4 options and both IPv6 forms carry the same handshake.

    All of them used to silently corrupt the parse, IPv6 most completely: the
    40-byte header is twice IPv4's, so every offset landed inside the address
    fields.
    """
    assert suites(name) == suites("plain_ipv4"), (
        f"{name} framing produced different output from the identical "
        f"handshake without it")


def test_vlan_endpoints_are_read_from_the_right_offsets():
    """Not just the payload -- the addresses and ports move with the tag too."""
    plain = CryptoMon.tls_parse_crypto(None, skb(frame("plain_ipv4")))
    tagged = CryptoMon.tls_parse_crypto(None, skb(frame("vlan")))
    assert tagged["eth"] == plain["eth"]
    assert tagged["eth"]["dst"]["port"] == 443


# --------------------------------------------------------------- refusals
@pytest.mark.parametrize("name", ["udp", "ipv6_fragment"])
def test_unreadable_framing_is_refused_not_guessed(name):
    """
    Returning {} drops the packet, which is what a caller already does with a
    falsy result. The alternative is reading whatever bytes happen to sit
    where a plain IPv4/TCP frame would have put them.
    """
    assert decode_ipv4_tcp(frame(name)) is None
    reset_parse_stats()
    assert CryptoMon.tls_parse_crypto(None, skb(frame(name))) == {}
    assert PARSE_STATS["unsupported_framing"] == 1


def test_truncated_frames_are_refused():
    full = frame("plain_ipv4")
    for length in (0, 13, 14, 33, 53):
        assert decode_ipv4_tcp(full[:length]) is None, f"accepted {length} bytes"


def test_malformed_ihl_is_refused():
    raw = bytearray(frame("plain_ipv4"))
    raw[14] = 0x44          # version 4, IHL 4 -> below the 20-byte minimum
    assert decode_ipv4_tcp(bytes(raw)) is None


def test_vlan_stack_depth_is_bounded():
    """A frame claiming endless tags must not walk off the end."""
    raw = bytearray(frame("plain_ipv4"))
    for offset in range(12, 40, 4):
        raw[offset:offset + 2] = (0x81, 0x00)     # another 802.1Q tag
    assert decode_ipv4_tcp(bytes(raw)) is None


def test_ipv6_addresses_are_not_rendered_as_ipv4():
    """
    The address key names its family, and the value is formatted from the
    raw bytes rather than from an integer.

    decimal_to_human() picks the family by magnitude, so every IPv6 address
    below ::ffff:ffff -- ::1 included -- came out as an IPv4 dotted quad.
    """
    parsed = CryptoMon.tls_parse_crypto(None, skb(frame("ipv6")))
    assert parsed["eth"]["src"] == {"ipv6": "2001:db8::1", "port": 54321}
    assert parsed["eth"]["dst"]["ipv6"] == "2001:db8::2"
    assert "ipv4" not in parsed["eth"]["src"]


def test_ipv4_records_keep_their_existing_shape():
    """Existing documents and queries use eth.src.ipv4; that must not move."""
    parsed = CryptoMon.tls_parse_crypto(None, skb(frame("plain_ipv4")))
    assert parsed["eth"]["src"] == {"ipv4": "10.0.0.1", "port": 54321}
    assert "ipv6" not in parsed["eth"]["src"]


def test_ipv6_extension_chain_is_bounded():
    """A frame claiming an endless chain of option headers must not loop."""
    raw = bytearray(frame("ipv6_extheader"))
    raw[20] = 60                      # next header = destination options
    for pos in range(54, min(len(raw) - 2, 200), 8):
        raw[pos] = 60                 # ...and every following one, too
        raw[pos + 1] = 0
    assert decode_ipv4_tcp(bytes(raw)) is None


def test_ipv6_ports_come_from_the_right_offset():
    """The 40-byte header is fixed, but the TCP header sits past any chain."""
    plain = CryptoMon.tls_parse_crypto(None, skb(frame("ipv6")))
    chained = CryptoMon.tls_parse_crypto(None, skb(frame("ipv6_extheader")))
    assert plain["eth"]["dst"]["port"] == 443
    assert chained["eth"]["dst"]["port"] == 443
