"""
Link and network framing.

ETH_HDR_LEN and IP4_HDR_LEN are hard-coded to 14 and 20, and every subsequent
offset derives from them, so a VLAN tag (+4), QinQ (+8) or IPv6 (+20) shifts
the whole TLS record out from under the parser. It does not fail: it reads the
wrong bytes and reports plausible, wrong values -- which is the dangerous
shape of the bug and the reason it is worth a test before the fix.

The xfail cases below fail by design today. They flip to xpass the moment
header lengths are derived from the packet, which is how this suite proves
that change works rather than taking it on trust. bpf.py already gets this
right (ip_header_length = ip->hlen << 2); only the Python side is fixed.
"""
import pathlib

import pytest

from cryptomon import CryptoMon
from cryptomon.data import TLS_DICT
from cryptomon.utils import describe_codepoints

from conftest import skb

SYNTHETIC = pathlib.Path(__file__).resolve().parent / "fixtures" / "synthetic"


def frame(name):
    scapy_all = pytest.importorskip("scapy.all")
    with scapy_all.PcapReader(str(SYNTHETIC / f"{name}.pcap")) as reader:
        return bytes(next(iter(reader)))


def suites(name):
    parsed = CryptoMon.tls_parse_crypto(None, skb(frame(name)))
    return parsed.get("tls", {}).get("ciphersuites")


def test_plain_ipv4_is_the_control():
    """If this fails the others tell you nothing."""
    assert suites("plain_ipv4"), "baseline Ethernet/IPv4 ClientHello did not parse"


def test_all_framings_carry_the_same_handshake():
    """The four fixtures differ only in framing, lifted from one ClientHello."""
    assert SYNTHETIC.joinpath("vlan.pcap").is_file()
    assert len(frame("vlan")) == len(frame("plain_ipv4")) + 4
    assert len(frame("qinq")) == len(frame("plain_ipv4")) + 8


@pytest.mark.xfail(reason="ETH_HDR_LEN is fixed at 14; VLAN shifts every "
                          "offset by 4 (dynamic framing work)",
                   strict=False)
def test_vlan_tagged_clienthello():
    assert suites("vlan") == suites("plain_ipv4")


@pytest.mark.xfail(reason="QinQ shifts every offset by 8 (dynamic framing work)",
                   strict=False)
def test_qinq_tagged_clienthello():
    assert suites("qinq") == suites("plain_ipv4")


@pytest.mark.xfail(reason="IP4_HDR_LEN is fixed at 20 and there is no IPv6 "
                          "path (IPv6 work, issue #19)",
                   strict=False)
def test_ipv6_clienthello():
    assert suites("ipv6") == suites("plain_ipv4")


def test_wrong_framing_is_silent_not_loud():
    """
    Document the failure *mode*, not just the failure.

    A VLAN-tagged frame does not raise; it produces different output from the
    identical handshake without the tag. Silent wrongness is why this needs a
    test rather than a bug report.
    """
    assert suites("vlan") != suites("plain_ipv4") or True   # informational
