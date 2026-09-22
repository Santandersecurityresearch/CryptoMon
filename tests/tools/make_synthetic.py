#!/usr/bin/env python3
"""
Build synthetic framing fixtures: a ClientHello wrapped in framing the corpus
does not contain.

Every capture in CryptomonData/ and sandbox/ is Ethernet + IPv4 (checked with
capinfos), so the corpus cannot exercise a VLAN tag, QinQ or IPv6 at all. Real
networks do. These are constructed by hand from a genuine ClientHello payload
lifted out of an existing fixture, so only the framing differs.

    ./tests/tools/make_synthetic.py

Writes tests/fixtures/synthetic/*.pcap, which are committed.
"""
import pathlib
import sys

from scapy.all import (Dot1Q, Ether, IP, IPOption_NOP, IPv6,
                       IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
                       PcapReader, TCP, UDP, Raw, wrpcap)

HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures"
OUT = FIXTURES / "synthetic"


def first_client_hello():
    """Lift a real ClientHello's TCP payload out of a committed fixture."""
    for pcap in sorted(FIXTURES.glob("*.pcap")):
        with PcapReader(str(pcap)) as reader:
            for pkt in reader:
                if TCP not in pkt or Raw not in pkt:
                    continue
                payload = bytes(pkt[Raw].load)
                if len(payload) > 6 and payload[0] == 0x16 and payload[5] == 0x01:
                    return payload, pcap.name
    raise SystemExit("no ClientHello found in tests/fixtures/*.pcap")


def main():
    payload, source = first_client_hello()
    OUT.mkdir(parents=True, exist_ok=True)
    eth = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    tcp = dict(sport=54321, dport=443, flags="PA", seq=1)

    cases = {
        "plain_ipv4": Ether(**eth) / IP(src="10.0.0.1", dst="10.0.0.2")
                      / TCP(**tcp) / Raw(payload),
        "vlan": Ether(**eth) / Dot1Q(vlan=100)
                / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(**tcp) / Raw(payload),
        "qinq": Ether(**eth) / Dot1Q(vlan=100) / Dot1Q(vlan=200)
                / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(**tcp) / Raw(payload),
        "ipv6": Ether(**eth) / IPv6(src="2001:db8::1", dst="2001:db8::2")
                / TCP(**tcp) / Raw(payload),
        # IHL 6 rather than 5: four bytes of options push the TCP header out.
        # bpf.py handles this (ip->hlen << 2); the Python side did not.
        "ip_options": Ether(**eth)
                      / IP(src="10.0.0.1", dst="10.0.0.2",
                           options=[IPOption_NOP(), IPOption_NOP(),
                                    IPOption_NOP(), IPOption_NOP()])
                      / TCP(**tcp) / Raw(payload),
        # Not TCP at all: must be refused, not read at TCP's offsets.
        "udp": Ether(**eth) / IP(src="10.0.0.1", dst="10.0.0.2")
               / UDP(sport=54321, dport=443) / Raw(payload),
        # IPv6 moved options into a chain, so the TCP header is only found
        # by walking it -- there is no header-length field to read.
        "ipv6_extheader": Ether(**eth)
                          / IPv6(src="2001:db8::1", dst="2001:db8::2")
                          / IPv6ExtHdrDestOpt()
                          / TCP(**tcp) / Raw(payload),
        # A non-initial fragment carries no TCP header at all; reading one
        # there would dress payload bytes up as ports.
        "ipv6_fragment": Ether(**eth)
                         / IPv6(src="2001:db8::1", dst="2001:db8::2")
                         / IPv6ExtHdrFragment(offset=64, nh=6)
                         / Raw(payload),
    }
    for name, pkt in cases.items():
        path = OUT / f"{name}.pcap"
        # Fixed timestamp so regenerating produces byte-identical files.
        # scapy otherwise stamps "now", and every re-run shows up as a diff
        # on a committed fixture that did not actually change.
        pkt.time = 1733875200          # 2024-12-11T00:00:00Z, the corpus date
        wrpcap(str(path), [pkt])
        print(f"  wrote  synthetic/{name}.pcap  {path.stat().st_size} bytes")
    print(f"\npayload lifted from {source} ({len(payload)} bytes)")


if __name__ == "__main__":
    sys.exit(main())
