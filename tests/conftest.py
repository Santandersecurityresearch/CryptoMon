"""
Shared test helpers.

The parsers are reachable without an instance: tls_parse_crypto and
ssh_parse_crypto touch only skb_event.raw and skb_event.magic and use no
attribute of self, so `CryptoMon.tls_parse_crypto(None, skb)` runs with no BPF
compile, no raw socket, no root and no MongoDB. That is what lets this suite
run anywhere, and it is the property the planned cryptomon.parsers extraction
must preserve -- if a later change breaks it, these tests stop collecting.
"""
import csv
import pathlib
import types

import pytest

HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
ORACLE = HERE / "oracle"

TLS_MAGIC = 1
SSH_MAGIC = 2


def fixture_names():
    return sorted(p.stem for p in FIXTURES.glob("*.pcap"))


def skb(frame_bytes, magic=TLS_MAGIC):
    """Stand in for the ctypes SkbEvent the eBPF perf buffer delivers."""
    return types.SimpleNamespace(raw=bytes(frame_bytes), magic=magic)


def forwarded_by_ebpf(frame):
    """
    Would the kernel filter hand this frame to tls_parse_crypto?

    bpf.py only raises the TLS event when the TCP payload *starts* with a
    handshake record: payload[0] == 0x16, payload[1] == 3 and payload[2] in
    {1,2,3,4}. Feeding the parser anything else tests a path production never
    takes. The corpus contains frames where a ChangeCipherSpec record precedes
    the handshake in the same segment -- tshark decodes those, the live path
    cannot see them, and that gap belongs to the reassembly and record-walking
    work, not to these tests.
    """
    payload = tcp_payload(frame)
    return (len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 3
            and payload[2] in (1, 2, 3, 4))


def tcp_payload(frame):
    """TCP payload of an Ethernet/IPv4 frame, using the parser's own offsets."""
    eth_hdr, ip_hdr = 14, 20
    if len(frame) < eth_hdr + ip_hdr + 20:
        return b""
    tcp_hdr = (frame[eth_hdr + ip_hdr + 12] >> 4) * 4
    return frame[eth_hdr + ip_hdr + tcp_hdr:]


def read_frames(name, ebpf_gate=True):
    """
    Frames of a fixture, as raw bytes, indexed from 1 like tshark.

    By default only the frames the eBPF filter would forward, so the parser is
    judged on the input it actually receives.
    """
    scapy_all = pytest.importorskip("scapy.all")
    out = {}
    with scapy_all.PcapReader(str(FIXTURES / f"{name}.pcap")) as pr:
        for i, pkt in enumerate(pr, start=1):
            frame = bytes(pkt)
            if ebpf_gate and not forwarded_by_ebpf(frame):
                continue
            out[i] = frame
    return out


def _codepoints(cell):
    """tshark prints numeric code points; turn them into (hi, lo) tuples."""
    if not cell:
        return []
    out = []
    for raw in cell.split(","):
        raw = raw.strip()
        if not raw:
            continue
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        out.append((value >> 8 & 0xFF, value & 0xFF))
    return out


def read_oracle(name):
    """tshark's independent view of a fixture, keyed by frame number."""
    rows = {}
    with open(ORACLE / f"{name}.tsv", newline="") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            rows[int(row["frame"])] = {
                "type": int(row["type"].split(",")[0]) if row["type"] else None,
                "ciphersuites": _codepoints(row["ciphersuites"]),
                "groups": _codepoints(row["groups"]),
                "sigalgs": _codepoints(row["sigalgs"]),
                "key_share": _codepoints(row["key_share"]),
                "sni": row["sni"] or None,
            }
    return rows


@pytest.fixture(params=fixture_names())
def capture(request):
    """A fixture capture paired with tshark's view of it."""
    name = request.param
    return types.SimpleNamespace(
        name=name, frames=read_frames(name), oracle=read_oracle(name))
