#!/usr/bin/env python3
"""
Attach the eBPF program to loopback and replay frames through it.

check_bpf.py proves the program compiles and passes the verifier. This proves
it forwards the frames it is supposed to: the claim of the IPv6 and VLAN work
is that packets which used to be dropped in the kernel now reach userspace,
and only a real attach can show that.

Linux, root and bcc required, so this runs in a container or in CI:

    docker run --rm --privileged -v "$PWD":/work -w /work <image> \
        python3 tests/tools/check_bpf_behaviour.py

Frames come from the committed synthetic fixtures, read with a 40-line pcap
parser so that scapy is not needed in the container.
"""
import importlib.util
import pathlib
import socket
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from check_bpf import ensure_kernel_headers, load_program_text  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SYNTHETIC = ROOT / "tests" / "fixtures" / "synthetic"
IFACE = "lo"

# fixture -> should the kernel filter forward it?
EXPECTED = {
    "plain_ipv4": True,
    "vlan": True,
    "qinq": True,
    "ip_options": True,
    "ipv6": True,
    "ipv6_extheader": True,
    "ipv6_fragment": False,      # no transport header in a non-initial fragment
    "udp": False,                # not TCP
}


def read_pcap(path):
    """First packet of a classic little-endian pcap. Enough for a fixture."""
    data = path.read_bytes()
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        raise SystemExit(f"{path}: not a little-endian classic pcap")
    caplen = struct.unpack("<I", data[24 + 8:24 + 12])[0]
    return data[40:40 + caplen]


def main():
    ensure_kernel_headers()
    from bcc import BPF

    program = BPF(text=load_program_text())
    fn = program.load_func("crypto_monitor", BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(fn, IFACE)

    seen = []
    program["skb_events"].open_perf_buffer(
        lambda cpu, data, size: seen.append(size))

    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sender.bind((IFACE, 0))

    failures = []
    for name, expected in EXPECTED.items():
        path = SYNTHETIC / f"{name}.pcap"
        if not path.is_file():
            print(f"SKIP  {name}: no fixture")
            continue
        seen.clear()
        sender.send(read_pcap(path))
        program.perf_buffer_poll(timeout=300)
        forwarded = len(seen) > 0
        ok = forwarded == expected
        verdict = "OK  " if ok else "FAIL"
        print(f"{verdict}  {name:16} forwarded={str(forwarded):5} "
              f"expected={expected}")
        if not ok:
            failures.append(name)

    if failures:
        print(f"\n{len(failures)} mismatched: {', '.join(failures)}")
        return 1
    print("\nall framings behave as intended")
    return 0


if __name__ == "__main__":
    sys.exit(main())
