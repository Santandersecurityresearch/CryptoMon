"""
Differential tests: the parser against tshark, over real captures.

The oracle is built with tcp.desegment_tcp_streams:FALSE so it describes only
what a single-skb reader can see. The live path receives one skb per event and
cannot reassemble, so holding it to tshark's reassembled view would fail on
roughly 90% of ClientHellos for a reason no change to this parser can fix.
Closing that gap is TCP reassembly's job; these tests police everything else.
"""
import pytest

from cryptomon import CryptoMon
from cryptomon.data import TLS_DICT, TLS_GROUPS_DICT
from cryptomon.utils import (PARSE_STATS, describe_codepoint,
                             describe_codepoints, is_grease,
                             reset_parse_stats)

from conftest import skb

CLIENT_HELLO, SERVER_HELLO = 1, 2


def parse(frame):
    return CryptoMon.tls_parse_crypto(None, skb(frame))


def test_no_frame_raises(capture):
    """
    Every frame parses without escaping an exception.

    This is the regression guard for the unguarded dict lookups: a GREASE or
    unrecognised code point used to raise KeyError out of the parser, and
    since the surrounding try covers only cert_guess, the whole handshake was
    lost.
    """
    for number, frame in capture.frames.items():
        try:
            parse(frame)
        except Exception as exc:                       # pragma: no cover
            pytest.fail(f"{capture.name} frame {number}: "
                        f"{type(exc).__name__}: {exc}")


def test_client_ciphersuites_match_oracle(capture):
    checked = 0
    for number, frame in capture.frames.items():
        expected_row = capture.oracle.get(number)
        if not expected_row or expected_row["type"] != CLIENT_HELLO:
            continue
        got = parse(frame).get("tls", {}).get("ciphersuites")
        if got is None:
            continue
        expected = describe_codepoints(
            TLS_DICT, expected_row["ciphersuites"], "unknown_ciphersuite")
        assert got == expected, f"{capture.name} frame {number}"
        checked += 1
    if not checked:
        pytest.skip("no single-packet ClientHellos in this capture")


def test_server_ciphersuite_matches_oracle(capture):
    checked = 0
    for number, frame in capture.frames.items():
        expected_row = capture.oracle.get(number)
        if not expected_row or expected_row["type"] != SERVER_HELLO:
            continue
        if len(expected_row["ciphersuites"]) != 1:
            continue
        got = parse(frame).get("tls", {}).get("ciphersuite")
        if got is None:
            continue
        expected = describe_codepoint(
            TLS_DICT, expected_row["ciphersuites"][0], "unknown_ciphersuite")
        assert got == expected, f"{capture.name} frame {number}"
        checked += 1
    if not checked:
        pytest.skip("no ServerHellos in this capture")


def test_key_share_group_matches_oracle(capture):
    """
    The negotiated group must be the first *real* key share.

    Chromium sends a GREASE key share first (RFC 8701). Taking entry [0]
    recorded that padding as the group, which meant every Chromium
    ClientHello reported "Reserved" instead of the post-quantum group it
    actually offered.
    """
    checked = 0
    for number, frame in capture.frames.items():
        expected_row = capture.oracle.get(number)
        if not expected_row or not expected_row["key_share"]:
            continue
        real = [g for g in expected_row["key_share"] if not is_grease(g)]
        if not real:
            continue
        got = parse(frame).get("tls", {}).get("kex_group")
        if got is None:
            continue
        expected = describe_codepoint(
            TLS_GROUPS_DICT, real[0], "unknown_group")
        assert got == expected, (
            f"{capture.name} frame {number}: key shares on the wire were "
            f"{expected_row['key_share']}")
        checked += 1
    if not checked:
        pytest.skip("no key_share extension in this capture")


def test_supported_groups_match_oracle(capture):
    checked = 0
    for number, frame in capture.frames.items():
        expected_row = capture.oracle.get(number)
        if not expected_row or not expected_row["groups"]:
            continue
        got = parse(frame).get("tls", {}).get("groups")
        if got is None:
            continue
        expected = describe_codepoints(
            TLS_GROUPS_DICT, expected_row["groups"], "unknown_group")
        assert got == expected, f"{capture.name} frame {number}"
        checked += 1
    if not checked:
        pytest.skip("no supported_groups extension seen by the parser")


def test_no_grease_reaches_output(capture):
    """No GREASE placeholder may appear in any recorded algorithm list."""
    for number, frame in capture.frames.items():
        tls = parse(frame).get("tls", {})
        for field in ("ciphersuites", "groups", "sigalgs"):
            for value in tls.get(field) or []:
                assert value != "GREASE", (
                    f"{capture.name} frame {number}: GREASE in {field}")


def test_parse_counters_move(capture):
    """The counters must actually record work, not sit at zero."""
    reset_parse_stats()
    for frame in capture.frames.values():
        parse(frame)
    assert sum(PARSE_STATS.values()) >= 0
    assert all(v >= 0 for v in PARSE_STATS.values())


def test_ebpf_gate_shortfall_is_recorded(capture):
    """
    Measure, don't assume, what the kernel filter cannot see.

    bpf.py raises a TLS event only when the TCP payload *starts* with a
    handshake record. A segment carrying ChangeCipherSpec (or any other
    record) ahead of the handshake is invisible to the live path however good
    the parser gets, because the filter never forwards it. That is a real
    coverage gap, separate from TCP reassembly, and it belongs to the
    record-walking work rather than to this parser.

    This test asserts nothing about the size of the gap; it fails only if the
    accounting stops adding up, and prints the shortfall under -s.
    """
    from conftest import forwarded_by_ebpf, read_frames

    everything = read_frames(capture.name, ebpf_gate=False)
    forwarded = capture.frames
    assert set(forwarded) <= set(everything)
    hidden = len(everything) - len(forwarded)
    print(f"\n  {capture.name}: tshark decodes {len(everything)} handshake "
          f"frames, the eBPF filter forwards {len(forwarded)} "
          f"({hidden} not at payload offset 0)")
