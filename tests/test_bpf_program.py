"""
What can be checked about the eBPF program without a kernel.

Compiling it, loading it past the verifier and watching which framings it
forwards all need Linux, root and bcc, so they live in tests/tools/ and run
in CI and in a container. What is left here is cheap and catches the mistakes
that would otherwise only surface there.
"""
import pathlib
import re

import pytest

pytestmark = pytest.mark.smoke

BPF_SOURCE = (pathlib.Path(__file__).resolve().parent.parent
              / "cryptomon" / "bpf.py")


@pytest.fixture(scope="module")
def program():
    from cryptomon.bpf import bpf_text
    return bpf_text


def test_old_name_still_works():
    """
    bpf_ipv4_txt is what CryptoMon.__init__ defaults to and what anything
    pinned to an earlier release imports. The program is no longer IPv4-only,
    but removing the name would break those callers for nothing.
    """
    from cryptomon.bpf import bpf_ipv4_txt, bpf_text
    assert bpf_ipv4_txt is bpf_text


def test_program_is_exported_and_named(program):
    assert "crypto_monitor" in program
    assert "BPF_PERF_OUTPUT(skb_events)" in program


def test_every_loop_is_bounded(program):
    """
    The verifier rejects an unbounded loop, and a rejected program means the
    service does not start. Each loop must be a constant-bound for with an
    unroll pragma -- which is easy to lose in an edit and impossible to catch
    without a kernel.
    """
    loops = re.findall(r"for\s*\(int \w+ = 0; \w+ < (\w+);", program)
    assert loops, "no bounded loops found -- did the walk logic change?"
    for bound in loops:
        assert bound.startswith("MAX_"), (
            f"loop bound {bound!r} is not a MAX_ constant")
        assert re.search(rf"#define {bound}\s+\d+", program), (
            f"{bound} has no #define")
    assert program.count("#pragma unroll") >= len(loops)


def test_both_families_are_handled(program):
    for token in ("ETH_P_IP", "ETH_P_IPV6", "ETH_P_8021Q", "IP6_FRAGMENT"):
        assert token in program, f"{token} missing"


def test_offsets_are_computed_not_assumed(program):
    """ETH_HLEN may seed the walk, but must not be the only thing deciding
    where the network header starts."""
    assert "nh_off" in program
    assert "load_half(skb, 12)" in program, "ethertype is not read"
