"""
Robustness against malformed input.

The parsers read attacker-supplied binary. Every length field in a TLS hello
is chosen by the peer, and before this each was trusted outright: a session id
length was indexed without a check, the extension walk was driven by a
packet-supplied length, and every list loop ran for as many iterations as a
two-byte field claimed.

These tests do not check *what* is parsed -- the oracle tests do that. They
check that nothing raises, nothing hangs, and nothing reads outside the frame,
whatever bytes arrive.
"""
import time
import types

import pytest

from cryptomon import CryptoMon
from cryptomon.utils import cert_guess

from conftest import fixture_names, read_frames, skb

pytestmark = pytest.mark.smoke


def parse_both(raw):
    """Run a frame through both parsers, as get_ebpf_data would."""
    return (CryptoMon.tls_parse_crypto(None, skb(raw, 1)),
            CryptoMon.ssh_parse_crypto(None, skb(raw, 2)))


@pytest.fixture(scope="module")
def sample_frames():
    frames = []
    for name in fixture_names():
        frames.extend(list(read_frames(name).values())[:3])
    assert frames, "no fixture frames available"
    return frames


def test_truncation_at_every_length(sample_frames):
    """
    Cut each frame at every possible length. None may raise.

    This is the cheapest way to reach the off-by-one at the end of every
    nested length in the parser, and it is exactly the shape of a capture
    truncated by a snaplen.
    """
    for raw in sample_frames[:6]:
        for cut in range(len(raw) + 1):
            try:
                parse_both(raw[:cut])
            except Exception as exc:                      # pragma: no cover
                pytest.fail(f"truncated to {cut}/{len(raw)} bytes: "
                            f"{type(exc).__name__}: {exc}")


def test_every_length_field_set_to_maximum(sample_frames):
    """
    Walk a 0xffff through the frame two bytes at a time.

    A length field the parser trusts will send it far past the end of the
    buffer; the point is that it neither raises nor hangs when it does.
    """
    raw = bytearray(sample_frames[0])
    for offset in range(54, min(len(raw) - 2, 260)):
        mutated = bytearray(raw)
        mutated[offset] = 0xFF
        mutated[offset + 1] = 0xFF
        try:
            parse_both(bytes(mutated))
        except Exception as exc:                          # pragma: no cover
            pytest.fail(f"0xffff at offset {offset}: "
                        f"{type(exc).__name__}: {exc}")


def test_malformed_input_stays_fast(sample_frames):
    """
    A crafted length must not buy unbounded work.

    Without the iteration caps a two-byte field could drive tens of thousands
    of out-of-range reads per packet, at packet rate.
    """
    raw = bytearray(sample_frames[0])
    for offset in range(54, min(len(raw) - 2, 140), 2):
        raw[offset] = 0xFF
        raw[offset + 1] = 0xFF
    started = time.monotonic()
    for _ in range(50):
        parse_both(bytes(raw))
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"50 malformed frames took {elapsed:.2f}s"


@pytest.mark.parametrize("raw", [
    b"", b"\x00", b"\xff" * 14, b"\xff" * 54, b"\x00" * 600,
    bytes(range(256)) * 3,
])
def test_degenerate_inputs(raw):
    parse_both(raw)


def test_random_bytes_never_raise():
    import random
    rng = random.Random(20260922)          # fixed seed: failures reproduce
    for _ in range(400):
        length = rng.randrange(0, 700)
        parse_both(bytes(rng.randrange(256) for _ in range(length)))


# ------------------------------------------------------------- cert_guess
def test_cert_guess_does_not_read_past_the_end():
    # in_array[i+10] used to raise IndexError when the 0x0b marker landed
    # within 15 bytes of the end -- about one ClientHello in ten.
    for tail in range(1, 20):
        cert_guess([0x00] * 40 + [0x0B] + [0x00] * tail)


def test_cert_guess_marker_at_offset_zero_is_not_discarded():
    # `match = 0` meant both "not found" and "found at offset 0".
    array = [0x0B] + [0x00] * 9 + [0x30, 0x82, 0x00, 0x08, 0x30] + [0x00] * 40
    cert_guess(array)      # must not treat offset 0 as "no certificate"


def test_cert_guess_declared_length_beyond_the_frame():
    # A chain longer than the captured frame is the normal case, not an
    # anomaly: certificates routinely span several TCP segments.
    array = ([0x00] * 5 + [0x0B] + [0x00] + [0xFF, 0xFF, 0xFF]
             + [0x30, 0x82, 0xFF, 0xFF, 0x30] + [0x00] * 30)
    assert isinstance(cert_guess(array), dict)
