"""Unit tests for GREASE handling and the never-raising code point lookups."""
import pytest

from cryptomon.data import TLS_DICT
from cryptomon.utils import (describe_codepoint, describe_codepoints,
                             is_grease, parse_sigalgs)

# Merge gate: these need no capture fixtures and run in well under a second.
pytestmark = pytest.mark.smoke

GREASE = [(v, v) for v in (0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
                           0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA)]


@pytest.mark.parametrize("value", GREASE)
def test_all_sixteen_grease_values(value):
    assert is_grease(value)


@pytest.mark.parametrize("value", [
    (0x0A, 0x1A),   # bytes differ
    (0x0B, 0x0B),   # equal but wrong low nibble
    (0xAA, 0xAB),
    (0x13, 0x01),   # TLS_AES_128_GCM_SHA256
    (0x00, 0x2F),
])
def test_near_misses_are_not_grease(value):
    assert not is_grease(value)


@pytest.mark.parametrize("value", [None, (), (1,), (1, 2, 3), "xx", 42])
def test_is_grease_never_raises(value):
    assert is_grease(value) in (True, False)


def test_unknown_keeps_its_code_point():
    # "Reserved" collapsed every unrecognised value into one bucket; the code
    # point is what lets you identify it afterwards.
    assert describe_codepoint(TLS_DICT, (0xDE, 0xAD)) == "Unknown (0xdead)"


def test_known_suite_resolves():
    assert describe_codepoint(TLS_DICT, (0x13, 0x01)) == "TLS_AES_128_GCM_SHA256"


def test_grease_dropped_from_lists_but_labelled_alone():
    got = describe_codepoints(TLS_DICT, [(0x1A, 0x1A), (0x13, 0x01)])
    assert got == ["TLS_AES_128_GCM_SHA256"]
    # A peer should never *select* GREASE, so a lone value is reported.
    assert describe_codepoint(TLS_DICT, (0x2A, 0x2A)) == "GREASE"


def test_parse_sigalgs_survives_grease():
    # Regression: this raised KeyError: 10 and lost the whole handshake.
    assert parse_sigalgs([(0x0A, 0x0A)]) == []


def test_parse_sigalgs_labels_unknown():
    assert parse_sigalgs([(0x09, 0x09)]) == ["Unknown (0x0909)"]


def test_parse_sigalgs_resolves_known():
    assert parse_sigalgs([(0x08, 0x04)]) == ["rsa_pss_rsae_sha256"]
