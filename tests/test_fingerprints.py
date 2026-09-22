"""
JA4, JA4S and JA3: the strings have to be the *same* strings.

A fingerprint is only worth computing if it agrees with everybody else's.
Its entire use is joining: this capture against last month's, this network
against a public database, this hello against the one somebody published in
an incident report. An implementation that is internally consistent and
externally wrong produces 36 characters that look exactly right, match
nothing, and are believed anyway -- which is worse than not computing them.

So these tests are mostly golden values, of three kinds:

  * Hand-built hellos where the expected string was worked out from the
    specification by hand, and only the sha256 was left to a machine. These
    pin the parts of the format that are easy to read past: that the
    extension *count* includes server_name and ALPN while the extension
    *hash* excludes them, that the signature algorithms go in unsorted
    after an underscore, that the version comes from supported_versions
    rather than from the header.
  * Values checked against ones published outside this project entirely,
    which is the only evidence available that this is the same algorithm
    and not merely a self-consistent one. FoxIO publish
    `t130200_1301_a56c5b993250` as the JA4S of Sliver's implant server, and
    this parser produces that string in full from a hello built here.
    FoxIO also publish `t13d1516h2_8daaf6152771_...` for Chrome, and the
    Chrome capture in tests/fixtures/streams reproduces those first two
    parts exactly -- counts and cipher hash. The third part is a hash of
    the extension set, which differs between Chrome builds, so it is
    pinned here as a regression value and not as an external match.
  * The real fixtures, pinned, so that a change to the parser that shifts a
    code point by one byte fails here rather than silently renaming every
    client on the network.

And one test that is not about correctness: that JA4 clusters. A
fingerprint where every session is unique is not identifying clients, and
it is the failure mode that looks like success.
"""
import pathlib

import pytest

from cryptomon.fingerprints import alpn_label, ja3, ja4, ja4s, version_label
from cryptomon.parsers.tls import parse_tls
from pcapscan.sessions import iter_sessions

from conftest import read_frames
from test_extensions import (alpn_ext, client_hello, extension, server_hello,
                             sni_ext)

pytestmark = pytest.mark.smoke

STREAMS = pathlib.Path(__file__).resolve().parent / "fixtures" / "streams"

GREASE_CIPHER = 0x0A0A
GREASE_EXTENSION = 0x1A1A

SUPPORTED_VERSIONS_13 = extension(43, b"\x02\x03\x04")
SIGALGS = extension(13, b"\x00\x04\x04\x03\x08\x04")
SUPPORTED_GROUPS = extension(10, b"\x00\x04\x00\x1d\x00\x17")
EC_POINT_FORMATS = extension(11, b"\x01\x00")


def full_hello(**kwargs):
    """
    A TLS 1.3 hello offering three ciphers and four extensions.

    JA4: transport t, version 13 (from supported_versions, not from the
    0x0303 in the header), SNI present so d, three ciphers after GREASE is
    dropped so 03, four extensions after GREASE is dropped -- 0, 16, 43, 13
    -- so 04, and ALPN h2.
      ja4_b = sha256("1301,1302,c02f")
      ja4_c = sha256("000d,002b_0403,0804"), which is the extensions minus
              server_name and ALPN, sorted, then the signature algorithms in
              the order the client sent them.
    """
    return client_hello(
        sni_ext() + alpn_ext(b"h2") + SUPPORTED_VERSIONS_13 + SIGALGS,
        ciphers=(GREASE_CIPHER, 0x1301, 0x1302, 0xC02F), **kwargs)


FULL_HELLO_JA4 = "t13d0304h2_40b44b994229_ef5f37ab036a"


# --------------------------------------------------------------------------
# golden values, built by hand
# --------------------------------------------------------------------------
def test_a_hand_built_hello_produces_the_hand_computed_fingerprint():
    assert full_hello()["ja4"] == FULL_HELLO_JA4


def test_a_bare_hello_without_sni_or_alpn_says_so():
    """
    'i' for an IP-addressed connection and '00' for no ALPN, and the count
    of one extension, which is the signature_algorithms that is still in
    the hash. The version falls back to the header because there is no
    supported_versions extension to prefer.
      ja4_b = sha256("c02f"), ja4_c = sha256("000d_0403")
    """
    tls = client_hello(extension(13, b"\x00\x02\x04\x03"), ciphers=(0xC02F,))
    assert tls["ja4"] == "t12i010100_f06271c2b022_79c50902419d"


def test_the_extension_count_includes_sni_and_alpn_but_the_hash_does_not():
    """
    The asymmetry in the specification, stated directly, because it is the
    single easiest thing to get wrong: four extensions are counted and two
    are hashed. Getting this wrong shifts every fingerprint by two and
    matches nothing anyone has published.
    """
    counted = full_hello()["ja4"]
    assert counted[6:8] == "04"
    without = client_hello(SUPPORTED_VERSIONS_13 + SIGALGS,
                           ciphers=(0x1301, 0x1302, 0xC02F))["ja4"]
    assert without[6:8] == "02"
    # Same two hashed extensions and the same signature algorithms, so the
    # third part is identical either way.
    assert without.split("_")[2] == counted.split("_")[2]


def test_grease_changes_neither_the_counts_nor_the_hashes():
    """
    GREASE is padding whose only purpose is to be ignored (RFC 8701).
    Chrome and Edge send it in the ciphers, the extensions, the groups and
    the versions, so a fingerprint that counted it would give every
    Chromium build a value nobody else computes.
    """
    greased = client_hello(
        sni_ext() + alpn_ext(b"h2") + SUPPORTED_VERSIONS_13 + SIGALGS
        + extension(GREASE_EXTENSION),
        ciphers=(GREASE_CIPHER, 0x1301, 0x1302, 0xC02F))
    plain = client_hello(
        sni_ext() + alpn_ext(b"h2") + SUPPORTED_VERSIONS_13 + SIGALGS,
        ciphers=(0x1301, 0x1302, 0xC02F))
    assert greased["ja4"] == plain["ja4"] == FULL_HELLO_JA4


def test_the_same_hello_twice_is_the_same_fingerprint():
    """
    Nothing in the string may depend on dict ordering, on a set, or on
    anything else that is free to vary between two runs of one process.
    """
    assert full_hello()["ja4"] == full_hello()["ja4"]


def test_the_cipher_count_saturates_rather_than_overflowing():
    """
    Two digits is two digits. A hello offering 150 ciphers is not a
    browser, and whatever it is, its fingerprint still has to be 36
    characters long.
    """
    many = tuple(range(0x0100, 0x0100 + 150))
    tls = client_hello(extension(13, b"\x00\x02\x04\x03"), ciphers=many)
    assert tls["ja4"].startswith("t12i990100_")


def test_the_version_comes_from_supported_versions_not_from_the_header():
    """
    Every TLS 1.3 hello writes 0x0303 in the header for the benefit of
    middleboxes. Reading that would label the entire corpus TLS 1.2.
    """
    assert full_hello()["ja4"].startswith("t13")
    assert full_hello()["tls_versions"] == ["TLSv1.3"]


def test_the_highest_offered_version_wins():
    assert version_label([0x0303, 0x0304, 0x0A0A]) == "13"
    assert version_label([0x0A0A], legacy=0x0301) == "10"
    assert version_label(names=["TLSv1.3", "TLSv1.2"]) == "13"
    assert version_label([0x0999]) == "00"


# --------------------------------------------------------------------------
# the ALPN characters
# --------------------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    (b"h2", "h2"),
    (b"http/1.1", "h1"),
    (b"h", "hh"),
    (b"", "00"),
    (None, "00"),
    (b"spdy/3.1", "s1"),
    # Not alphanumeric at one end, so the hex form of the whole value:
    # 0xab 0xcd is "abcd", first and last of that is "ad".
    (b"\xab\xcd", "ad"),
    (b"\x20\x61", "21"),
    (b"\x30\xab", "3b"),
])
def test_the_alpn_characters(value, expected):
    assert alpn_label(value) == expected


def test_no_alpn_extension_is_two_zeroes_rather_than_an_omission():
    """Fixed width: leaving it out would shift everything after it."""
    tls = client_hello(sni_ext() + SUPPORTED_VERSIONS_13 + SIGALGS,
                       ciphers=(0x1301,))
    assert tls["ja4"][8:10] == "00"


# --------------------------------------------------------------------------
# JA4S
# --------------------------------------------------------------------------
def test_the_server_fingerprint_matches_a_published_one():
    """
    FoxIO publish `t130200_1301_a56c5b993250` as the JA4S of Sliver's
    implant server: TLS 1.3, two extensions, no ALPN, TLS_AES_128_GCM_SHA256
    and the hash of supported_versions and key_share in that order. This
    parser produces the same string from a hello built here, which is the
    only external check available that it is the same algorithm.
    """
    tls = server_hello(extension(43, b"\x03\x04") + extension(51, bytes(4)))
    assert tls["ja4s"] == "t130200_1301_a56c5b993250"


def test_the_server_extension_order_is_part_of_the_fingerprint():
    """
    Not sorted, unlike the client's. Which order a server lists its
    extensions in is a property of its implementation rather than of the
    client's request, so sorting would throw away the signal. Both of these
    occur in the corpus -- 177 sessions with 43 before 51, 123 with 51
    before 43 -- and they are different servers.
    """
    forwards = server_hello(
        extension(43, b"\x03\x04") + extension(51, bytes(4)))
    backwards = server_hello(
        extension(51, bytes(4)) + extension(43, b"\x03\x04"))
    assert backwards["ja4s"] == "t130200_1301_234ea6891581"
    assert forwards["ja4s"] != backwards["ja4s"]


def test_the_server_writes_its_chosen_cipher_rather_than_hashing_it():
    """One value does not need a hash, and the hex is readable."""
    tls = server_hello(extension(43, b"\x03\x04"), cipher=0xC02F)
    assert tls["ja4s"].split("_")[1] == "c02f"


def test_a_server_that_chose_an_alpn_records_it():
    tls = server_hello(alpn_ext(b"http/1.1") + extension(43, b"\x03\x04"))
    assert tls["ja4s"].startswith("t1302h1_")


# --------------------------------------------------------------------------
# real captures
# --------------------------------------------------------------------------
def test_the_stream_fixtures_fingerprint_as_expected():
    """
    Three whole conversations, pinned end to end.

    The first is Chrome, and its first two parts -- t13d1516h2 and the
    cipher hash 8daaf6152771 -- are the ones FoxIO publish for Chrome. The
    second and third are Firefox, whose published cipher hash is likewise
    5b57614c22b0. Two independent implementations agreeing on the same
    browsers is the check; the rest of each string is pinned against this
    parser changing under itself.
    """
    expected = {
        "tls13_hello_retry.pcap": ("t13d1516h2_8daaf6152771_02713d6af862",
                                   "t130200_1302_a56c5b993250"),
        "tls12_certificate.pcap": ("t13d1716h2_5b57614c22b0_eeeea6562960",
                                   "t1205h1_c02f_845f7282a956"),
        "tls12_split_certificate.pcap": (
            "t13d1716h2_5b57614c22b0_eeeea6562960",
            "t1205h1_c02f_845f7282a956"),
    }
    for name, (client, server) in expected.items():
        record = next(iter(iter_sessions(STREAMS / name)))
        assert record["tls"]["proposed"]["ja4"] == client, name
        assert record["tls"]["selected"]["ja4s"] == server, name


def test_ja4_clusters_where_ja3_does_not():
    """
    The reason JA4 exists, measured on a committed capture.

    Thirteen ClientHellos from one Edge installation produce thirteen
    distinct JA3 values -- Chromium shuffles its extension order on every
    connection, and JA3 hashes that order -- and three distinct JA4 values,
    which is the number of genuinely different hellos Edge sends. A
    fingerprint that gave thirteen answers to "which client is this" would
    look like it was working.
    """
    hellos = [parse_tls(frame).get("tls", {})
              for frame in read_frames("edge_win11").values()]
    ja4s_seen = {tls["ja4"] for tls in hellos if "ja4" in tls}
    ja3s_seen = {tls["ja3"] for tls in hellos if "ja3" in tls}
    assert len(ja3s_seen) == 13
    assert len(ja4s_seen) == 3


# --------------------------------------------------------------------------
# JA3, and what it is allowed to be trusted for
# --------------------------------------------------------------------------
def test_the_ja3_string_is_the_one_everybody_else_builds():
    """
    md5("771,4865-4866-49199,0-16-43-13-10-11,29-23,0"): the legacy
    version, the ciphers, the extensions in wire order, the groups and the
    point formats, each dash-joined, GREASE dropped throughout. Pinned
    because the only reason to compute JA3 at all is to join against tools
    that compute it this way.
    """
    tls = client_hello(
        sni_ext() + alpn_ext(b"h2") + SUPPORTED_VERSIONS_13 + SIGALGS
        + SUPPORTED_GROUPS + EC_POINT_FORMATS + extension(GREASE_EXTENSION),
        ciphers=(GREASE_CIPHER, 0x1301, 0x1302, 0xC02F))
    assert tls["ja3"] == "98dfec3c2d1916763dace28c8bdcb59a"


# --------------------------------------------------------------------------
# refusing rather than guessing
# --------------------------------------------------------------------------
def test_without_the_raw_code_points_there_is_no_fingerprint():
    """
    The ciphersuites in a parsed record are names, and only the names this
    installation's table happens to know. Recovering code points from them
    would make the fingerprint depend on the table, so two deployments
    would disagree about the same packet -- which is the one thing an
    identifier may not do. None is the honest answer.
    """
    parsed = full_hello()
    assert ja4(parsed) is None
    assert ja3(parsed) is None
    assert ja4s(parsed) is None


def test_a_fingerprint_that_cannot_be_computed_is_absent_not_null():
    """A null would read as "this client has no JA4"."""
    tls = server_hello(extension(43, b"\x03\x04"))
    assert "ja4" not in tls and "ja3" not in tls
    assert tls["ja4s"] is not None
