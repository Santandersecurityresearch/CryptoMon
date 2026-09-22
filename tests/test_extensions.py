"""
The extensions a hello carries, and what they are allowed to say.

Each extension added in PR-30 is a new walk over bytes the peer chose, with
its own nested length fields, inside a walk that already exists. Two
failures matter and they are different from each other.

The first is the ordinary one: a length field that is trusted sends the
walk off the end of the message, or round a loop that never terminates.
Every test below that feeds an absurd length is guarding one specific new
walk against exactly that, and the expected outcome is never an exception
-- it is a bounded list and a counter in PARSE_STATS.

The second is quieter and worse. These fields are read by people deciding
what to do about their TLS estate: `ech` decides whether `hostname` can be
believed, `session_ticket_len` decides whether a handshake performed a key
exchange, `cert_compression` decides whether a client could accept a
post-quantum certificate chain at all. A field that is present but wrong
is acted on; a field that is absent is not. So the tests here pin absence
as carefully as they pin values, and the parser is required to leave a key
out rather than fill it with a null or a guess.
"""
import pathlib

import pytest

from cryptomon.parsers.tls import (CLIENT_HELLO, MAX_LIST_ITEMS, SERVER_HELLO,
                                   parse_handshake, parse_hello_message,
                                   parse_tls)
from cryptomon.utils import PARSE_STATS, reset_parse_stats
from pcapscan.sessions import iter_sessions

from conftest import read_frames

pytestmark = pytest.mark.smoke

STREAMS = pathlib.Path(__file__).resolve().parent / "fixtures" / "streams"

# The fields the parser produced before PR-30, and the ones it adds. Kept as
# sets rather than checked one by one because the point is the *difference*:
# this is the before-and-after diff of the whole parser output, as a test.
# Enriching a record must not quietly rename or drop what other code already
# reads out of it.
CLIENT_FIELDS_BEFORE = {
    "EtM", "ciphersuites", "extensions", "groups", "hostname", "kex_group",
    "sigalgs", "tls_versions"}
SERVER_FIELDS_BEFORE = {
    "ciphersuite", "extensions", "kex_group", "tls_versions"}


# --------------------------------------------------------------------------
# constructed hellos
# --------------------------------------------------------------------------
def extension(ext_type, body=b""):
    return (ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body)


def sni_ext(name=b"test.invalid"):
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    return extension(0, len(entry).to_bytes(2, "big") + entry)


def alpn_ext(*names):
    listing = b"".join(bytes([len(n)]) + n for n in names)
    return extension(16, len(listing).to_bytes(2, "big") + listing)


def client_hello(extensions=b"", ciphers=(0x1301,), version=b"\x03\x03"):
    """
    A ClientHello body carrying whatever extension bytes are given.

    Returns the parsed tls dict, or {} if the hello was rejected. Everything
    before the extensions is the minimum a hello needs to be walked at all:
    the point of these tests is the extension block, so nothing else varies.
    """
    suites = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body = (version + bytes(32) + b"\x00"               # random, no session
            + len(suites).to_bytes(2, "big") + suites
            + b"\x01\x00"                               # null compression
            + len(extensions).to_bytes(2, "big") + extensions)
    return (parse_hello_message(CLIENT_HELLO, body) or {}).get("tls", {})


def server_hello(extensions=b"", cipher=0x1301, version=b"\x03\x03"):
    body = (version + bytes(32) + b"\x00"
            + cipher.to_bytes(2, "big") + b"\x00"       # cipher, compression
            + len(extensions).to_bytes(2, "big") + extensions)
    return (parse_hello_message(SERVER_HELLO, body) or {}).get("tls", {})


@pytest.fixture(autouse=True)
def _clean_stats():
    """Each test reads PARSE_STATS as its own; none inherits a count."""
    reset_parse_stats()


# --------------------------------------------------------------------------
# ALPN
# --------------------------------------------------------------------------
def test_alpn_is_a_list_of_names_in_the_order_offered():
    """
    The order is the client's preference and the first entry is what JA4
    fingerprints, so a set or a sorted list would lose information that is
    used two layers up.
    """
    assert client_hello(alpn_ext(b"h2", b"http/1.1"))["alpn"] == [
        "h2", "http/1.1"]


def test_the_server_records_the_one_protocol_it_chose():
    assert server_hello(alpn_ext(b"http/1.1"))["alpn"] == ["http/1.1"]


def test_an_alpn_list_longer_than_the_extension_holding_it_is_refused():
    """A 0xffff list length inside a two-byte body."""
    assert client_hello(extension(16, b"\xff\xff"))["alpn"] == []


def test_an_alpn_name_longer_than_its_list_keeps_the_names_before_it():
    """
    Truncation is not corruption of what came before. The names already
    read are real, and dropping them would lose the first ALPN value --
    which is the one everything downstream uses.
    """
    listing = b"\x02h2" + b"\x7fnot-this-long"
    tls = client_hello(extension(
        16, len(listing).to_bytes(2, "big") + listing))
    assert tls["alpn"] == ["h2"]
    assert PARSE_STATS["truncated_alpn"] == 1


def test_a_zero_length_alpn_extension_is_counted_not_guessed():
    assert client_hello(extension(16))["alpn"] == []
    assert PARSE_STATS["truncated_extension"] == 1


def test_empty_alpn_names_are_kept_as_empty_names():
    """
    Three zero-length names is not three missing names. It is also the
    shape that makes a length-driven loop spin forever if the walk advances
    by the name length alone.
    """
    assert client_hello(
        extension(16, b"\x00\x03\x00\x00\x00"))["alpn"] == ["", "", ""]


def test_the_alpn_list_is_bounded():
    names = [b"x"] * (MAX_LIST_ITEMS + 50)
    assert len(client_hello(alpn_ext(*names))["alpn"]) == MAX_LIST_ITEMS
    assert PARSE_STATS["alpn_cap_hit"] == 1


def test_a_non_printable_alpn_name_is_escaped_for_the_record():
    """
    Same reason as the hostname: this value reaches a CSV, a JSON document
    and a terminal, and it is the peer's bytes.
    """
    assert client_hello(alpn_ext(b"h\x002"))["alpn"] == ["h\\x002"]


# --------------------------------------------------------------------------
# encrypted_client_hello -- the one that changes what another field means
# --------------------------------------------------------------------------
def test_an_outer_client_hello_is_labelled_offered():
    assert client_hello(
        extension(65037, b"\x00" + bytes(20)))["ech"] == "offered"


def test_a_server_echoing_ech_is_labelled_accepted():
    assert server_hello(extension(65037, bytes(8)))["ech"] == "accepted"


def test_a_hello_without_ech_carries_no_ech_key_at_all():
    """
    Not 'absent', not None. A null in this field reads as "we looked and
    there was none", which is the same thing as the key being missing and
    one more value every consumer has to handle.
    """
    assert "ech" not in client_hello(sni_ext())


def test_an_inner_client_hello_in_the_clear_is_flagged_rather_than_trusted():
    """
    The inner hello is by definition the encrypted one. A plaintext
    ClientHelloInner is either a broken client or something pretending to
    be one, and either way its server_name is not what it appears to be.
    """
    tls = client_hello(extension(65037, b"\x01"))
    assert tls["ech"] == "inner"
    assert PARSE_STATS["ech_inner_in_the_clear"] == 1


@pytest.mark.parametrize("body", [b"", b"\x07"])
def test_an_unreadable_ech_extension_says_so(body):
    tls = client_hello(extension(65037, body))
    assert tls["ech"] == "malformed"
    assert PARSE_STATS["malformed_ech"] == 1


def test_a_real_hello_offering_ech_is_recognised():
    """
    465 of the 1260 sessions in the corpus offer ECH. If this stopped
    working, the hostname column would go on being printed with no
    indication that a third of it may be an outer name.
    """
    frames = read_frames("edge_win11")
    assert parse_tls(frames[1])["tls"]["ech"] == "offered"


# --------------------------------------------------------------------------
# pre_shared_key and the resumption signals
# --------------------------------------------------------------------------
def test_a_client_offering_a_psk_is_not_a_client_resuming():
    """
    Presence on the client side is an offer and nothing more; the server's
    echo is what makes it a resumption. Recording the offer as the answer
    would count every hello that carries a ticket as a session that
    performed no key exchange.
    """
    assert client_hello(extension(41, bytes(40)))["psk_offered"] is True
    assert "psk_selected" not in client_hello(extension(41, bytes(40)))


def test_the_server_records_which_identity_it_selected():
    assert server_hello(extension(41, b"\x00\x02"))["psk_selected"] == 2


def test_a_truncated_psk_selection_is_counted_not_invented():
    """Index 0 is a real answer, so it cannot stand for "no answer"."""
    tls = server_hello(extension(41, b"\x00"))
    assert "psk_selected" not in tls
    assert PARSE_STATS["truncated_extension"] == 1


def test_the_psk_modes_are_named():
    assert client_hello(extension(45, b"\x02\x00\x01"))["psk_modes"] == [
        "psk_ke", "psk_dhe_ke"]


def test_an_unknown_psk_mode_keeps_its_number():
    tls = client_hello(extension(45, b"\x01\x09"))
    assert tls["psk_modes"] == ["Unknown (0x09)"]
    assert PARSE_STATS["unknown_psk_mode"] == 1


def test_a_psk_mode_list_longer_than_its_extension_is_clamped():
    assert client_hello(extension(45, b"\xff\x01"))["psk_modes"] == [
        "psk_dhe_ke"]


def test_real_hellos_carry_the_psk_signals():
    """
    teams_win11 frame 1 offers a PSK and frame 2 is the server accepting
    identity 0 -- a resumed TLS 1.3 session, which performed no key
    exchange of its own.
    """
    frames = read_frames("teams_win11")
    assert parse_tls(frames[1])["tls"]["psk_offered"] is True
    assert parse_tls(frames[2])["tls"]["psk_selected"] == 0


# --------------------------------------------------------------------------
# session_ticket
# --------------------------------------------------------------------------
def test_an_empty_session_ticket_is_a_request_not_a_resumption():
    """
    Zero is the answer, and it is not the same answer as absent: an empty
    session_ticket asks the server for one, a missing extension does not
    ask at all.
    """
    tls = client_hello(extension(35))
    assert tls["session_ticket_len"] == 0
    assert "session_ticket_len" not in client_hello(sni_ext())


def test_a_ticket_bearing_hello_records_its_length():
    assert client_hello(
        extension(35, bytes(192)))["session_ticket_len"] == 192


def test_a_ticket_longer_than_the_capture_is_reported_as_declared():
    """
    The declared length is what the peer says it is holding, and a capture
    cut short should not read as a shorter ticket. The discrepancy is
    counted so that it is visible rather than inferred.
    """
    hostile = b"\x00\x23\xff\xff" + bytes(4)
    tls = client_hello(sni_ext() + hostile)
    assert tls["session_ticket_len"] == 0xFFFF
    assert PARSE_STATS["truncated_session_ticket"] == 1


# --------------------------------------------------------------------------
# signature_algorithms_cert and compress_certificate
# --------------------------------------------------------------------------
def test_certificate_signature_algorithms_are_named_like_the_others():
    """
    Reusing parse_sigalgs is the point: two spellings of the same code
    point in one record would be read as two different algorithms by the
    inventory.
    """
    assert client_hello(
        extension(50, b"\x00\x04\x04\x03\x08\x04"))["sigalgs_cert"] == [
            "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]


def test_an_oversized_certificate_sigalg_list_is_clamped_to_what_is_there():
    assert len(client_hello(
        extension(50, b"\xff\xff\x04\x03"))["sigalgs_cert"]) == 1


def test_a_real_hello_distinguishes_certificate_signature_algorithms():
    """
    212 sessions in the corpus send a different list for certificates than
    for the handshake signature. Where they differ, this is the one that
    says which CA the client can accept.
    """
    tls = parse_tls(read_frames("pcapng_sample")[1])["tls"]
    assert tls["sigalgs_cert"][:2] == ["ecdsa_secp256r1_sha256",
                                       "ecdsa_secp384r1_sha384"]


def test_certificate_compression_algorithms_are_named():
    assert client_hello(
        extension(27, b"\x06\x00\x01\x00\x02\x00\x03")
    )["cert_compression"] == ["zlib", "brotli", "zstd"]


def test_an_unknown_compression_algorithm_keeps_its_code_point():
    tls = client_hello(extension(27, b"\x02\x00\x09"))
    assert tls["cert_compression"] == ["Unknown (0x0009)"]
    assert PARSE_STATS["unknown_cert_compression"] == 1


def test_an_oversized_compression_list_is_clamped():
    assert client_hello(
        extension(27, b"\xff\x00\x02"))["cert_compression"] == ["brotli"]


# --------------------------------------------------------------------------
# nothing new may raise, and nothing old may change
# --------------------------------------------------------------------------
def every_new_extension():
    return (sni_ext() + alpn_ext(b"h2", b"http/1.1")
            + extension(27, b"\x02\x00\x02")
            + extension(35, bytes(16))
            + extension(41, bytes(8))
            + extension(45, b"\x01\x01")
            + extension(50, b"\x00\x02\x08\x04")
            + extension(65037, b"\x00" + bytes(12)))


def test_a_hello_cut_at_every_offset_never_raises():
    """
    The bound the walks are given shrinks while the lengths inside the
    message stay as they were, which is what a snaplen-truncated capture
    looks like and what every new length field here has to survive.
    """
    suites = b"\x13\x01"
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02" + suites
            + b"\x01\x00"
            + len(every_new_extension()).to_bytes(2, "big")
            + every_new_extension())
    buf = bytes([CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    for cut in range(len(buf) + 1):
        try:
            parse_handshake(buf, 0, cut)
        except Exception as exc:                          # pragma: no cover
            pytest.fail("cut at {0}/{1}: {2}: {3}".format(
                cut, len(buf), type(exc).__name__, exc))


def test_the_new_fields_are_exactly_the_new_fields():
    """
    The before-and-after diff of the parser, pinned.

    PR-30 adds keys to a dict that pcapscan.sessions copies wholesale into
    every session record, which the CBOM, the CSV and the stored documents
    are all built from. Adding to it is safe; renaming, dropping or
    changing anything already in it is not, and the difference is invisible
    unless something checks.
    """
    record = next(iter(iter_sessions(STREAMS / "tls13_hello_retry.pcap")))
    proposed, selected = record["tls"]["proposed"], record["tls"]["selected"]
    assert CLIENT_FIELDS_BEFORE <= set(proposed)
    assert set(proposed) - CLIENT_FIELDS_BEFORE == {
        "alpn", "cert_compression", "ech", "ja3", "ja4", "psk_modes",
        "session_ticket_len"}
    assert SERVER_FIELDS_BEFORE <= set(selected)
    assert set(selected) - SERVER_FIELDS_BEFORE == {"ja4s"}


def test_the_values_of_the_existing_fields_are_unchanged():
    """
    The same record, field by field, as it read before PR-30. A parser
    change that shifted an offset by one would still produce a plausible
    hostname and a plausible group; this is what says it produced the same
    ones.
    """
    record = next(iter(iter_sessions(STREAMS / "tls13_hello_retry.pcap")))
    proposed, selected = record["tls"]["proposed"], record["tls"]["selected"]
    assert proposed["hostname"] == "cdn.bizible.com"
    assert proposed["kex_group"] == "X25519Kyber768Draft00"
    assert proposed["tls_versions"] == ["TLSv1.3", "TLSv1.2"]
    assert proposed["EtM"] is False
    assert len(proposed["ciphersuites"]) == 15
    assert proposed["groups"] == ["X25519Kyber768Draft00", "x25519",
                                  "secp256r1", "secp384r1"]
    assert proposed["sigalgs"][0] == "ecdsa_secp256r1_sha256"
    assert selected["ciphersuite"] == "TLS_AES_256_GCM_SHA384"
    assert selected["kex_group"] == "secp256r1"
    assert selected["tls_versions"] == ["TLSv1.3"]
