"""
The IKEv2 handler, and the two claims it has to earn.

**Every number here comes from a fixture.** There is no IKEv2 anywhere in this
project's capture corpus -- zero packets on UDP 500 or 4500 and zero of IP
protocol 50 across all 160,221 packets -- so unlike `test_parsers_vs_oracle`
there is no independent decoder and no real traffic to check against. The
captures in `tests/fixtures/ikev2/` were written from RFC 7296's field layouts
by `tests/tools/make_ikev2_fixtures.py`, and the risk that carries is obvious:
a parser and its fixtures written by the same hand agree with each other by
construction. Three things are done about it rather than hoped about it.

  * The bytes are built from the specification's field order, not from what
    the parser reads. `make_ikev2_fixtures.py` never imports `pcapscan.ikev2`.
  * The vendor-ID table is checked against its own derivation: those constants
    are the MD5 of published strings, and `test_vendor_ids_are_the_md5_of_...`
    recomputes them. That is a real external check, small as it is.
  * Most of the file is not about the happy path at all. It is about what the
    parser does with lengths that lie, chains that loop, attributes that run
    past their transform and an ESP packet arriving where an IKE header is
    expected -- none of which a fixture built to match would ever produce.

The malformed cases are written as bytes in the test rather than committed as
captures, because a fixture is for something a real peer might send and these
are for things only an attacker would.
"""
import importlib.util
import json
import os
import pathlib
import struct

import pytest

os.environ.setdefault("DB_URL", "mongodb://127.0.0.1:27017")
os.environ.setdefault("DB_NAME", "cryptomon_test")

from cryptomon.analysis import (CLASSICAL, HYBRID, POST_QUANTUM, SYMMETRIC,
                                UNKNOWN, analyse, classify_algorithm,
                                symmetric_label)
from cryptomon.utils import PARSE_STATS, reset_parse_stats
from pcapscan import ikev2
from pcapscan.datagrams import DatagramKey, DatagramRouter, handlers
from pcapscan.ikev2 import (ENCR_TRANSFORMS, HANDLER, IKE_HDR_LEN, KE_GROUPS,
                            NON_ESP_MARKER, VENDOR_IDS, Ikev2Handler,
                            algorithms_of, classify_datagram,
                            combined_key_exchange, describe_vendor_id,
                            key_exchange_name, parse_attributes, parse_header,
                            parse_message, parse_notify, parse_sa,
                            transform_name, walk_payloads)
from pcapscan.sessions import iter_sessions

from fuzzing import mutate, seeded

HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "ikev2"
TOOL = HERE / "tools" / "make_ikev2_fixtures.py"

ISPI = bytes.fromhex("1122334455667788")
RSPI = bytes.fromhex("99aabbccddeeff00")
ZERO_SPI = b"\x00" * 8

P_SA, P_KE, P_NONCE, P_NOTIFY, P_VID = 33, 34, 40, 41, 43
X_SA_INIT, X_AUTH = 34, 35
F_INITIATOR, F_RESPONSE = 0x08, 0x20


# --------------------------------------------------------------------------
# builders -- deliberately independent of the fixture generator, so that a
# mistake shared between the parser and one builder is not shared with both
# --------------------------------------------------------------------------
def payload_chain(items):
    blob, first = b"", 0
    for ptype, body in reversed(items):
        blob = (bytes([first, 0]) + struct.pack(">H", 4 + len(body)) + body
                + blob)
        first = ptype
    return first, blob


def message(items, ispi=ISPI, rspi=ZERO_SPI, exchange=X_SA_INIT,
            flags=F_INITIATOR, message_id=0, major=2, length=None):
    first, blob = payload_chain(items)
    total = IKE_HDR_LEN + len(blob) if length is None else length
    return (ispi + rspi + bytes([first, major << 4, exchange, flags])
            + struct.pack(">II", message_id, total) + blob)


def transform(ttype, tid, last, key_length=None):
    attributes = b""
    if key_length is not None:
        attributes = struct.pack(">HH", 0x8000 | 14, key_length)
    return (bytes([0 if last else 3, 0])
            + struct.pack(">H", 8 + len(attributes))
            + bytes([ttype, 0]) + struct.pack(">H", tid) + attributes)


def proposal(transforms, number=1, protocol=1, spi=b"", last=True,
             declared=None):
    body = b"".join(transforms)
    count = len(transforms) if declared is None else declared
    return (bytes([0 if last else 2, 0])
            + struct.pack(">H", 8 + len(spi) + len(body))
            + bytes([number, protocol, len(spi), count]) + spi + body)


def simple_sa():
    return proposal([transform(1, 12, False, key_length=256),
                     transform(2, 5, False),
                     transform(3, 12, False),
                     transform(4, 19, True)])


def sa_init_request(sa=None, extra=()):
    return message([(P_SA, sa if sa is not None else simple_sa()),
                    (P_KE, struct.pack(">HH", 19, 0) + bytes(64)),
                    (P_NONCE, bytes(32))] + list(extra))


KEY = DatagramKey("10.0.0.1", 500, "10.0.0.2", 500)
KEY_4500 = DatagramKey("10.0.0.1", 4500, "10.0.0.2", 4500)
KEY_53 = DatagramKey("10.0.0.1", 55000, "10.0.0.2", 53)


# --------------------------------------------------------------------------
# the header, and what makes a flow claimable
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_header_fields_are_read_at_rfc_7296_offsets():
    raw = sa_init_request()
    header = parse_header(raw)
    assert header["initiator_spi"] == ISPI.hex()
    assert header["responder_spi"] == ZERO_SPI.hex()
    assert (header["major"], header["minor"]) == (2, 0)
    assert header["exchange_type"] == X_SA_INIT
    assert header["initiator"] is True and header["response"] is False
    assert header["length"] == len(raw)
    assert header["plausible"] is True


@pytest.mark.smoke
def test_detect_claims_a_real_ike_sa_init():
    assert HANDLER.detect(sa_init_request(), KEY) is True


@pytest.mark.smoke
@pytest.mark.parametrize("payload", [
    b"",
    b"\x00" * IKE_HDR_LEN,
    b"\x16\x03\x01\x02\x00\x01",                 # a TLS record
    bytes(range(IKE_HDR_LEN)),
    b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",   # a DNS query
    b"A" * 1200,
])
def test_detect_refuses_what_is_not_ike(payload):
    assert HANDLER.detect(payload, KEY) is False


@pytest.mark.smoke
def test_a_length_that_disagrees_with_the_datagram_is_refused():
    """
    The strongest of the seven header checks, and the one doing the work.

    IKE carries the total message length in its own header and a UDP datagram
    carries exactly one message, so the two must agree. Without this check
    almost any 28 well-chosen bytes would claim a UDP flow.
    """
    raw = sa_init_request()
    assert HANDLER.detect(raw, KEY) is True
    assert HANDLER.detect(raw + b"\x00", KEY) is False
    assert HANDLER.detect(raw[:-1], KEY) is False


@pytest.mark.smoke
def test_a_zero_initiator_spi_is_refused():
    """RFC 7296 section 3.1: the initiator's SPI "MUST NOT be zero"."""
    assert HANDLER.detect(sa_init_request(), KEY) is True
    assert parse_header(message([(P_NONCE, bytes(32))],
                                ispi=ZERO_SPI))["plausible"] is False


@pytest.mark.smoke
def test_an_sa_init_request_naming_a_responder_spi_is_refused():
    """
    The first message of an exchange asks the responder to choose an SPI, so
    it cannot already know one. Eight arbitrary bytes at offset 8 are what a
    non-IKE datagram most often has there.
    """
    raw = message([(P_NONCE, bytes(32))], rspi=RSPI)
    assert parse_header(raw)["plausible"] is False
    # ...but the *response* legitimately carries one.
    raw = message([(P_NONCE, bytes(32))], rspi=RSPI, flags=F_RESPONSE)
    assert parse_header(raw)["plausible"] is True


@pytest.mark.smoke
def test_reserved_flag_bits_must_be_zero():
    for flags in (F_INITIATOR | 0x01, F_INITIATOR | 0x80, 0xFF):
        raw = message([(P_NONCE, bytes(32))], flags=flags)
        assert parse_header(raw)["plausible"] is False, hex(flags)


@pytest.mark.smoke
def test_an_unassigned_exchange_type_is_refused():
    raw = message([(P_NONCE, bytes(32))], exchange=99)
    assert parse_header(raw)["plausible"] is False


@pytest.mark.smoke
def test_a_first_payload_outside_the_ikev2_range_is_refused():
    raw = bytearray(sa_init_request())
    raw[16] = 7                                  # not an IKEv2 payload type
    assert parse_header(bytes(raw))["plausible"] is False


@pytest.mark.smoke
def test_detect_never_raises_on_mutated_input():
    """
    `detect` is offered attacker-chosen bytes on every new UDP flow in a
    capture. The router catches exceptions, but a detector that throws is a
    defect -- so this asserts absence of exceptions rather than an invariant.
    """
    rnd = seeded("ikev2-detect")
    seeds = [sa_init_request(), NON_ESP_MARKER + sa_init_request(),
             b"\xff", ikev2.NAT_KEEPALIVE + bytes(40)]
    for _ in range(600):
        payload = mutate(rnd.choice(seeds), rnd)
        for key in (KEY, KEY_4500, KEY_53):
            assert HANDLER.detect(payload, key) in (True, False)


# --------------------------------------------------------------------------
# port 4500: IKE, ESP and a keepalive sharing one port
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_the_non_esp_marker_is_stripped_before_the_header_is_read():
    raw = sa_init_request()
    kind, body = classify_datagram(NON_ESP_MARKER + raw)
    assert (kind, body) == ("ike", raw)


@pytest.mark.smoke
def test_an_esp_packet_is_not_read_as_an_ike_header():
    """
    The defect this discrimination exists to prevent: an encrypted ESP packet
    parsed at IKE's offsets yields a well-formed-looking proposal made of
    ciphertext.
    """
    esp = struct.pack(">II", 0xCAFE1234, 1) + bytes(range(32))
    kind, spi = classify_datagram(esp)
    assert kind == "esp" and spi == b"\xca\xfe\x12\x34"
    assert parse_header(esp)["plausible"] is False


@pytest.mark.smoke
def test_esp_is_claimed_on_4500_and_nowhere_else():
    """
    The one place a port decides anything here, and it is a port because ESP
    has no content to decide from -- it is an opaque SPI and ciphertext.
    Claiming it by shape alone would claim every unrecognised UDP flow.
    """
    esp = struct.pack(">II", 0xCAFE1234, 1) + bytes(range(32))
    assert HANDLER.detect(esp, KEY_4500) is True
    assert HANDLER.detect(esp, KEY) is False
    assert HANDLER.detect(esp, KEY_53) is False


@pytest.mark.smoke
@pytest.mark.parametrize("payload", [
    b"\x00\x00\x00\x00" + b"\x00" * 32,          # a zero SPI is the marker
    struct.pack(">II", 42, 1) + bytes(32),       # RFC 4303 reserves 1-255
    struct.pack(">II", 0xCAFE1234, 1) + b"\x00" * 3,     # too short
    struct.pack(">II", 0xCAFE1234, 1) + bytes(9),        # not 4-octet aligned
])
def test_what_is_not_esp_shaped(payload):
    assert ikev2.looks_like_esp(payload) is False


@pytest.mark.smoke
def test_a_nat_keepalive_is_neither_ike_nor_esp():
    assert classify_datagram(b"\xff") == ("keepalive", None)
    handler = Ikev2Handler()
    handler.push(1.0, b"\xff", KEY_4500, None)
    assert handler.keepalives == 1
    assert handler.esp_packets == 0
    # A flow of nothing but keepalives is still a finding: something is
    # holding an IPsec NAT mapping open between these two addresses.
    record, = [d["ikev2"] for d in handler.finish()]
    assert record["kind"] == "esp" and record["opaque"] is True
    assert record["esp"] == {"spis": [], "packets": 0, "bytes": 0,
                             "encapsulation": "udp", "port": 4500,
                             "nat_keepalives": 1}


@pytest.mark.smoke
def test_ike_on_port_500_whose_spi_begins_with_four_zero_octets():
    """
    A marker-shaped datagram is tried both ways. RFC 7296 forbids an
    all-zero initiator SPI but not one whose first four octets are zero, and
    on port 500 there is no marker to strip -- so stripping unconditionally
    would lose a legitimate message.
    """
    raw = sa_init_request()
    raw = b"\x00\x00\x00\x00" + raw[4:]
    raw = raw[:24] + struct.pack(">I", len(raw)) + raw[28:]
    assert raw[:4] == NON_ESP_MARKER
    kind, body = classify_datagram(raw)
    assert kind == "ike" and body == raw


# --------------------------------------------------------------------------
# the payload chain: a linked list with attacker-chosen lengths
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_the_chain_is_walked_in_order():
    raw = sa_init_request()
    names = [p["name"] for p in walk_payloads(raw, raw[16])]
    assert names == ["SA", "KE", "Nonce"]


@pytest.mark.smoke
def test_a_zero_length_payload_terminates_rather_than_looping():
    """
    A payload shorter than its own four-octet header makes the walk stand
    still. Without the floor check this is an infinite loop on six bytes an
    attacker chose.
    """
    body = bytes([P_NONCE, 0, 0, 0])             # length 0
    raw = (ISPI + ZERO_SPI + bytes([P_NONCE, 0x20, X_SA_INIT, F_INITIATOR])
           + struct.pack(">II", 0, IKE_HDR_LEN + len(body)) + body)
    reset_parse_stats()
    assert walk_payloads(raw, raw[16]) == []
    assert PARSE_STATS["ikev2_payload_bad_length"] == 1


@pytest.mark.smoke
def test_a_payload_length_past_the_message_is_refused():
    raw = bytearray(sa_init_request())
    raw[IKE_HDR_LEN + 2:IKE_HDR_LEN + 4] = b"\xff\xff"
    reset_parse_stats()
    assert walk_payloads(bytes(raw), raw[16]) == []
    assert PARSE_STATS["ikev2_payload_bad_length"] == 1


@pytest.mark.smoke
def test_the_chain_is_capped():
    items = [(P_NONCE, b"\x00" * 4)] * (ikev2.MAX_PAYLOADS + 20)
    raw = message(items)
    reset_parse_stats()
    assert len(walk_payloads(raw, raw[16])) == ikev2.MAX_PAYLOADS
    assert PARSE_STATS["ikev2_payload_chain_too_long"] == 1


@pytest.mark.smoke
def test_a_declared_length_shorter_than_the_buffer_bounds_the_walk():
    """
    The walk stops at the *declared* message length, not at the buffer end,
    so trailing bytes a sender appended are never read as payloads. Note the
    datagram itself is longer -- it is the header's own length field that
    decides, and it is the smaller of the two.
    """
    raw = message([(P_NONCE, b"\x01\x02\x03\x04"),
                   (P_NONCE, b"\x05\x06\x07\x08")])
    assert len(raw) == IKE_HDR_LEN + 16
    assert len(walk_payloads(raw, raw[16])) == 2
    short = raw[:24] + struct.pack(">I", IKE_HDR_LEN + 8) + raw[28:]
    walked = walk_payloads(short, short[16])
    assert len(walked) == 1
    assert walked[0]["body"] == b"\x01\x02\x03\x04"


# --------------------------------------------------------------------------
# the SA payload: three levels of nested, sender-chosen length
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_a_proposal_decodes_to_named_transforms():
    proposals = parse_sa(simple_sa())
    assert len(proposals) == 1
    grouped = algorithms_of(proposals[0])
    assert grouped["ENCR"] == ["ENCR_AES_256_CBC"]
    assert grouped["PRF"] == ["PRF_HMAC_SHA2_256"]
    assert grouped["INTEG"] == ["AUTH_HMAC_SHA2_256_128"]
    assert grouped["KE"] == ["secp256r1"]


@pytest.mark.smoke
def test_the_key_length_attribute_is_folded_into_the_encryption_name():
    """
    ENCR_AES_CBC is not an algorithm; it is three of them. The size arrives in
    a separate TV attribute and a name that omits it cannot be classified or
    compared -- `symmetric_label` reads the strength off `AES_256` in the name.
    """
    for bits in (128, 192, 256):
        proposals = parse_sa(proposal([transform(1, 12, True,
                                                 key_length=bits)]))
        name = proposals[0]["transforms"][0]["name"]
        assert name == "ENCR_AES_{0}_CBC".format(bits)
        assert proposals[0]["transforms"][0]["key_length"] == bits
    assert symmetric_label("ENCR_AES_256_CBC") == (
        "AES_256 (256 bits, 128 after Grover)")


@pytest.mark.smoke
def test_a_missing_key_length_keeps_the_bare_iana_name():
    """Reported as what was on the wire, never as a guessed default."""
    proposals = parse_sa(proposal([transform(1, 12, True)]))
    assert proposals[0]["transforms"][0]["name"] == "ENCR_AES_CBC"
    assert "key_length" not in proposals[0]["transforms"][0]


@pytest.mark.smoke
def test_a_tv_attribute_is_not_read_as_a_length():
    """
    The top bit selects the format. Reading a TV key length of 256 as a TLV
    length is a promise of 256 further octets that are not there.
    """
    tv = parse_attributes(struct.pack(">HH", 0x8000 | 14, 256))
    assert tv == [{"type": 14, "name": "Key Length", "format": "TV",
                   "value": 256}]
    tlv = parse_attributes(struct.pack(">HH", 14, 2) + b"\x01\x00")
    assert tlv[0]["format"] == "TLV" and tlv[0]["value"] == 256


@pytest.mark.smoke
def test_a_tlv_attribute_running_past_its_transform_is_refused():
    reset_parse_stats()
    assert parse_attributes(struct.pack(">HH", 14, 0xFFFF)) == []
    assert PARSE_STATS["ikev2_attribute_bad_length"] == 1


@pytest.mark.smoke
def test_attributes_are_capped():
    body = struct.pack(">HH", 0x8000 | 99, 1) * (ikev2.MAX_ATTRIBUTES + 10)
    assert len(parse_attributes(body)) == ikev2.MAX_ATTRIBUTES


@pytest.mark.smoke
@pytest.mark.parametrize("length", [0xFFFF, 0, 7])
def test_a_transform_whose_length_is_wrong_yields_no_transforms(length):
    """
    The nested bound. A transform's length is checked against its *proposal's*
    end, not the datagram's: checking against the datagram is how a
    three-deep length check turns into no length check at all, because the
    transform would then be read out of the next proposal's bytes.

    The proposal survives with an empty transform list rather than vanishing.
    That is deliberate -- "a proposal was offered and could not be read" and
    "no proposal was offered" are different facts -- and it is safe, because
    a proposal with no transforms contributes no algorithm to the inventory.
    """
    body = bytearray(proposal([transform(1, 12, True, key_length=256)]))
    struct.pack_into(">H", body, 8 + 2, length)   # the transform's length
    reset_parse_stats()
    proposals = parse_sa(bytes(body))
    assert [p["transforms"] for p in proposals] == [[]]
    assert algorithms_of(proposals[0]) == {}
    assert PARSE_STATS["ikev2_transform_bad_length"] == 1


@pytest.mark.smoke
def test_a_corrupt_transform_cannot_reach_into_the_next_proposal():
    """
    What the nested bound buys. The first proposal's transform claims 65535
    octets; the second proposal, whole and valid, is still read.
    """
    first = bytearray(proposal([transform(1, 12, True, key_length=256)],
                               number=1, last=False))
    struct.pack_into(">H", first, 8 + 2, 0xFFFF)
    second = proposal([transform(4, 19, True)], number=2, last=True)
    proposals = parse_sa(bytes(first) + second)
    assert [p["number"] for p in proposals] == [1, 2]
    assert algorithms_of(proposals[0]) == {}
    assert algorithms_of(proposals[1]) == {"KE": ["secp256r1"]}


@pytest.mark.smoke
def test_a_proposal_spi_size_past_its_own_end_is_refused():
    body = bytearray(proposal([transform(4, 19, True)]))
    body[6] = 0xFF                                # SPI size
    reset_parse_stats()
    assert parse_sa(bytes(body)) == []
    assert PARSE_STATS["ikev2_proposal_bad_spi_size"] == 1


@pytest.mark.smoke
def test_a_zero_length_proposal_terminates():
    body = bytearray(proposal([transform(4, 19, True)]))
    struct.pack_into(">H", body, 2, 0)
    reset_parse_stats()
    assert parse_sa(bytes(body)) == []
    assert PARSE_STATS["ikev2_proposal_bad_length"] == 1


@pytest.mark.smoke
def test_a_lied_about_transform_count_is_recorded_not_believed():
    """
    Nothing in the walk is driven by this count -- it is bounded by length --
    but a sender who lies about it is usually testing a parser, so it is kept.
    """
    body = proposal([transform(4, 19, True)], declared=200)
    reset_parse_stats()
    proposals = parse_sa(body)
    assert proposals[0]["transform_count_mismatch"] is True
    assert proposals[0]["transforms_declared"] == 200
    assert len(proposals[0]["transforms"]) == 1
    assert PARSE_STATS["ikev2_transform_count_mismatch"] == 1


@pytest.mark.smoke
def test_proposals_are_capped():
    body = b"".join(proposal([transform(4, 19, True)], last=False)
                    for _ in range(ikev2.MAX_PROPOSALS + 10))
    assert len(parse_sa(body)) == ikev2.MAX_PROPOSALS


@pytest.mark.smoke
def test_several_proposals_are_all_kept():
    body = (proposal([transform(1, 12, True, key_length=256)], number=1,
                     last=False)
            + proposal([transform(1, 3, True)], number=2, last=True))
    proposals = parse_sa(body)
    assert [p["number"] for p in proposals] == [1, 2]
    assert proposals[1]["transforms"][0]["name"] == "ENCR_3DES"


# --------------------------------------------------------------------------
# the names, which are an interface to cryptomon.analysis
# --------------------------------------------------------------------------
def test_every_key_exchange_group_classifies_as_something():
    """
    The quantum-relevant assertion. A group reported as "Group 19" rather than
    "secp256r1" lands in `unknown`, and an unrecognised key exchange in a
    post-quantum readiness report is a finding thrown away.
    """
    unclassified = [(gid, name) for gid, name in KE_GROUPS.items()
                    if name != "none"
                    and classify_algorithm(name) == UNKNOWN]
    assert unclassified == []


@pytest.mark.smoke
@pytest.mark.parametrize("group,name,verdict", [
    (1, "dh-modp768", CLASSICAL),
    (2, "dh-modp1024", CLASSICAL),
    (5, "dh-modp1536", CLASSICAL),
    (14, "dh-modp2048", CLASSICAL),
    (18, "dh-modp8192", CLASSICAL),
    (19, "secp256r1", CLASSICAL),
    (20, "secp384r1", CLASSICAL),
    (21, "secp521r1", CLASSICAL),
    (31, "x25519", CLASSICAL),
    (32, "x448", CLASSICAL),
    (35, "ml-kem-512", POST_QUANTUM),
    (36, "ml-kem-768", POST_QUANTUM),
    (37, "ml-kem-1024", POST_QUANTUM),
])
def test_the_groups_named_in_the_brief(group, name, verdict):
    assert key_exchange_name(group) == name
    assert classify_algorithm(name) == verdict


@pytest.mark.smoke
def test_an_unregistered_group_keeps_its_number_and_stays_unknown():
    assert key_exchange_name(999) == "unknown-ke-999"
    assert classify_algorithm("unknown-ke-999") == UNKNOWN


@pytest.mark.smoke
def test_a_private_use_group_is_named_as_such_and_never_guessed_at():
    """
    Transform IDs from 1024 up are private use and implementations have
    shipped post-quantum KEMs in there for years. A wrong algorithm name in a
    cryptography inventory is worse than an honest gap, so these are reported
    by number.
    """
    assert key_exchange_name(1031) == "unknown-ke-private-1031"
    assert classify_algorithm(key_exchange_name(1031)) == UNKNOWN


@pytest.mark.smoke
def test_the_rfc_9370_transform_types_start_at_six():
    """
    RFC 7296 spent types 1-5 on ENCR, PRF, INTEG, D-H and ESN, so RFC 9370's
    seven additional key exchanges can only begin at 6. Any table that put
    them at 3-7 or 5-7 would be reading INTEG, D-H and ESN transforms as key
    exchanges -- which is a quantum-relevant field read out of the wrong one.
    """
    assert ikev2.TRANSFORM_TYPES[3] == "INTEG"
    assert ikev2.TRANSFORM_TYPES[4] == "KE"
    assert ikev2.TRANSFORM_TYPES[5] == "ESN"
    assert [ikev2.TRANSFORM_TYPES[n] for n in range(6, 13)] == [
        "ADDKE1", "ADDKE2", "ADDKE3", "ADDKE4", "ADDKE5", "ADDKE6", "ADDKE7"]
    assert transform_name(6, 36) == "ml-kem-768"


@pytest.mark.smoke
def test_a_group_plus_a_kem_is_reported_as_the_hybrid_it_is():
    """
    RFC 9370's whole point: the key exchange is no longer one algorithm. The
    combined name is what says so, and it is built to be classifiable by the
    marker table that already exists -- `x25519+ml-kem-768` normalises to
    `x25519mlkem768`, in which `classify_algorithm` finds one marker of each
    kind. Neither half gives that answer alone.
    """
    grouped = {"KE": ["x25519"], "ADDKE1": ["ml-kem-768"]}
    combined = combined_key_exchange(grouped)
    assert combined == "x25519+ml-kem-768"
    assert classify_algorithm(combined) == HYBRID
    assert classify_algorithm("x25519") == CLASSICAL
    assert classify_algorithm("ml-kem-768") == POST_QUANTUM


@pytest.mark.smoke
def test_a_none_additional_key_exchange_is_not_appended():
    assert combined_key_exchange({"KE": ["x25519"],
                                  "ADDKE1": ["none"]}) == "x25519"


@pytest.mark.smoke
def test_encryption_names_feed_the_symmetric_strength_table():
    for tid, bits, expected in ((12, 256, "AES_256"), (12, 128, "AES_128"),
                                (20, 256, "AES_256"), (23, 128, "CAMELLIA_128")):
        name = transform_name(1, tid, bits)
        assert symmetric_label(name).startswith(expected), name
    assert "broken" in symmetric_label(transform_name(1, 3))      # 3DES
    assert "broken" in symmetric_label(transform_name(1, 11))     # NULL


@pytest.mark.smoke
def test_an_unregistered_encryption_transform_keeps_its_number():
    assert transform_name(1, 250) == "unknown-encr-250"
    assert transform_name(2, 250) == "unknown-prf-250"
    assert transform_name(3, 250) == "unknown-integ-250"


@pytest.mark.smoke
def test_the_variable_key_templates_only_apply_where_a_key_length_may_ride():
    """A fixed-key algorithm must not grow a size it never negotiated."""
    for tid, (iana, template) in ENCR_TRANSFORMS.items():
        if template is None:
            assert transform_name(1, tid, 256) == iana


# --------------------------------------------------------------------------
# notify payloads: where IKEv2 says what TLS puts in extensions
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_signature_hash_algorithms_are_decoded():
    notify = parse_notify(bytes([0, 0]) + struct.pack(">HHHH", 16431, 2, 3, 4))
    assert notify["name"] == "SIGNATURE_HASH_ALGORITHMS"
    assert notify["hash_algorithms"] == ["SHA2-256", "SHA2-384", "SHA2-512"]


@pytest.mark.smoke
def test_invalid_ke_payload_carries_the_counter_offer():
    """IKEv2's HelloRetryRequest: "not that group, this one"."""
    notify = parse_notify(bytes([0, 0]) + struct.pack(">HH", 17, 19))
    assert notify["name"] == "INVALID_KE_PAYLOAD"
    assert notify["error"] is True
    assert notify["group_name"] == "secp256r1"


@pytest.mark.smoke
@pytest.mark.parametrize("code,name", [
    (16435, "USE_PPK"), (16430, "IKEV2_FRAGMENTATION_SUPPORTED"),
    (16418, "CHILDLESS_IKEV2_SUPPORTED"), (16438,
                                           "INTERMEDIATE_EXCHANGE_SUPPORTED"),
    (16441, "ADDITIONAL_KEY_EXCHANGE"), (14, "NO_PROPOSAL_CHOSEN"),
    (16390, "COOKIE"), (16388, "NAT_DETECTION_SOURCE_IP"),
])
def test_the_notify_types_the_brief_names(code, name):
    notify = parse_notify(bytes([0, 0]) + struct.pack(">H", code))
    assert notify["name"] == name
    assert notify["error"] is (code < 16384)


@pytest.mark.smoke
def test_a_notify_spi_size_past_its_own_payload_is_refused():
    reset_parse_stats()
    assert parse_notify(bytes([1, 0xFF]) + struct.pack(">H", 14)) is None
    assert PARSE_STATS["ikev2_notify_bad_spi_size"] == 1


@pytest.mark.smoke
def test_notification_data_is_kept_as_bounded_hex():
    notify = parse_notify(bytes([0, 0]) + struct.pack(">H", 16390)
                          + b"\xaa" * 500)
    assert len(notify["data"]) == ikev2.MAX_NOTIFY_DATA * 2
    assert notify["data_truncated"] == 500


@pytest.mark.smoke
def test_notifies_are_capped():
    items = [(P_NOTIFY, bytes([0, 0]) + struct.pack(">H", 16430))] * 50
    view = ikev2.summarise_message(parse_message(message(items)))
    assert len(view["notifies"]) == ikev2.MAX_NOTIFIES


# --------------------------------------------------------------------------
# vendor IDs
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_vendor_ids_are_the_md5_of_their_published_strings():
    """
    The one external check in this file. These four hex constants are
    documented in the wild independently of this repository, and they are also
    what MD5 of the strings in `_VENDOR_ID_SOURCES` produces -- so if the
    table were mistyped, the derivation and the published value would not
    agree. MD5 here is a naming convention, not a security decision.
    """
    published = {
        "882fe56d6fd20dbc2251613b2ebe5beb": "strongSwan",
        "4a131c81070358455c5728f20e95452f": "NAT-T (RFC 3947)",
        "4048b7d56ebce88525e7de7f00d6c2d3": "Microsoft IKE fragmentation",
        "90cb80913ebb696e086381b5ec427b1f":
            "NAT-T (draft-ietf-ipsec-nat-t-ike-02)",
    }
    for digest, name in published.items():
        assert VENDOR_IDS[digest] == name


@pytest.mark.smoke
def test_a_known_vendor_id_is_named_and_an_unknown_one_keeps_its_hex():
    known = describe_vendor_id(
        bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb"))
    assert known["name"] == "strongSwan"
    unknown = describe_vendor_id(b"\x01\x02\x03\x04")
    assert unknown == {"hex": "01020304"}


@pytest.mark.smoke
def test_a_vendor_id_with_a_version_suffix_still_matches():
    raw = bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb") + b"\x05\x09\x02"
    assert describe_vendor_id(raw)["name"] == "strongSwan"


@pytest.mark.smoke
def test_an_ascii_vendor_id_is_printed_rather_than_hexed():
    assert describe_vendor_id(b"CISCO-DELETE-REASON")["name"] == (
        "Cisco (delete reason)")
    assert describe_vendor_id(b"SomeVendor-1.2")["name"] == "SomeVendor-1.2"


@pytest.mark.smoke
def test_vendor_ids_are_capped_and_truncated():
    items = [(P_VID, b"A" * 500)] * 40
    view = ikev2.summarise_message(parse_message(message(items)))
    assert len(view["vendor_ids"]) == ikev2.MAX_VENDOR_IDS
    assert len(view["vendor_ids"][0]["hex"]) == ikev2.MAX_VENDOR_ID_BYTES * 2


# --------------------------------------------------------------------------
# IKEv1: recognised, counted, and not parsed
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_ikev1_is_recognised_as_ikev1():
    raw = message([(1, bytes(40))], major=1, exchange=2, flags=0)
    header = parse_header(raw)
    assert header["major"] == 1 and header["plausible"] is True
    assert parse_message(raw)["exchange"] == "Identity Protection (Main Mode)"


@pytest.mark.smoke
def test_ikev1_payloads_are_not_walked():
    """
    IKEv1's SA payload nests DOI, situation and attribute-encoded proposals
    where IKEv2 nests transforms. Reading it at IKEv2's offsets produces a
    well-formed-looking answer that is wrong, which is the worst failure a
    cryptography inventory can have.
    """
    raw = message([(1, bytes(40))], major=1, exchange=2, flags=0)
    assert parse_message(raw)["payloads"] == []


@pytest.mark.smoke
def test_ikev1_is_counted_and_reported_as_refused():
    raw = message([(1, bytes(40))], major=1, exchange=2, flags=0)
    reset_parse_stats()
    handler = Ikev2Handler()
    handler.push(1.0, raw, KEY, None)
    assert handler.stats["ikev1"] == 1
    assert PARSE_STATS["ikev2_refused_ikev1"] == 1
    documents = list(handler.finish())
    assert len(documents) == 1
    record = documents[0]["ikev2"]
    assert record["kind"] == "ikev1" and record["refused"] is True
    assert record["kex_group"] is None
    assert record["opaque"] is True
    assert "RFC 9395" in record["opaque_reason"]


@pytest.mark.smoke
def test_major_version_three_is_not_claimed():
    raw = message([(P_NONCE, bytes(32))], major=3)
    assert parse_header(raw)["plausible"] is False
    assert HANDLER.detect(raw, KEY) is False


# --------------------------------------------------------------------------
# the handler and the router
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_the_module_exposes_what_the_seam_asks_for():
    assert HANDLER is Ikev2Handler
    assert Ikev2Handler.name == "ikev2"
    assert Ikev2Handler.ports == frozenset({500, 4500})
    assert Ikev2Handler in handlers()


@pytest.mark.smoke
def test_the_router_claims_an_ike_flow_and_emits_a_document():
    router = DatagramRouter(handler_classes=[Ikev2Handler])

    class Datagram:
        payload_offset = 0
        payload_end = None
        endpoints = {"src": {"ipv4": "10.0.0.1", "port": 500},
                     "dst": {"ipv4": "10.0.0.2", "port": 500}}

    request = sa_init_request()
    datagram = Datagram()
    datagram.payload_end = len(request)
    router.push(1.0, request, datagram)
    assert router.stats["flows_ikev2"] == 1
    documents = list(router.finish())
    assert len(documents) == 1
    assert documents[0]["ptype"] == "session"
    assert documents[0]["eth"]["dst"]["port"] == 500
    assert documents[0]["ikev2"]["kind"] == "ike"


@pytest.mark.smoke
def test_a_request_with_no_response_reports_no_negotiated_group():
    """
    The proposed/selected distinction, which matters more here than for TLS:
    an IKE_SA_INIT request is a menu a dozen entries long. Reporting the
    initiator's first choice as the session's key exchange would make a
    one-sided capture look like a successful negotiation every time the
    client happened to ask for something good.
    """
    handler = Ikev2Handler()
    handler.push(1.0, sa_init_request(), KEY, None)
    record = list(handler.finish())[0]["ikev2"]
    assert record["kex_group"] is None
    assert "request only" in record["evidence"]
    assert record["proposed_kex_groups"] == ["secp256r1"]
    assert record["offered_kex_group"] == "secp256r1"


@pytest.mark.smoke
def test_the_handler_never_raises_on_mutated_input():
    rnd = seeded("ikev2-push")
    seeds = [sa_init_request(), NON_ESP_MARKER + sa_init_request()]
    for _ in range(500):
        handler = Ikev2Handler()
        payload = mutate(rnd.choice(seeds), rnd)
        handler.push(1.0, payload, KEY_4500, None)
        list(handler.finish())


@pytest.mark.smoke
def test_the_handler_emits_json_serialisable_documents_for_mutated_input():
    """
    A crash is the cheap failure. The expensive one is a document that cannot
    be exported -- one unserialisable value anywhere in a capture kills the
    whole JSON export, which is how the corrupt-timestamp bug in the CSV
    exporter was found.
    """
    rnd = seeded("ikev2-json")
    seeds = [sa_init_request(), NON_ESP_MARKER + sa_init_request()]
    for _ in range(300):
        handler = Ikev2Handler()
        handler.push(1.0, mutate(rnd.choice(seeds), rnd), KEY_4500, None)
        for document in handler.finish():
            json.dumps(document, sort_keys=True)


@pytest.mark.smoke
def test_security_associations_are_capped_per_flow():
    handler = Ikev2Handler()
    for n in range(ikev2.MAX_SAS + 5):
        spi = struct.pack(">Q", 0x1000 + n)
        handler.push(1.0, sa_init_request_with_spi(spi), KEY, None)
    assert len(handler.sas) == ikev2.MAX_SAS
    assert handler.stats["sas_dropped"] == 5


def sa_init_request_with_spi(spi):
    return message([(P_SA, simple_sa()),
                    (P_KE, struct.pack(">HH", 19, 0) + bytes(64)),
                    (P_NONCE, bytes(32))], ispi=spi)


@pytest.mark.smoke
def test_init_messages_are_capped_per_sa():
    handler = Ikev2Handler()
    for _ in range(ikev2.MAX_INIT_MESSAGES + 6):
        handler.push(1.0, sa_init_request(), KEY, None)
    assert handler.stats["init_messages_dropped"] == 6


# --------------------------------------------------------------------------
# the fixtures, end to end through the real pipeline
# --------------------------------------------------------------------------
def documents(name):
    return [d["ikev2"] for d in iter_sessions(FIXTURES / "{0}.pcap".format(name))]


def test_the_fixtures_are_where_the_oracle_cannot_see_them():
    """
    `tests/conftest.py::fixture_names` globs `tests/fixtures/*.pcap` and pairs
    each with `tests/oracle/<name>.tsv`. A capture dropped at that top level
    fails the whole suite with a missing-oracle error before anything parses a
    byte, which is why these live in a subdirectory -- as `synthetic/` and
    `streams/` do.
    """
    assert sorted(p.name for p in FIXTURES.glob("*.pcap")) == [
        "ikev2_esp_only.pcap", "ikev2_ikev1.pcap", "ikev2_ipv6.pcap",
        "ikev2_legacy.pcap", "ikev2_natt_4500.pcap",
        "ikev2_post_quantum.pcap", "ikev2_pq_refused.pcap",
        "ikev2_sa_init.pcap"]
    assert list((HERE / "fixtures").glob("ikev2*.pcap")) == []


def test_the_fixtures_regenerate_byte_for_byte(tmp_path, monkeypatch):
    """
    A fixture that regenerates differently dirties the working tree on every
    run and makes every diff unreadable. That happened here once and was fixed
    in PR-14 by pinning the timestamps; this stops it coming back.
    """
    pytest.importorskip("scapy.all")
    spec = importlib.util.spec_from_file_location("make_ikev2_fixtures", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "OUT", tmp_path)
    module.main()
    for committed in sorted(FIXTURES.glob("*.pcap")):
        assert (tmp_path / committed.name).read_bytes() == \
            committed.read_bytes(), committed.name


def test_an_ordinary_negotiation_reports_what_was_selected():
    record, = documents("ikev2_sa_init")
    assert record["kind"] == "ike"
    assert record["evidence"] == "IKE_SA_INIT response"
    assert record["kex_group"] == "secp256r1"
    assert record["encryption"] == "ENCR_AES_256_CBC"
    assert record["prf"] == "PRF_HMAC_SHA2_256"
    assert record["integrity"] == "AUTH_HMAC_SHA2_256_128"
    assert record["messages"] == {"IKE_SA_INIT": 2, "IKE_AUTH": 2}
    assert record["vendor_ids"][0]["name"] == "strongSwan"
    assert record["signature_hash_algorithms"] == ["SHA2-256", "SHA2-384",
                                                   "SHA2-512"]


def test_the_menu_is_kept_alongside_the_choice():
    record, = documents("ikev2_sa_init")
    offered = record["proposed"]["proposals"][0]["algorithms"]
    assert offered["KE"] == ["secp256r1", "dh-modp2048", "x25519"]
    assert len(offered["ENCR"]) == 3
    chosen = record["selected"]["proposals"][0]["algorithms"]
    assert chosen["KE"] == ["secp256r1"]
    assert chosen["ENCR"] == ["ENCR_AES_256_CBC"]


def test_a_post_quantum_negotiation_reads_as_hybrid():
    record, = documents("ikev2_post_quantum")
    assert record["kex_group"] == "x25519+ml-kem-768"
    assert classify_algorithm(record["kex_group"]) == HYBRID
    assert record["additional_kex_groups"] == ["ml-kem-768"]
    assert record["post_quantum_preshared_key"] == "agreed"
    assert record["intermediate_exchange"] == "agreed"
    # The additional key exchange itself happens inside IKE_INTERMEDIATE and
    # is encrypted. Visible as a count and as nothing else, which is honest.
    assert record["additional_key_exchanges_performed"] == 2
    assert record["encrypted_exchanges"]["IKE_INTERMEDIATE"] == 2


def test_a_refused_post_quantum_offer_is_visible_end_to_end():
    record, = documents("ikev2_pq_refused")
    assert record["offered_kex_group"] == "x25519+ml-kem-768"
    assert record["retry_kex_group"] == "secp256r1"
    assert record["kex_group"] == "secp256r1"
    assert classify_algorithm(record["offered_kex_group"]) == HYBRID
    assert classify_algorithm(record["kex_group"]) == CLASSICAL


def test_legacy_choices_are_named_as_broken_today():
    record, = documents("ikev2_legacy")
    assert record["kex_group"] == "dh-modp1024"
    assert set(record["weak"]) == {"dh-modp1024", "ENCR_3DES",
                                   "AUTH_HMAC_MD5_96", "PRF_HMAC_MD5"}
    assert record["vendor_ids"][0]["name"] == "Cisco (delete reason)"


def test_ike_and_esp_on_4500_are_separated():
    ike, esp = documents("ikev2_natt_4500")
    assert ike["kind"] == "ike"
    assert ike["kex_group"] == "secp256r1"
    assert esp["kind"] == "esp"
    assert esp["esp"]["packets"] == 2
    # One SPI per direction: an IPsec Child SA is unidirectional, so a tunnel
    # carrying traffic both ways has two of them.
    assert sorted(esp["esp"]["spis"]) == ["cafe1205", "caff1205"]
    assert esp["esp"]["nat_keepalives"] == 1


def test_an_esp_only_flow_is_reported_as_present_and_opaque():
    record, = documents("ikev2_esp_only")
    assert record["kind"] == "esp"
    assert record["opaque"] is True
    assert record["kex_group"] is None
    assert record["esp"]["packets"] == 6
    assert record["esp"]["encapsulation"] == "udp"
    assert "IKE_SA_INIT" in record["opaque_reason"]


def test_ikev1_in_a_capture_is_refused_by_name():
    record, = documents("ikev2_ikev1")
    assert record["kind"] == "ikev1"
    assert record["messages"] == {"Identity Protection (Main Mode)": 2}


def test_ipv6_works_because_the_framing_walk_is_shared():
    record, = documents("ikev2_ipv6")
    assert record["kex_group"] == "secp256r1"
    assert record["initiator"] == "[2001:db8::1]:500"
    assert record["responder"] == "[2001:db8::2]:500"


def test_the_documents_are_json_serialisable():
    for path in sorted(FIXTURES.glob("*.pcap")):
        for document in iter_sessions(path):
            json.dumps(document, sort_keys=True)


# --------------------------------------------------------------------------
# what the analysis layer makes of it
# --------------------------------------------------------------------------
def all_documents():
    out = []
    for path in sorted(FIXTURES.glob("*.pcap")):
        out.extend(iter_sessions(path))
    return out


def test_the_summary_counts_ikev2_as_ikev2():
    """
    Without the routing change requested in this PR's report, an IKEv2 record
    falls through to `Summary._add_tls` and is counted as a TLS session with
    no key exchange -- so this test is also the check that the change is in.
    """
    summary = analyse(all_documents())
    assert summary.protocols.get("tls", 0) == 0
    assert summary.protocols["ikev2"] == 6
    assert summary.protocols["esp"] == 2
    assert summary.protocols["ikev1"] == 1


def test_the_readiness_headline_over_the_fixtures():
    summary = analyse(all_documents())
    readiness = summary.readiness()
    assert readiness["key_exchanges_performed"] == 6
    assert readiness["hybrid"] == 1
    assert readiness["classical"] == 5
    assert readiness["post_quantum_refused"] == 1
    # ESP and IKEv1 are not "no key exchange": the key exchange happened and
    # could not be read. Counting them beside a resumed TLS session would be
    # counting an event that did happen as one that did not.
    assert readiness["opaque_flows"] == 3
    assert readiness["no_key_exchange"] == 0


def test_the_inventory_carries_the_transforms_separately():
    summary = analyse(all_documents())
    kinds = {(entry["kind"], entry["name"]): entry for entry in
             summary.inventory}
    assert kinds[("key-exchange", "x25519+ml-kem-768")]["verdict"] == HYBRID
    assert kinds[("cipher", "ENCR_AES_256_CBC")]["verdict"] == SYMMETRIC
    assert kinds[("prf", "PRF_HMAC_SHA2_256")]["verdict"] == SYMMETRIC
    assert kinds[("integrity", "AUTH_HMAC_SHA2_256_128")]["verdict"] == (
        SYMMETRIC)


def test_the_cbom_fills_ikev2_transform_types():
    """
    The field CycloneDX has for exactly this and nothing here filled. IKEv2
    is the one protocol that puts its four transform types on the wire as
    four separately numbered fields, which is what the schema models.
    """
    jsonschema = pytest.importorskip("jsonschema")
    from pcapscan.cbom import build
    summary = analyse(all_documents())
    bom = build(summary, source="ikev2 fixtures")
    schema = json.loads((HERE / "schema" / "bom-1.6.schema.json").read_text())
    jsonschema.Draft7Validator(schema).validate(bom)

    protocols = {component["name"]: component for component in
                 bom["components"]
                 if component["cryptoProperties"]["assetType"] == "protocol"}
    ike = protocols["IKEv2"]["cryptoProperties"]["protocolProperties"]
    assert ike["type"] == "ike" and ike["version"] == "2.0"
    transforms = ike["ikev2TransformTypes"]
    assert "key-exchange/x25519mlkem768" in transforms["ke"]
    assert "cipher/encraes256cbc" in transforms["encr"]
    assert "prf/prfhmacsha2256" in transforms["prf"]
    assert "integrity/authhmacsha2256128" in transforms["integ"]
    assert protocols["ESP"]["cryptoProperties"][
        "protocolProperties"]["type"] == "ipsec"
