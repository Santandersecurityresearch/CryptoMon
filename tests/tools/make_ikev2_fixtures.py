#!/usr/bin/env python3
"""
Build the IKEv2 fixtures, from RFC 7296's field layouts rather than from a capture.

    ./tests/tools/make_ikev2_fixtures.py

Writes tests/fixtures/ikev2/*.pcap, which are committed.

**Why these are constructed and not captured.** There is no IKEv2 anywhere in
this project's corpus: zero packets on UDP 500 or 4500 and zero of IP protocol
50 across all 160,221 packets, checked rather than assumed. So unlike every
other parser here, `pcapscan/ikev2.py` has no real traffic to be judged
against, and these files are the only thing it has ever parsed. That is a
weakness of the evidence and is stated in the PR report rather than papered
over.

What makes them worth anything is that the bytes come from the specification
and not from what makes the parser pass: every offset, every "Last Substruc"
value and every transform ID below is written out from RFC 7296 sections 3.1
to 3.10, RFC 3948 section 2.2 for the non-ESP marker, RFC 8784 for USE_PPK and
RFC 9370 for the additional key exchange transform types. Where a value could
not be checked against a specification in the repository it is not invented --
see the note on private-use key exchange IDs in `pcapscan/ikev2.py`.

They live in a subdirectory rather than beside `tests/fixtures/*.pcap` on
purpose. `tests/conftest.py::fixture_names` globs that top level and pairs
every file it finds with `tests/oracle/<name>.tsv`, so a new capture dropped
there fails the whole suite with a missing-oracle FileNotFoundError before
anything has parsed a byte. `synthetic/` and `streams/` are there for the
same reason.

Timestamps are pinned. scapy otherwise stamps "now", and a committed fixture
that regenerates differently shows up as a diff on every run -- which happened
here once already and was fixed in PR-14.
"""
import pathlib
import struct
import sys

from scapy.all import Ether, IP, IPv6, UDP, Raw, wrpcap

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent / "fixtures" / "ikev2"

# 2024-12-11T00:00:00Z, the corpus date, and a millisecond per packet so that
# ordering and durations are as fixed as the bytes are.
BASE_TIME = 1733875200
TICK = 0.001

ETH = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
CLIENT6, SERVER6 = "2001:db8::1", "2001:db8::2"

# Each capture gets its own /24 and its own initiator SPI, set by `main()`
# before it is built. They would otherwise all be 10.0.0.1 <-> 10.0.0.2 with
# the same SPI, and `pcapscan tests/fixtures/ikev2/*.pcap` -- one scan over
# all of them -- would key them into a single UDP flow holding a single IKE
# SA, folding four different negotiations into one nonsensical record. Each
# file parses correctly on its own, which is what hides it.
CLIENT, SERVER = "10.0.0.1", "10.0.0.2"

ISPI = bytes.fromhex("1122334455667788")
RSPI = bytes.fromhex("99aabbccddeeff00")
NO_SPI = b"\x00" * 8
ESP_SPI = 0xCAFE1200


def use_capture(index):
    """Point the builders at capture `index`'s own addresses and SPIs."""
    global CLIENT, SERVER, ISPI, RSPI, ESP_SPI
    CLIENT = "10.0.{0}.1".format(index)
    SERVER = "10.0.{0}.2".format(index)
    ISPI = bytes([0x11 + index]) + bytes.fromhex("22334455667788")
    RSPI = bytes([0x99 + index]) + bytes.fromhex("aabbccddeeff00")
    ESP_SPI = 0xCAFE1200 + index

# Payload types (RFC 7296 section 3.2)
P_SA, P_KE, P_NONCE, P_NOTIFY, P_VID, P_SK = 33, 34, 40, 41, 43, 46
# Exchange types
X_SA_INIT, X_AUTH, X_INTERMEDIATE = 34, 35, 43
# Header flags
F_INITIATOR, F_RESPONSE = 0x08, 0x20
# Transform types
T_ENCR, T_PRF, T_INTEG, T_KE, T_ESN, T_ADDKE1 = 1, 2, 3, 4, 5, 6


def fill(length, seed):
    """A fixed, non-repeating filler. Nonces and key shares need bytes, not
    meaning, and `os.urandom` would make the fixture different every run."""
    return bytes((seed + i * 7) & 0xFF for i in range(length))


# --------------------------------------------------------------------------
# substructures, innermost first
# --------------------------------------------------------------------------
def transform(ttype, tid, last, key_length=None):
    """A transform substructure (section 3.3.2), optionally with a key length.

    "Last Substruc" is 0 for the last transform in a proposal and 3 for any
    other -- 3, not 2: 2 is what a *proposal* uses. The key length rides in a
    TV-format attribute (top bit set, type 14), which is the only attribute
    IKEv2 defines and the one without which ENCR_AES_CBC names nothing."""
    attributes = b""
    if key_length is not None:
        attributes = struct.pack(">HH", 0x8000 | 14, key_length)
    return (bytes([0 if last else 3, 0])
            + struct.pack(">H", 8 + len(attributes))
            + bytes([ttype, 0]) + struct.pack(">H", tid) + attributes)


def proposal(number, protocol, spi, transforms, last):
    """A proposal substructure (section 3.3.1). "Last Substruc" is 0 or 2."""
    body = b"".join(transforms)
    return (bytes([0 if last else 2, 0])
            + struct.pack(">H", 8 + len(spi) + len(body))
            + bytes([number, protocol, len(spi), len(transforms)])
            + spi + body)


def sa_payload(proposals):
    return b"".join(proposals)


def ke_payload(group, key_bytes):
    return struct.pack(">HH", group, 0) + fill(key_bytes, 0x40)


def nonce_payload(length=32):
    return fill(length, 0x11)


def notify_payload(notify_type, data=b"", protocol=0, spi=b""):
    return (bytes([protocol, len(spi)]) + struct.pack(">H", notify_type)
            + spi + data)


def ike_message(ispi, rspi, exchange, flags, message_id, payloads, major=2):
    """Header (section 3.1) plus the payload chain, with the lengths agreeing.

    The chain is built backwards because each payload header names the type of
    the one that *follows* it; the last carries 0."""
    blob = b""
    first = 0
    for ptype, body in reversed(payloads):
        blob = (bytes([first, 0]) + struct.pack(">H", 4 + len(body)) + body
                + blob)
        first = ptype
    header = (ispi + rspi + bytes([first, (major << 4), exchange, flags])
              + struct.pack(">II", message_id, IKE_HDR + len(blob)))
    return header + blob


IKE_HDR = 28
NON_ESP_MARKER = b"\x00\x00\x00\x00"


def esp_packet(spi, sequence, octets=32):
    """SPI, sequence number and ciphertext (RFC 4303). Nothing else is visible."""
    return struct.pack(">II", spi, sequence) + fill(octets, 0x55)


# --------------------------------------------------------------------------
# the negotiations
# --------------------------------------------------------------------------
def classical_init_request():
    """What strongSwan's default proposal looks like: a menu."""
    transforms = [
        transform(T_ENCR, 12, False, key_length=256),   # ENCR_AES_CBC
        transform(T_ENCR, 12, False, key_length=128),
        transform(T_ENCR, 20, False, key_length=256),   # ENCR_AES_GCM_16
        transform(T_PRF, 5, False),                     # PRF_HMAC_SHA2_256
        transform(T_PRF, 7, False),                     # PRF_HMAC_SHA2_512
        transform(T_INTEG, 12, False),                  # AUTH_HMAC_SHA2_256_128
        transform(T_KE, 19, False),                     # secp256r1
        transform(T_KE, 14, False),                     # 2048-bit MODP
        transform(T_KE, 31, True),                      # Curve25519
    ]
    return ike_message(ISPI, NO_SPI, X_SA_INIT, F_INITIATOR, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(19, 64)),
        (P_NONCE, nonce_payload()),
        (P_NOTIFY, notify_payload(16388, fill(20, 0x70))),   # NAT_DETECTION_SOURCE_IP
        (P_NOTIFY, notify_payload(16389, fill(20, 0x90))),   # ..._DESTINATION_IP
        (P_NOTIFY, notify_payload(16430)),                   # FRAGMENTATION_SUPPORTED
        (P_NOTIFY, notify_payload(16431, struct.pack(">HHH", 2, 3, 4))),
        (P_VID, bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb")),  # strongSwan
    ])


def classical_init_response():
    """One proposal, one transform of each type -- what section 3.3 requires."""
    transforms = [
        transform(T_ENCR, 12, False, key_length=256),
        transform(T_PRF, 5, False),
        transform(T_INTEG, 12, False),
        transform(T_KE, 19, True),
    ]
    return ike_message(ISPI, RSPI, X_SA_INIT, F_RESPONSE, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(19, 64)),
        (P_NONCE, nonce_payload()),
        (P_NOTIFY, notify_payload(16388, fill(20, 0x70))),
        (P_NOTIFY, notify_payload(16389, fill(20, 0x90))),
        (P_NOTIFY, notify_payload(16430)),
    ])


def post_quantum_init_request():
    """RFC 9370 plus RFC 8784: a KEM alongside the group, and a PPK."""
    transforms = [
        transform(T_ENCR, 20, False, key_length=256),   # ENCR_AES_GCM_16
        transform(T_PRF, 5, False),
        transform(T_KE, 31, False),                     # Curve25519
        transform(T_ADDKE1, 36, False),                 # ML-KEM-768
        transform(T_ADDKE1, 0, True),                   # ...or none
    ]
    return ike_message(ISPI, NO_SPI, X_SA_INIT, F_INITIATOR, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(31, 32)),
        (P_NONCE, nonce_payload()),
        (P_NOTIFY, notify_payload(16435)),   # USE_PPK (RFC 8784)
        (P_NOTIFY, notify_payload(16438)),   # INTERMEDIATE_EXCHANGE_SUPPORTED
        (P_NOTIFY, notify_payload(16430)),
    ])


def post_quantum_init_response():
    transforms = [
        transform(T_ENCR, 20, False, key_length=256),
        transform(T_PRF, 5, False),
        transform(T_KE, 31, False),
        transform(T_ADDKE1, 36, True),
    ]
    return ike_message(ISPI, RSPI, X_SA_INIT, F_RESPONSE, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(31, 32)),
        (P_NONCE, nonce_payload()),
        (P_NOTIFY, notify_payload(16435)),
        (P_NOTIFY, notify_payload(16438)),
    ])


def encrypted(exchange, flags, message_id):
    """Anything after IKE_SA_INIT: one SK payload and nothing readable in it."""
    return ike_message(ISPI, RSPI, exchange, flags, message_id,
                       [(P_SK, fill(48, 0xA0))])


def legacy_init_request():
    """A 2005-era proposal, still deployed: 3DES, MD5 and 1024-bit MODP."""
    transforms = [
        transform(T_ENCR, 3, False),      # ENCR_3DES
        transform(T_PRF, 1, False),       # PRF_HMAC_MD5
        transform(T_INTEG, 1, False),     # AUTH_HMAC_MD5_96
        transform(T_KE, 2, True),         # 1024-bit MODP
    ]
    return ike_message(ISPI, NO_SPI, X_SA_INIT, F_INITIATOR, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(2, 128)),
        (P_NONCE, nonce_payload(16)),
        (P_VID, b"CISCO-DELETE-REASON"),
    ])


def legacy_init_response():
    transforms = [
        transform(T_ENCR, 3, False),
        transform(T_PRF, 1, False),
        transform(T_INTEG, 1, False),
        transform(T_KE, 2, True),
    ]
    return ike_message(ISPI, RSPI, X_SA_INIT, F_RESPONSE, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(2, 128)),
        (P_NONCE, nonce_payload(16)),
    ])


def refused_pq_request(group, with_kem):
    transforms = [transform(T_ENCR, 20, False, key_length=256),
                  transform(T_PRF, 5, False)]
    if with_kem:
        transforms.append(transform(T_KE, 31, False))
        transforms.append(transform(T_ADDKE1, 36, True))
    else:
        transforms.append(transform(T_KE, 19, True))
    return ike_message(ISPI, NO_SPI, X_SA_INIT, F_INITIATOR, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(group, 64 if group == 19 else 32)),
        (P_NONCE, nonce_payload()),
    ])


def invalid_ke_response(group):
    """Section 2.7: "not that group, this one" -- IKEv2's HelloRetryRequest."""
    return ike_message(ISPI, NO_SPI, X_SA_INIT, F_RESPONSE, 0, [
        (P_NOTIFY, notify_payload(17, struct.pack(">H", group))),
    ])


def accepted_classical_response():
    transforms = [transform(T_ENCR, 20, False, key_length=256),
                  transform(T_PRF, 5, False),
                  transform(T_KE, 19, True)]
    return ike_message(ISPI, RSPI, X_SA_INIT, F_RESPONSE, 0, [
        (P_SA, sa_payload([proposal(1, 1, b"", transforms, last=True)])),
        (P_KE, ke_payload(19, 64)),
        (P_NONCE, nonce_payload()),
    ])


def ikev1_main_mode():
    """An ISAKMP Main Mode message: same 28-octet header, different everything.

    Its first payload is type 1 (SA), which does not exist in IKEv2's payload
    numbering -- which is exactly how it is told apart before anything tries
    to read a transform out of it."""
    body = fill(40, 0x30)
    blob = bytes([0, 0]) + struct.pack(">H", 4 + len(body)) + body
    header = (ISPI + NO_SPI + bytes([1, 0x10, 2, 0])
              + struct.pack(">II", 0, IKE_HDR + len(blob)))
    return header + blob


# --------------------------------------------------------------------------
# the captures
# --------------------------------------------------------------------------
def udp(payload, sport, dport, reverse=False, six=False):
    src, dst = (CLIENT6, SERVER6) if six else (CLIENT, SERVER)
    if reverse:
        src, dst = dst, src
        sport, dport = dport, sport
    network = IPv6(src=src, dst=dst) if six else IP(src=src, dst=dst)
    return (Ether(**ETH) / network / UDP(sport=sport, dport=dport)
            / Raw(payload))


def sa_init_only():
    """A complete, ordinary negotiation on port 500: a menu and a choice."""
    return [
        udp(classical_init_request(), 500, 500),
        udp(classical_init_response(), 500, 500, reverse=True),
        udp(encrypted(X_AUTH, F_INITIATOR, 1), 500, 500),
        udp(encrypted(X_AUTH, F_RESPONSE, 1), 500, 500, reverse=True),
    ]


def post_quantum():
    """RFC 9370 + RFC 8784.

    The two IKE_INTERMEDIATE messages are where the KEM's key exchange
    actually happens, and they are encrypted -- so they are visible as a
    count and as nothing else."""
    return [
        udp(post_quantum_init_request(), 500, 500),
        udp(post_quantum_init_response(), 500, 500, reverse=True),
        udp(encrypted(X_INTERMEDIATE, F_INITIATOR, 1), 500, 500),
        udp(encrypted(X_INTERMEDIATE, F_RESPONSE, 1), 500, 500, reverse=True),
        udp(encrypted(X_AUTH, F_INITIATOR, 2), 500, 500),
    ]


def legacy():
    """Still deployed, and broken today rather than in 2035."""
    return [
        udp(legacy_init_request(), 500, 500),
        udp(legacy_init_response(), 500, 500, reverse=True),
    ]


def pq_refused():
    """A post-quantum offer turned down.

    The responder demands secp256r1 with INVALID_KE_PAYLOAD and the initiator
    comes back without the KEM."""
    return [
        udp(refused_pq_request(31, with_kem=True), 500, 500),
        udp(invalid_ke_response(19), 500, 500, reverse=True),
        udp(refused_pq_request(19, with_kem=False), 500, 500),
        udp(accepted_classical_response(), 500, 500, reverse=True),
    ]


def natt_4500():
    """Port 4500, where IKE and ESP share a port and four zero octets are the
    only thing that tells them apart."""
    return [
        udp(NON_ESP_MARKER + classical_init_request(), 4500, 4500),
        udp(NON_ESP_MARKER + classical_init_response(), 4500, 4500,
            reverse=True),
        udp(NON_ESP_MARKER + encrypted(X_AUTH, F_INITIATOR, 1), 4500, 4500),
        udp(esp_packet(ESP_SPI, 1), 4500, 4500),
        udp(esp_packet(ESP_SPI + 0x10000, 1), 4500, 4500, reverse=True),
        udp(b"\xff", 4500, 4500),
    ]


def esp_only():
    """A capture that started after the tunnel was already up.

    ESP and nothing else, which is the common real case. The useful finding
    is that there is a VPN here at all."""
    return [udp(esp_packet(ESP_SPI, n), 4500, 4500, reverse=bool(n % 2))
            for n in range(1, 7)]


def ikev1():
    """IKEv1 on the same port and behind the same header.

    Must be named, counted and not parsed."""
    return [
        udp(ikev1_main_mode(), 500, 500),
        udp(ikev1_main_mode(), 500, 500, reverse=True),
    ]


def ipv6():
    """The same negotiation over IPv6.

    So the shared framing walk in cryptomon/parsers/framing.py is exercised
    on this path too."""
    return [
        udp(classical_init_request(), 500, 500, six=True),
        udp(classical_init_response(), 500, 500, reverse=True, six=True),
    ]


# Built one at a time rather than all at once, because each is built from the
# module-level addresses and SPIs that `use_capture` rewrites between them.
CAPTURES = (
    ("ikev2_sa_init", sa_init_only),
    ("ikev2_post_quantum", post_quantum),
    ("ikev2_legacy", legacy),
    ("ikev2_pq_refused", pq_refused),
    ("ikev2_natt_4500", natt_4500),
    ("ikev2_esp_only", esp_only),
    ("ikev2_ikev1", ikev1),
    ("ikev2_ipv6", ipv6),
)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    total = 0
    for index, (name, build) in enumerate(CAPTURES, start=1):
        use_capture(index)
        packets = build()
        for position, packet in enumerate(packets):
            packet.time = BASE_TIME + position * TICK
        path = OUT / "{0}.pcap".format(name)
        wrpcap(str(path), packets)
        size = path.stat().st_size
        total += size
        print("  wrote  ikev2/{0}.pcap  {1} packets, {2} bytes  ({3})".format(
            name, len(packets), size, CLIENT))
    print("\n{0} bytes total".format(total))
    print("no IKEv2 exists in the corpus; these are the only IKEv2 bytes "
          "this project has.")


if __name__ == "__main__":
    sys.exit(main())
