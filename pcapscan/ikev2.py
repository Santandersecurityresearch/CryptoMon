"""
IKEv2 over UDP: what an IPsec tunnel agreed on, in the clear, before it goes dark.

**Why this protocol is worth more per packet than any other here.** TLS makes
you infer: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` is one code point that has
to be unpicked into four decisions, and in TLS 1.3 the suite stopped naming
the key exchange at all. IKEv2 does the opposite. RFC 7296 puts the
encryption algorithm, the integrity algorithm, the PRF and the Diffie-Hellman
group on the wire as four separately numbered transforms, in an `IKE_SA_INIT`
exchange that happens before anything is encrypted -- and it sends both the
initiator's whole menu and the responder's single choice. One request and one
response are a complete, unambiguous statement of an estate's IPsec
cryptography.

It is also where the post-quantum story is legible rather than inferred:

  RFC 8784  a post-quantum preshared key, announced by the `USE_PPK` notify.
            It does not change the key exchange; it mixes a shared secret
            into the keys so that a recorded session cannot be opened later
            by breaking the Diffie-Hellman. "Harvest now, decrypt later" is
            the threat this answers, and seeing the notify is seeing an
            estate answer it.
  RFC 9370  multiple key exchanges. Transform types 6..12 carry up to seven
            *additional* key exchanges alongside the one in transform type 4,
            which is how a KEM is bolted to a classical group without
            trusting either alone. This is a hybrid in the precise sense
            `cryptomon.analysis` means, and the name this module emits --
            `x25519+ml-kem-768` -- is built so that the existing marker table
            classifies it as one without needing to learn a new word.

**What this module refuses to do.** IKEv1 uses the same 28-byte ISAKMP header
and a different everything else: its SA payload nests DOI, situation and
attribute-encoded proposals where IKEv2 nests transforms. Reading an IKEv1
message at IKEv2's offsets produces a well-formed-looking answer that is
wrong -- transform types read out of attribute headers, group numbers read
out of lengths -- which is the worst failure mode a crypto inventory can
have. So major version 1 is recognised, counted and reported as IKEv1 with no
algorithms attached. RFC 9395 deprecated it; "there is deprecated IKEv1 here"
is a finding on its own and does not need to be dressed up as transforms.

**Port 4500 carries two protocols and tells them apart with four bytes.**
RFC 3948 multiplexes IKE and ESP on the same port: IKE is prefixed with four
zero octets (the non-ESP marker) and ESP is not, which works because an ESP
SPI may not be zero. Get that wrong and an encrypted ESP packet is parsed as
an IKE header, and the report grows a proposal made of ciphertext. A single
0xFF octet is a NAT keepalive and is neither.

**ESP is reported as present and opaque, and that is the honest answer.** An
ESP packet is an SPI, a sequence number and ciphertext; there is nothing to
decode and never will be. "There is a VPN between these two addresses and we
cannot see inside it" is a real finding for a readiness report -- it is
traffic whose cryptography this tool cannot account for -- and it is better
said out loud than left out of the totals.

**There is no IKEv2 in this project's capture corpus.** Zero packets on UDP
500 or 4500 and zero of IP protocol 50 across all 160,221 packets, checked
rather than assumed. Every number this module has been measured against comes
from the fixtures in `tests/fixtures/ikev2/`, which are built from RFC 7296's
own field layouts by `tests/tools/make_ikev2_fixtures.py`. Nothing here has
been validated against traffic from a real VPN concentrator, and the tests
say so where it matters.

Bounds, because this parses attacker-chosen bytes behind an upload form: the
payload chain is a linked list whose lengths the sender picks, and the SA
payload nests three deep (proposal -> transform -> attribute). Every walk has
an iteration cap *and* checks its length against its parent's remaining
bytes, and no length field ever sizes an allocation -- the only slicing is of
a buffer that already exists.
"""
import collections
import hashlib

from cryptomon.utils import PARSE_STATS

# --------------------------------------------------------------------------
# the wire format (RFC 7296 section 3)
# --------------------------------------------------------------------------
IKE_HDR_LEN = 28
PAYLOAD_HDR_LEN = 4
PROPOSAL_HDR_LEN = 8
TRANSFORM_HDR_LEN = 8
ATTRIBUTE_HDR_LEN = 4

# RFC 3948 section 2.2. Four zero octets in front of an IKE message on port
# 4500; absent on an ESP one. Unambiguous because RFC 4303 forbids a zero SPI.
NON_ESP_MARKER = b'\x00\x00\x00\x00'
# RFC 3948 section 4: one octet of 0xFF, sent to keep a NAT mapping alive.
NAT_KEEPALIVE = b'\xff'

FLAG_INITIATOR = 0x08
FLAG_VERSION = 0x10
FLAG_RESPONSE = 0x20
# Bits 0-2 and 6-7 of the flags octet are reserved and "MUST be sent as
# zero". Checking them is most of what makes detection cheap and certain.
FLAGS_RESERVED = 0x07 | 0xC0

PAYLOAD_NONE = 0
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_NONCE = 40
PAYLOAD_NOTIFY = 41
PAYLOAD_VENDOR_ID = 43
PAYLOAD_SK = 46
PAYLOAD_SKF = 53

PAYLOAD_NAMES = {
    0: 'None', 33: 'SA', 34: 'KE', 35: 'IDi', 36: 'IDr', 37: 'CERT',
    38: 'CERTREQ', 39: 'AUTH', 40: 'Nonce', 41: 'Notify', 42: 'Delete',
    43: 'VendorID', 44: 'TSi', 45: 'TSr', 46: 'SK', 47: 'CP', 48: 'EAP',
    49: 'GSPM', 50: 'IDg', 51: 'GSA', 52: 'KD', 53: 'SKF', 54: 'PS',
}
# The lowest and highest payload type RFC 7296 and its extensions assign. A
# first payload outside this range is not a payload type, which is one of the
# cheapest ways to refuse a datagram that is not IKE at all.
PAYLOAD_MIN, PAYLOAD_MAX = 33, 54
# IKEv1's own range (RFC 2408): SA is 1, not 33. Used only to recognise an
# IKEv1 message so that it can be refused by name.
PAYLOAD_MIN_V1, PAYLOAD_MAX_V1 = 1, 13

EXCHANGE_IKE_SA_INIT = 34
EXCHANGE_IKE_AUTH = 35
EXCHANGE_CREATE_CHILD_SA = 36
EXCHANGE_INFORMATIONAL = 37
EXCHANGE_IKE_INTERMEDIATE = 43
EXCHANGE_IKE_FOLLOWUP_KE = 44

EXCHANGE_NAMES = {
    34: 'IKE_SA_INIT', 35: 'IKE_AUTH', 36: 'CREATE_CHILD_SA',
    37: 'INFORMATIONAL', 38: 'IKE_SESSION_RESUME', 39: 'GSA_AUTH',
    40: 'GSA_REGISTRATION', 41: 'GSA_REKEY', 43: 'IKE_INTERMEDIATE',
    44: 'IKE_FOLLOWUP_KE',
}
# IKEv1's exchange types, listed only so that an IKEv1 message can be
# recognised as one rather than mistaken for a corrupt IKEv2 one.
EXCHANGE_NAMES_V1 = {
    0: 'NONE', 1: 'Base', 2: 'Identity Protection (Main Mode)',
    3: 'Authentication Only', 4: 'Aggressive', 5: 'Informational',
    32: 'Quick Mode', 33: 'New Group Mode',
}

PROTOCOL_NAMES = {1: 'IKE', 2: 'AH', 3: 'ESP', 4: 'FC_ESP_HEADER',
                  5: 'FC_CT_AUTHENTICATION'}

# --------------------------------------------------------------------------
# transforms (RFC 7296 section 3.3.2, extended by RFC 9370)
# --------------------------------------------------------------------------
TRANSFORM_ENCR = 1
TRANSFORM_PRF = 2
TRANSFORM_INTEG = 3
TRANSFORM_KE = 4
TRANSFORM_ESN = 5
# RFC 9370 renamed type 4 from "Diffie-Hellman Group" to "Key Exchange
# Method" and added seven more of them. They start at 6 and not lower: types
# 1-5 were already spent on ENCR, PRF, INTEG, D-H and ESN by RFC 7296, so any
# description of the additional key exchanges as "types 3-7" or "types 5-7"
# has them colliding with INTEG, D-H and ESN. See the note in this PR's report.
TRANSFORM_ADDKE_FIRST = 6
TRANSFORM_ADDKE_LAST = 12

TRANSFORM_TYPES = {
    TRANSFORM_ENCR: 'ENCR', TRANSFORM_PRF: 'PRF', TRANSFORM_INTEG: 'INTEG',
    TRANSFORM_KE: 'KE', TRANSFORM_ESN: 'ESN',
    6: 'ADDKE1', 7: 'ADDKE2', 8: 'ADDKE3', 9: 'ADDKE4', 10: 'ADDKE5',
    11: 'ADDKE6', 12: 'ADDKE7',
}

# Attribute type 14, the key length in bits, and the only attribute IKEv2
# defines. It is what makes an encryption transform mean anything: ENCR_AES_CBC
# is not an algorithm, it is three of them.
ATTRIBUTE_KEY_LENGTH = 14
ATTRIBUTE_NAMES = {14: 'Key Length'}

# (IANA name, variable-key template). The template exists because the key
# length arrives in a separate attribute and a name that omits it is a name
# that cannot be classified or compared: `cryptomon.analysis` reads the
# strength off `AES_128` / `AES_256` in the name, and an entry called
# `ENCR_AES_CBC` would be counted as a cipher of unknown strength forever.
# The size is inserted where the IANA-registered TLS and IPsec names put it,
# so `ENCR_AES_256_CBC` and not `ENCR_AES_CBC_256`.
ENCR_TRANSFORMS = {
    1: ('ENCR_DES_IV64', None),
    2: ('ENCR_DES', None),
    3: ('ENCR_3DES', None),
    4: ('ENCR_RC5', 'ENCR_RC5_{0}'),
    5: ('ENCR_IDEA', None),
    6: ('ENCR_CAST', 'ENCR_CAST_{0}'),
    7: ('ENCR_BLOWFISH', 'ENCR_BLOWFISH_{0}'),
    8: ('ENCR_3IDEA', None),
    9: ('ENCR_DES_IV32', None),
    11: ('ENCR_NULL', None),
    12: ('ENCR_AES_CBC', 'ENCR_AES_{0}_CBC'),
    13: ('ENCR_AES_CTR', 'ENCR_AES_{0}_CTR'),
    14: ('ENCR_AES_CCM_8', 'ENCR_AES_{0}_CCM_8'),
    15: ('ENCR_AES_CCM_12', 'ENCR_AES_{0}_CCM_12'),
    16: ('ENCR_AES_CCM_16', 'ENCR_AES_{0}_CCM_16'),
    18: ('ENCR_AES_GCM_8', 'ENCR_AES_{0}_GCM_8'),
    19: ('ENCR_AES_GCM_12', 'ENCR_AES_{0}_GCM_12'),
    20: ('ENCR_AES_GCM_16', 'ENCR_AES_{0}_GCM_16'),
    21: ('ENCR_NULL_AUTH_AES_GMAC', 'ENCR_NULL_AUTH_AES_{0}_GMAC'),
    23: ('ENCR_CAMELLIA_CBC', 'ENCR_CAMELLIA_{0}_CBC'),
    24: ('ENCR_CAMELLIA_CTR', 'ENCR_CAMELLIA_{0}_CTR'),
    25: ('ENCR_CAMELLIA_CCM_8', 'ENCR_CAMELLIA_{0}_CCM_8'),
    26: ('ENCR_CAMELLIA_CCM_12', 'ENCR_CAMELLIA_{0}_CCM_12'),
    27: ('ENCR_CAMELLIA_CCM_16', 'ENCR_CAMELLIA_{0}_CCM_16'),
    28: ('ENCR_CHACHA20_POLY1305', None),
    29: ('ENCR_AES_CCM_8_IIV', 'ENCR_AES_{0}_CCM_8_IIV'),
    30: ('ENCR_AES_GCM_16_IIV', 'ENCR_AES_{0}_GCM_16_IIV'),
    31: ('ENCR_CHACHA20_POLY1305_IIV', None),
    32: ('ENCR_KUZNYECHIK_MGM_KTREE', None),
    33: ('ENCR_MAGMA_MGM_KTREE', None),
    34: ('ENCR_KUZNYECHIK_MGM_MAC_KTREE', None),
    35: ('ENCR_MAGMA_MGM_MAC_KTREE', None),
}

PRF_TRANSFORMS = {
    1: 'PRF_HMAC_MD5', 2: 'PRF_HMAC_SHA1', 3: 'PRF_HMAC_TIGER',
    4: 'PRF_AES128_XCBC', 5: 'PRF_HMAC_SHA2_256', 6: 'PRF_HMAC_SHA2_384',
    7: 'PRF_HMAC_SHA2_512', 8: 'PRF_AES128_CMAC',
    9: 'PRF_HMAC_STREEBOG_512',
}

INTEG_TRANSFORMS = {
    0: 'NONE', 1: 'AUTH_HMAC_MD5_96', 2: 'AUTH_HMAC_SHA1_96',
    3: 'AUTH_DES_MAC', 4: 'AUTH_KPDK_MD5', 5: 'AUTH_AES_XCBC_96',
    6: 'AUTH_HMAC_MD5_128', 7: 'AUTH_HMAC_SHA1_160', 8: 'AUTH_AES_CMAC_96',
    9: 'AUTH_AES_128_GMAC', 10: 'AUTH_AES_192_GMAC', 11: 'AUTH_AES_256_GMAC',
    12: 'AUTH_HMAC_SHA2_256_128', 13: 'AUTH_HMAC_SHA2_384_192',
    14: 'AUTH_HMAC_SHA2_512_256',
}

ESN_TRANSFORMS = {0: 'NO_ESN', 1: 'ESN'}

# The quantum-relevant table. The *names* matter as much as the numbers: they
# are fed straight to `cryptomon.analysis.classify_algorithm`, which decides
# post-quantum / hybrid / classical by looking for markers inside the string.
# So the MODP groups are spelled with a `dh-` prefix (the marker `dh`), the
# random ECP groups are spelled with their SEC1 names rather than as "Group
# 19" (the marker `secp`), and ML-KEM keeps the name the marker table already
# knows. A group that came out as "Group 19" would be classified `unknown`,
# and an unrecognised key exchange in a post-quantum readiness report is a
# finding thrown away.
KE_GROUPS = {
    0: 'none',
    1: 'dh-modp768',
    2: 'dh-modp1024',
    5: 'dh-modp1536',
    14: 'dh-modp2048',
    15: 'dh-modp3072',
    16: 'dh-modp4096',
    17: 'dh-modp6144',
    18: 'dh-modp8192',
    19: 'secp256r1',
    20: 'secp384r1',
    21: 'secp521r1',
    22: 'dh-modp1024-s160',
    23: 'dh-modp2048-s224',
    24: 'dh-modp2048-s256',
    25: 'secp192r1',
    26: 'secp224r1',
    27: 'brainpoolP224r1',
    28: 'brainpoolP256r1',
    29: 'brainpoolP384r1',
    30: 'brainpoolP512r1',
    31: 'x25519',
    32: 'x448',
    33: 'gostr3410-2012-256',
    34: 'gostr3410-2012-512',
    35: 'ml-kem-512',
    36: 'ml-kem-768',
    37: 'ml-kem-1024',
}

# Transform IDs 1024 and above are private use (RFC 7296 section 3.3.2), and
# implementations have shipped post-quantum KEMs in there for years. This
# module will not put a vendor's guessed name on one: a wrong algorithm name
# in a cryptography inventory is worse than an honest gap, and there is no
# registry to check it against. They are reported by number and land in
# `unknown`, which is exactly what they are.
KE_PRIVATE_USE_FIRST = 1024

# Already broken without any quantum computer, so worth saying separately
# from the quantum verdict -- the same distinction `cryptomon.analysis` draws
# when it reports RC4 as "broken independently of any quantum computer"
# rather than as 128 bits. Groups 1, 2 and 22 are the Logjam sizes.
WEAK_KE_GROUPS = frozenset({'dh-modp768', 'dh-modp1024', 'dh-modp1024-s160'})
WEAK_ENCR = frozenset({'ENCR_DES', 'ENCR_DES_IV32', 'ENCR_DES_IV64',
                       'ENCR_3DES', 'ENCR_NULL', 'ENCR_IDEA', 'ENCR_RC5',
                       'ENCR_BLOWFISH', 'ENCR_CAST', 'ENCR_3IDEA'})
WEAK_INTEG = frozenset({'AUTH_HMAC_MD5_96', 'AUTH_HMAC_MD5_128',
                        'AUTH_KPDK_MD5', 'AUTH_DES_MAC', 'NONE'})
WEAK_PRF = frozenset({'PRF_HMAC_MD5', 'PRF_HMAC_TIGER'})

# --------------------------------------------------------------------------
# notify types (RFC 7296 section 3.10.1 and its extensions)
# --------------------------------------------------------------------------
NOTIFY_INVALID_KE_PAYLOAD = 17
NOTIFY_NO_PROPOSAL_CHOSEN = 14
NOTIFY_COOKIE = 16390
NOTIFY_SIGNATURE_HASH_ALGORITHMS = 16431
NOTIFY_USE_PPK = 16435
NOTIFY_INTERMEDIATE_SUPPORTED = 16438
NOTIFY_ADDITIONAL_KEY_EXCHANGE = 16441

NOTIFY_NAMES = {
    # errors
    1: 'UNSUPPORTED_CRITICAL_PAYLOAD', 4: 'INVALID_IKE_SPI',
    5: 'INVALID_MAJOR_VERSION', 7: 'INVALID_SYNTAX', 9: 'INVALID_MESSAGE_ID',
    11: 'INVALID_SPI', 14: 'NO_PROPOSAL_CHOSEN', 17: 'INVALID_KE_PAYLOAD',
    24: 'AUTHENTICATION_FAILED', 34: 'SINGLE_PAIR_REQUIRED',
    35: 'NO_ADDITIONAL_SAS', 36: 'INTERNAL_ADDRESS_FAILURE',
    37: 'FAILED_CP_REQUIRED', 38: 'TS_UNACCEPTABLE', 39: 'INVALID_SELECTORS',
    40: 'UNACCEPTABLE_ADDRESSES', 41: 'UNEXPECTED_NAT_DETECTED',
    42: 'USE_ASSIGNED_HoA', 43: 'TEMPORARY_FAILURE',
    44: 'CHILD_SA_NOT_FOUND', 45: 'INVALID_GROUP_ID',
    46: 'AUTHORIZATION_FAILED', 47: 'STATE_NOT_FOUND',
    # status
    16384: 'INITIAL_CONTACT', 16385: 'SET_WINDOW_SIZE',
    16386: 'ADDITIONAL_TS_POSSIBLE', 16387: 'IPCOMP_SUPPORTED',
    16388: 'NAT_DETECTION_SOURCE_IP', 16389: 'NAT_DETECTION_DESTINATION_IP',
    16390: 'COOKIE', 16391: 'USE_TRANSPORT_MODE',
    16392: 'HTTP_CERT_LOOKUP_SUPPORTED', 16393: 'REKEY_SA',
    16394: 'ESP_TFC_PADDING_NOT_SUPPORTED', 16395: 'NON_FIRST_FRAGMENTS_ALSO',
    16396: 'MOBIKE_SUPPORTED', 16397: 'ADDITIONAL_IP4_ADDRESS',
    16398: 'ADDITIONAL_IP6_ADDRESS', 16399: 'NO_ADDITIONAL_ADDRESSES',
    16400: 'UPDATE_SA_ADDRESSES', 16401: 'COOKIE2', 16402: 'NO_NATS_ALLOWED',
    16403: 'AUTH_LIFETIME', 16404: 'MULTIPLE_AUTH_SUPPORTED',
    16405: 'ANOTHER_AUTH_FOLLOWS', 16406: 'REDIRECT_SUPPORTED',
    16407: 'REDIRECT', 16408: 'REDIRECTED_FROM', 16409: 'TICKET_LT_OPAQUE',
    16410: 'TICKET_REQUEST', 16411: 'TICKET_ACK', 16412: 'TICKET_NACK',
    16413: 'TICKET_OPAQUE', 16414: 'LINK_ID', 16415: 'USE_WESP_MODE',
    16416: 'ROHC_SUPPORTED', 16417: 'EAP_ONLY_AUTHENTICATION',
    16418: 'CHILDLESS_IKEV2_SUPPORTED', 16419: 'QUICK_CRASH_DETECTION',
    16420: 'IKEV2_MESSAGE_ID_SYNC_SUPPORTED',
    16421: 'IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED',
    16422: 'IKEV2_MESSAGE_ID_SYNC', 16423: 'IPSEC_REPLAY_COUNTER_SYNC',
    16424: 'SECURE_PASSWORD_METHODS', 16425: 'PSK_PERSIST',
    16426: 'PSK_CONFIRM', 16427: 'ERX_SUPPORTED', 16428: 'IFOM_CAPABILITY',
    16429: 'SENDER_REQUEST_ID', 16430: 'IKEV2_FRAGMENTATION_SUPPORTED',
    16431: 'SIGNATURE_HASH_ALGORITHMS', 16432: 'CLONE_IKE_SA_SUPPORTED',
    16433: 'CLONE_IKE_SA', 16434: 'PUZZLE', 16435: 'USE_PPK',
    16436: 'PPK_IDENTITY', 16437: 'NO_PPK_AUTH',
    16438: 'INTERMEDIATE_EXCHANGE_SUPPORTED', 16439: 'IP4_ALLOWED',
    16440: 'IP6_ALLOWED', 16441: 'ADDITIONAL_KEY_EXCHANGE',
    16442: 'USE_PPK_INT',
}

# RFC 7427. The notification data is a list of two-octet hash identifiers,
# which is how an IKEv2 peer says which signature hashes it will accept --
# the closest thing IKEv2 has to TLS's signature_algorithms extension.
SIGNATURE_HASH_ALGORITHMS = {1: 'SHA1', 2: 'SHA2-256', 3: 'SHA2-384',
                             4: 'SHA2-512', 5: 'Identity'}

# The negotiation signals worth lifting out of the notify list into their own
# field, because a consumer should not have to string-match a list to answer
# "is this estate doing RFC 8784".
NOTIFY_FLAGS = {
    NOTIFY_USE_PPK: 'post_quantum_preshared_key',
    16430: 'fragmentation',
    16418: 'childless',
    16396: 'mobike',
    NOTIFY_INTERMEDIATE_SUPPORTED: 'intermediate_exchange',
    16417: 'eap_only_authentication',
    16406: 'redirect_supported',
}

# --------------------------------------------------------------------------
# vendor IDs
# --------------------------------------------------------------------------
# Most well-known vendor IDs are the MD5 of a fixed string, so the table is
# written as the strings and hashed here rather than pasted in as hex. That
# way the derivation is visible, a reader can check it, and a typo in a
# 32-character hex constant cannot silently mislabel an implementation.
# MD5 is a naming convention in this table, not a security decision.
_VENDOR_ID_SOURCES = {
    'strongSwan': 'strongSwan',
    'Openswan / Libreswan': 'Openswan',
    'Microsoft Windows (MS NT5 ISAKMPOAKLEY)': 'MS NT5 ISAKMPOAKLEY',
    'Microsoft IKE fragmentation': 'FRAGMENTATION',
    'Microsoft negotiation discovery': 'MS-Negotiation Discovery Capable',
    'NAT-T (RFC 3947)': 'RFC 3947',
    'NAT-T (draft-ietf-ipsec-nat-t-ike-02)': 'draft-ietf-ipsec-nat-t-ike-02\n',
    'NAT-T (draft-ietf-ipsec-nat-t-ike-03)': 'draft-ietf-ipsec-nat-t-ike-03',
    'SSH Communications ESPThruNAT': 'ESPThruNAT',
    'Initial contact (Vid-Initial-Contact)': 'Vid-Initial-Contact',
    'GSSAPI': 'GSSAPI',
}
# `usedforsecurity=False` because this is not a security decision and because
# of *where* it runs: this table is built at import time, and on a FIPS build
# a bare `hashlib.md5()` raises. `pcapscan.datagrams.handlers` re-raises
# anything that is not a missing module, so an exception here would take down
# the whole capture parse rather than cost one vendor-ID label. The JA3 hash
# in `cryptomon/fingerprints.py` has the same call inside a function, where
# it costs one fingerprint; this one does not have that luxury.
VENDOR_IDS = {
    hashlib.md5(source.encode(), usedforsecurity=False).hexdigest(): name
    for name, source in _VENDOR_ID_SOURCES.items()
}
# Vendor IDs that are not a hash of anything: the implementation simply sends
# the ASCII. Kept separate so that the hashed table above stays derivable.
VENDOR_IDS.update({
    b'CISCO-DELETE-REASON'.hex(): 'Cisco (delete reason)',
    b'FLEXVPN-SUPPORTED'.hex(): 'Cisco FlexVPN',
    b'CISCO(COPYRIGHT)&Copyright (c) 2009 Cisco Systems, Inc.'.hex():
        'Cisco',
})

# --------------------------------------------------------------------------
# bounds
# --------------------------------------------------------------------------
# Every one of these bounds an attacker-chosen linked list or an
# attacker-chosen count. They are set well above what a real negotiation
# needs: strongSwan's default proposal is one proposal of about a dozen
# transforms, and RFC 7296 allows at most seven additional key exchanges.
MAX_PAYLOADS = 64
MAX_PROPOSALS = 32
MAX_TRANSFORMS = 64
MAX_ATTRIBUTES = 16
MAX_NOTIFIES = 32
MAX_VENDOR_IDS = 16
# Per flow. A flow may legitimately carry several IKE SAs (a rekey makes a
# new one with new SPIs), but not many, and each one costs a document.
MAX_SAS = 8
# Per SA. An IKE_SA_INIT may be retried after COOKIE or INVALID_KE_PAYLOAD,
# and it is the *first* and *last* of those that carry the finding -- what was
# asked for and what was forced. Keeping a handful keeps both ends.
MAX_INIT_MESSAGES = 4
# Bytes of an opaque blob kept, as hex. A notify's data and a vendor ID are
# both sender-controlled and neither needs to be kept whole to be identified.
MAX_NOTIFY_DATA = 64
MAX_VENDOR_ID_BYTES = 64
MAX_ESP_SPIS = 8

# An ESP packet is a 4-octet SPI, a 4-octet sequence number and ciphertext,
# and RFC 4303 reserves SPI values 1-255. A shorter or misaligned datagram is
# not ESP; a zero SPI is a non-ESP marker.
ESP_HDR_LEN = 8
ESP_SPI_RESERVED_MAX = 255

# The one place in this module where a port number is load-bearing, and it is
# marked so that it can be argued with. `pcapscan/protocols.py` settled that
# detection is by content -- but ESP has no content to detect: it is an opaque
# SPI followed by ciphertext, indistinguishable by design from any other
# random-looking datagram. Claiming ESP by content alone would mean claiming
# every unrecognised UDP flow in the capture. So ESP *on its own* is only
# claimed on UDP 4500, the port IANA assigned to it (`ipsec-nat-t`); ESP that
# follows IKE on a flow this handler already owns needs no port at all, which
# is the case the corpus would mostly contain if it contained any.
ESP_PORT = 4500
IKE_PORT = 500


# --------------------------------------------------------------------------
# reading the wire
# --------------------------------------------------------------------------
def _u16(data, offset):
    return (data[offset] << 8) | data[offset + 1]


def _u32(data, offset):
    return int.from_bytes(bytes(data[offset:offset + 4]), 'big')


def parse_header(data):
    """
    The 28-octet IKE header (RFC 7296 section 3.1), or None if it is not one.

    Never raises and never guesses. The return carries `plausible`, which is
    the whole-header consistency check `detect` rests on -- separated from the
    field extraction so that a message which fails it can still be counted
    and described rather than merely dropped.
    """
    if len(data) < IKE_HDR_LEN:
        return None
    initiator = bytes(data[0:8])
    responder = bytes(data[8:16])
    version = data[17]
    header = {
        'initiator_spi': initiator.hex(),
        'responder_spi': responder.hex(),
        'next_payload': data[16],
        'major': version >> 4,
        'minor': version & 0x0F,
        'exchange_type': data[18],
        'flags': data[19],
        'message_id': _u32(data, 20),
        'length': _u32(data, 24),
    }
    header['initiator'] = bool(header['flags'] & FLAG_INITIATOR)
    header['response'] = bool(header['flags'] & FLAG_RESPONSE)
    header['plausible'] = _header_is_plausible(header, initiator, responder,
                                               len(data))
    return header


def _header_is_plausible(header, initiator, responder, available):
    """
    Does every field of this header agree with every other and with the buffer?

    Seven independent checks, which is what makes it safe to claim a UDP flow
    on content alone. The strongest is the length: IKE carries the total
    message length in its own header and a UDP datagram carries exactly one
    message, so the two must be equal. Random bytes clear that one in about
    one case in 2^16, and the remaining checks in far fewer.
    """
    if initiator == b'\x00' * 8:
        return False                    # RFC 7296: "MUST NOT be zero"
    if header['length'] != available:
        return False
    if header['length'] < IKE_HDR_LEN:
        return False
    if header['minor'] != 0:
        return False
    next_payload = header['next_payload']
    if header['major'] == 2:
        # IKEv2 renumbered the payload types: v1's SA payload is type 1 and
        # v2's is 33, so this range check has to be asked per version. Asking
        # it once, with IKEv2's range, is how an IKEv1 Main Mode message --
        # whose first payload is type 1 -- stops being recognised as IKEv1 at
        # all and falls through to "not IKE", which is the opposite of the
        # named refusal this module is supposed to produce.
        if next_payload != PAYLOAD_NONE and not (
                PAYLOAD_MIN <= next_payload <= PAYLOAD_MAX):
            return False
        if header['exchange_type'] not in EXCHANGE_NAMES:
            return False
        if header['flags'] & FLAGS_RESERVED:
            return False
        # The very first message of an exchange asks the responder to pick an
        # SPI, so it cannot already know one. This is what tells an
        # IKE_SA_INIT request apart from eight bytes that happen to decode.
        if (header['exchange_type'] == EXCHANGE_IKE_SA_INIT
                and not header['response']
                and responder != b'\x00' * 8):
            return False
        return True
    if header['major'] == 1:
        # IKEv1 shares this header and nothing below it. Recognised so that
        # it can be refused by name; its flag octet has different bits (E, C,
        # A rather than I, V, R), so it is not checked.
        if next_payload != PAYLOAD_NONE and not (
                PAYLOAD_MIN_V1 <= next_payload <= PAYLOAD_MAX_V1):
            return False
        return header['exchange_type'] in EXCHANGE_NAMES_V1
    return False


def classify_datagram(payload):
    """
    What a UDP payload on an IKE port is, before anything tries to parse it.

    Returns (kind, body): 'ike' with the message bytes, 'keepalive' with
    None, 'esp' with the SPI, or (None, None). The order matters. RFC 3948
    puts a four-octet non-ESP marker in front of IKE on port 4500 and nothing
    in front of ESP, so four leading zeros mean "strip them"; but port 500
    carries IKE with no marker and an initiator SPI whose first four octets
    are legitimately allowed to be zero. So a marked-looking datagram is tried
    both ways and whichever produces a consistent header wins. Reading an ESP
    packet at IKE's offsets is how a report grows a proposal made of
    ciphertext.
    """
    if not payload:
        return None, None
    if payload == NAT_KEEPALIVE:
        return 'keepalive', None

    candidates = [payload]
    if payload[:4] == NON_ESP_MARKER:
        # Marker first: on 4500 it is mandatory, so it is the likelier read.
        candidates.insert(0, payload[4:])
    for candidate in candidates:
        header = parse_header(candidate)
        if header is not None and header['plausible']:
            return 'ike', candidate

    if looks_like_esp(payload):
        return 'esp', bytes(payload[0:4])
    return None, None


def looks_like_esp(payload):
    """
    Is this shaped like an ESP packet (RFC 4303)?

    A weak test on purpose, and documented as weak: ESP is ciphertext with an
    opaque SPI in front, so there is nothing stronger available. All this
    rules out is what ESP definitely is not -- too short to hold a header and
    one cipher block, not a multiple of four octets, or carrying an SPI in
    the range RFC 4303 reserves. It is never used on its own to claim a flow;
    see ESP_PORT.
    """
    if len(payload) < ESP_HDR_LEN + 8 or len(payload) % 4:
        return False
    return _u32(payload, 0) > ESP_SPI_RESERVED_MAX


def walk_payloads(data, first_payload):
    """
    The payload chain (RFC 7296 section 3.2), as a list of (type, body).

    A linked list whose `next` pointers and lengths are both chosen by the
    sender, walked with three separate bounds: an iteration cap, a floor on
    each length (a payload shorter than its own 4-octet header would make the
    walk stand still), and a ceiling from the parent buffer. Without the floor
    a message full of zero-length payloads is an infinite loop; without the
    ceiling a length of 65535 reads past the datagram.
    """
    payloads = []
    offset = IKE_HDR_LEN
    next_type = first_payload
    end = min(len(data), _u32(data, 24)) if len(data) >= IKE_HDR_LEN else 0
    for _ in range(MAX_PAYLOADS):
        if next_type == PAYLOAD_NONE:
            return payloads
        if offset + PAYLOAD_HDR_LEN > end:
            PARSE_STATS['ikev2_payload_truncated'] += 1
            return payloads
        following = data[offset]
        critical = bool(data[offset + 1] & 0x80)
        length = _u16(data, offset + 2)
        if length < PAYLOAD_HDR_LEN or offset + length > end:
            PARSE_STATS['ikev2_payload_bad_length'] += 1
            return payloads
        payloads.append({
            'type': next_type,
            'name': PAYLOAD_NAMES.get(next_type,
                                      'unknown-{0}'.format(next_type)),
            'critical': critical,
            'body': bytes(data[offset + PAYLOAD_HDR_LEN:offset + length]),
        })
        offset += length
        next_type = following
    PARSE_STATS['ikev2_payload_chain_too_long'] += 1
    return payloads


def parse_attributes(body):
    """
    A transform's attributes (RFC 7296 section 3.3.5).

    Two formats sharing one header, selected by the top bit of the first
    octet: set means the two octets that would be a length are the value
    itself (TV), clear means they are the length of a value that follows
    (TLV). Mixing the two up reads a key length of 256 as a promise of 256
    further octets, which is the sort of length-field confusion that ends in
    a read past the buffer.
    """
    attributes = []
    offset = 0
    for _ in range(MAX_ATTRIBUTES):
        if offset + ATTRIBUTE_HDR_LEN > len(body):
            break
        short_form = bool(body[offset] & 0x80)
        attr_type = ((body[offset] & 0x7F) << 8) | body[offset + 1]
        raw = _u16(body, offset + 2)
        if short_form:
            value, offset = raw, offset + ATTRIBUTE_HDR_LEN
        else:
            start = offset + ATTRIBUTE_HDR_LEN
            if start + raw > len(body):
                PARSE_STATS['ikev2_attribute_bad_length'] += 1
                break
            value = int.from_bytes(body[start:start + raw], 'big') if raw else None
            offset = start + raw
        attributes.append({
            'type': attr_type,
            'name': ATTRIBUTE_NAMES.get(attr_type,
                                        'unknown-{0}'.format(attr_type)),
            'format': 'TV' if short_form else 'TLV',
            'value': value,
        })
    return attributes


def transform_name(transform_type, transform_id, key_length=None):
    """
    The name this project uses for one (type, id) pair.

    These strings are an interface, not a display detail: `cryptomon.analysis`
    classifies a key exchange by looking for markers inside the name and
    `pcapscan.cbom` builds a bom-ref out of it, so a group reported as
    "Group 19" rather than "secp256r1" is a quantum-relevant fact that
    silently lands in the `unknown` bucket. Unknown values keep their number
    in the name for the same reason `cryptomon.utils.name_or_code` does:
    an unrecognised algorithm should stay identifiable afterwards.
    """
    if transform_type == TRANSFORM_ENCR:
        entry = ENCR_TRANSFORMS.get(transform_id)
        if entry is None:
            return 'unknown-encr-{0}'.format(transform_id)
        iana, template = entry
        if key_length and template:
            return template.format(key_length)
        return iana
    if transform_type == TRANSFORM_PRF:
        return PRF_TRANSFORMS.get(transform_id,
                                  'unknown-prf-{0}'.format(transform_id))
    if transform_type == TRANSFORM_INTEG:
        return INTEG_TRANSFORMS.get(transform_id,
                                    'unknown-integ-{0}'.format(transform_id))
    if transform_type == TRANSFORM_ESN:
        return ESN_TRANSFORMS.get(transform_id,
                                  'unknown-esn-{0}'.format(transform_id))
    if (transform_type == TRANSFORM_KE
            or TRANSFORM_ADDKE_FIRST <= transform_type <= TRANSFORM_ADDKE_LAST):
        return key_exchange_name(transform_id)
    return 'unknown-type{0}-{1}'.format(transform_type, transform_id)


def key_exchange_name(group):
    """A key exchange method ID (transform type 4, or 6..12) as a name."""
    known = KE_GROUPS.get(group)
    if known is not None:
        return known
    if group >= KE_PRIVATE_USE_FIRST:
        return 'unknown-ke-private-{0}'.format(group)
    return 'unknown-ke-{0}'.format(group)


def parse_transform(body, offset, limit):
    """
    One transform substructure (RFC 7296 section 3.3.2).

    `limit` is the end of the *proposal* that contains it, not the end of the
    message: a transform whose length runs past its proposal is malformed
    even when it fits in the datagram, and checking against the datagram
    instead is how a nested length check turns into no length check at all.
    """
    if offset + TRANSFORM_HDR_LEN > limit:
        PARSE_STATS['ikev2_transform_truncated'] += 1
        return None, limit
    last = body[offset]
    length = _u16(body, offset + 2)
    if length < TRANSFORM_HDR_LEN or offset + length > limit:
        PARSE_STATS['ikev2_transform_bad_length'] += 1
        return None, limit
    transform_type = body[offset + 4]
    transform_id = _u16(body, offset + 6)
    attributes = parse_attributes(
        body[offset + TRANSFORM_HDR_LEN:offset + length])
    key_length = None
    for attribute in attributes:
        if attribute['type'] == ATTRIBUTE_KEY_LENGTH:
            key_length = attribute['value']
    transform = {
        'type': transform_type,
        'type_name': TRANSFORM_TYPES.get(
            transform_type, 'unknown-{0}'.format(transform_type)),
        'id': transform_id,
        'name': transform_name(transform_type, transform_id, key_length),
        'last': last == 0,
    }
    if key_length is not None:
        transform['key_length'] = key_length
    other = [a for a in attributes if a['type'] != ATTRIBUTE_KEY_LENGTH]
    if other:
        transform['attributes'] = other
    return transform, offset + length


def parse_proposal(body, offset, limit):
    """One proposal substructure and its transforms (section 3.3.1)."""
    if offset + PROPOSAL_HDR_LEN > limit:
        PARSE_STATS['ikev2_proposal_truncated'] += 1
        return None, limit
    length = _u16(body, offset + 2)
    if length < PROPOSAL_HDR_LEN or offset + length > limit:
        PARSE_STATS['ikev2_proposal_bad_length'] += 1
        return None, limit
    end = offset + length
    number = body[offset + 4]
    protocol = body[offset + 5]
    spi_size = body[offset + 6]
    declared = body[offset + 7]
    spi_start = offset + PROPOSAL_HDR_LEN
    if spi_start + spi_size > end:
        PARSE_STATS['ikev2_proposal_bad_spi_size'] += 1
        return None, limit

    transforms = []
    cursor = spi_start + spi_size
    for _ in range(MAX_TRANSFORMS):
        if cursor >= end:
            break
        transform, cursor = parse_transform(body, cursor, end)
        if transform is None:
            break
        transforms.append(transform)
        if transform['last']:
            break

    proposal = {
        'number': number,
        'protocol': PROTOCOL_NAMES.get(protocol,
                                       'unknown-{0}'.format(protocol)),
        'transforms': transforms,
        # What the header claimed against what the bytes held. A mismatch is
        # not fatal -- everything above is bounded by length, not by this
        # count -- but it is exactly the kind of inconsistency worth keeping,
        # because a sender who lies about it is usually testing a parser.
        'transforms_declared': declared,
    }
    if spi_size:
        proposal['spi'] = bytes(body[spi_start:spi_start + spi_size]).hex()
    if declared != len(transforms):
        proposal['transform_count_mismatch'] = True
        PARSE_STATS['ikev2_transform_count_mismatch'] += 1
    return proposal, end


def parse_sa(body):
    """
    The Security Association payload (RFC 7296 section 3.3): the prize.

    One to many proposals, each one to many transforms, each transform zero
    to many attributes -- three levels of sender-chosen length nested inside
    each other, which is why every level here is given its parent's end and
    not the buffer's.
    """
    proposals = []
    offset = 0
    for _ in range(MAX_PROPOSALS):
        if offset >= len(body):
            break
        proposal, offset = parse_proposal(body, offset, len(body))
        if proposal is None:
            break
        proposals.append(proposal)
    return proposals


def parse_ke(body):
    """The Key Exchange payload (section 3.4): which group, and how big."""
    if len(body) < 4:
        PARSE_STATS['ikev2_ke_truncated'] += 1
        return None
    group = _u16(body, 0)
    return {'group': group, 'name': key_exchange_name(group),
            'key_bytes': len(body) - 4}


def parse_notify(body):
    """
    The Notify payload (section 3.10), with the few data fields worth decoding.

    Notify types are where IKEv2 says everything TLS puts in extensions:
    whether fragmentation is supported, which signature hashes are acceptable,
    whether a post-quantum preshared key is in play. The data is decoded only
    for the types whose layout is fixed and interesting; everything else keeps
    its bytes as bounded hex rather than being guessed at.
    """
    if len(body) < 4:
        PARSE_STATS['ikev2_notify_truncated'] += 1
        return None
    protocol = body[0]
    spi_size = body[1]
    notify_type = _u16(body, 2)
    if 4 + spi_size > len(body):
        PARSE_STATS['ikev2_notify_bad_spi_size'] += 1
        return None
    data = bytes(body[4 + spi_size:])
    notify = {
        'type': notify_type,
        'name': NOTIFY_NAMES.get(notify_type,
                                 'unknown-{0}'.format(notify_type)),
        'error': notify_type < 16384,
    }
    if protocol:
        notify['protocol'] = PROTOCOL_NAMES.get(
            protocol, 'unknown-{0}'.format(protocol))
    if spi_size:
        notify['spi'] = bytes(body[4:4 + spi_size]).hex()
    if notify_type == NOTIFY_SIGNATURE_HASH_ALGORITHMS:
        notify['hash_algorithms'] = [
            SIGNATURE_HASH_ALGORITHMS.get(_u16(data, i),
                                          'unknown-{0}'.format(_u16(data, i)))
            for i in range(0, len(data) - 1, 2)]
    elif notify_type == NOTIFY_INVALID_KE_PAYLOAD and len(data) >= 2:
        # The responder's counter-offer: "not that group, this one". This is
        # IKEv2's HelloRetryRequest, and the pair (what was asked for, what
        # was forced) is the whole downgrade finding.
        notify['group'] = _u16(data, 0)
        notify['group_name'] = key_exchange_name(notify['group'])
    elif data:
        notify['data'] = data[:MAX_NOTIFY_DATA].hex()
        if len(data) > MAX_NOTIFY_DATA:
            notify['data_truncated'] = len(data)
    return notify


def describe_vendor_id(body):
    """A vendor ID, named where it is one this project knows."""
    raw = bytes(body)
    entry = {'hex': raw[:MAX_VENDOR_ID_BYTES].hex()}
    name = VENDOR_IDS.get(raw.hex())
    if name is None:
        # Many vendor IDs are a known MD5 with a version suffix appended, so
        # a prefix match catches those the exact lookup misses.
        for known_hex, known_name in VENDOR_IDS.items():
            if raw.hex().startswith(known_hex):
                name = known_name
                break
    if name is None and _is_mostly_printable(raw):
        # The rest announce themselves in ASCII -- Cisco's do -- and printing
        # what the sender wrote is more useful than another hex string.
        name = raw.decode('ascii', 'replace')[:MAX_VENDOR_ID_BYTES]
    if name:
        entry['name'] = name
    return entry


def _is_mostly_printable(raw):
    if not raw:
        return False
    printable = sum(1 for byte in raw if 0x20 <= byte < 0x7F)
    return printable >= max(4, len(raw) * 3 // 4)


def parse_message(data):
    """
    One whole IKE message: header plus walked payload chain.

    Returns None only when the header itself does not decode. A message whose
    *payloads* are malformed still returns -- the header is the part that says
    what exchange this was, and losing that as well would turn a broken
    proposal into a flow that was never here.
    """
    header = parse_header(data)
    if header is None:
        return None
    message = dict(header)
    message['exchange'] = (
        EXCHANGE_NAMES.get(header['exchange_type'])
        if header['major'] == 2 else
        EXCHANGE_NAMES_V1.get(header['exchange_type']))
    if message['exchange'] is None:
        message['exchange'] = 'unknown-{0}'.format(header['exchange_type'])
    if header['major'] != 2:
        # Deliberately not walked. See the module docstring: IKEv1's payload
        # bodies are a different format behind an identical header.
        message['payloads'] = []
        return message
    message['payloads'] = walk_payloads(data, header['next_payload'])
    return message


# --------------------------------------------------------------------------
# what a message means to the SA it belongs to
# --------------------------------------------------------------------------
def summarise_message(message):
    """
    One IKE_SA_INIT half, as the facts a report wants.

    Both halves have the same shape, which is the point: the initiator's is a
    menu and the responder's is a single choice, and keeping them in the same
    shape is what lets `proposed` and `selected` be compared the way
    `pcapscan.sessions.Session.document` compares a ClientHello with a
    ServerHello.
    """
    view = {'proposals': [], 'notifies': [], 'vendor_ids': []}
    for payload in message['payloads']:
        kind = payload['type']
        if kind == PAYLOAD_SA:
            view['proposals'].extend(parse_sa(payload['body']))
        elif kind == PAYLOAD_KE:
            key_exchange = parse_ke(payload['body'])
            if key_exchange is not None:
                view['key_exchange'] = key_exchange
        elif kind == PAYLOAD_NONCE:
            view['nonce_bytes'] = len(payload['body'])
        elif kind == PAYLOAD_NOTIFY:
            if len(view['notifies']) < MAX_NOTIFIES:
                notify = parse_notify(payload['body'])
                if notify is not None:
                    view['notifies'].append(notify)
        elif kind == PAYLOAD_VENDOR_ID:
            if len(view['vendor_ids']) < MAX_VENDOR_IDS:
                view['vendor_ids'].append(describe_vendor_id(payload['body']))
        elif kind in (PAYLOAD_SK, PAYLOAD_SKF):
            view['encrypted'] = True
    view['payloads'] = [payload['name'] for payload in message['payloads']]
    if len(view['proposals']) > 1:
        view['proposal_count'] = len(view['proposals'])
    for notify in view['notifies']:
        flag = NOTIFY_FLAGS.get(notify['type'])
        if flag:
            view[flag] = True
        if notify['type'] == NOTIFY_SIGNATURE_HASH_ALGORITHMS:
            view['signature_hash_algorithms'] = notify.get('hash_algorithms')
    return view


def algorithms_of(proposal):
    """
    A proposal's transforms, grouped by what they are for.

    Returns a dict of lists, because a *proposal* is a menu: an initiator
    offers several encryption algorithms and the responder picks one. The
    responder's own proposal has exactly one of each (RFC 7296 section 3.3),
    which is what makes `selected` readable straight off this.
    """
    grouped = collections.OrderedDict()
    for transform in proposal.get('transforms', ()):
        slot = TRANSFORM_TYPES.get(transform['type'],
                                   'unknown-{0}'.format(transform['type']))
        grouped.setdefault(slot, []).append(transform['name'])
    return grouped


def combined_key_exchange(grouped):
    """
    The key exchange actually performed, as one classifiable name.

    RFC 9370's point is that the key exchange is no longer one algorithm: a
    peer agrees a classical group in transform type 4 *and* a KEM in one of
    types 6..12, and the session is as strong as the stronger of the two. The
    combined name is what says that. `x25519+ml-kem-768` normalises to
    `x25519mlkem768`, in which `cryptomon.analysis` finds a post-quantum
    marker and a classical one and answers `hybrid` -- which is the true
    answer, and the one neither half gives alone.
    """
    parts = []
    for slot in ['KE'] + ['ADDKE{0}'.format(n) for n in range(1, 8)]:
        # A *selected* proposal carries exactly one transform per type, so
        # the first name in each slot is the one that was agreed. Taking all
        # of them would turn an initiator's menu into a claim that every
        # group on it was used at once.
        name = _first(grouped.get(slot))
        if name and name != 'none':
            parts.append(name)
    if not parts:
        return None
    return '+'.join(parts)


# --------------------------------------------------------------------------
# the handler
# --------------------------------------------------------------------------
class _SecurityAssociation:
    """
    One IKE SA within a flow, keyed by the initiator's SPI.

    A flow is not an SA: a rekey creates a new SA with new SPIs over the same
    five-tuple, and folding those together would report one negotiation where
    there were two. Keyed by the initiator SPI because it is the only
    identifier present in every message of the SA, including the first, where
    the responder's SPI is still zero by definition.
    """

    __slots__ = ('initiator_spi', 'responder_spi', 'messages', 'requests',
                 'responses', 'first_ts', 'last_ts', 'encrypted_exchanges',
                 'initiator_endpoint', 'responder_endpoint', 'message_ids')

    def __init__(self, initiator_spi):
        self.initiator_spi = initiator_spi
        self.responder_spi = None
        self.messages = collections.Counter()
        self.requests = []
        self.responses = []
        self.first_ts = None
        self.last_ts = None
        self.encrypted_exchanges = collections.Counter()
        self.initiator_endpoint = None
        self.responder_endpoint = None
        self.message_ids = set()


class Ikev2Handler:
    """
    The `pcapscan.datagrams` handler for IKEv2, IKEv1 and UDP-encapsulated ESP.

    One instance per claimed flow. `finish` yields one document per IKE SA
    observed, plus one for ESP if any was seen, because an ESP Child SA is a
    different security association with different keys and a CBOM wants it as
    its own asset rather than as a footnote on the IKE one.
    """

    name = 'ikev2'
    # A hint for detector ordering only; see `DatagramRouter._detect`. Nothing
    # below decides anything from a port except the ESP-alone case, which says
    # so where it does it.
    ports = frozenset({IKE_PORT, ESP_PORT})

    @staticmethod
    def detect(payload, key):
        """
        Does this flow's first datagram look like IKE (or ESP on 4500)?

        Offered attacker-chosen bytes on every new UDP flow in the capture, so
        it is written to return rather than raise: every read is behind an
        explicit length check and no branch can index past the buffer.
        """
        kind, _body = classify_datagram(payload)
        if kind == 'ike':
            return True
        if kind == 'esp':
            # The documented exception to detection-by-content. ESP has no
            # content; see ESP_PORT.
            return ESP_PORT in (key.sport, key.dport)
        if kind == 'keepalive':
            # A NAT keepalive is one octet of 0xFF and says nothing about
            # what the flow carries -- but on 4500 it says an IPsec NAT
            # mapping is being held open, which is enough to claim the flow
            # and wait for the ESP or IKE that follows.
            return ESP_PORT in (key.sport, key.dport)
        return False

    def __init__(self):
        self.sas = collections.OrderedDict()
        self.stats = collections.Counter()
        self.esp_spis = collections.OrderedDict()
        self.esp_packets = 0
        self.esp_bytes = 0
        self.esp_port = None
        self.keepalives = 0
        self.ikev1 = collections.Counter()
        self.first_ts = None
        self.last_ts = None

    def push(self, timestamp, payload, key, datagram):
        """Deliver one datagram. Never raises for a malformed one."""
        self.stats['datagrams'] += 1
        if self.first_ts is None:
            self.first_ts = timestamp
        self.last_ts = timestamp

        kind, body = classify_datagram(payload)
        if kind == 'keepalive':
            self.keepalives += 1
            self._note_port(key)
            return
        if kind == 'esp':
            self._push_esp(key, body, len(payload))
            return
        if kind != 'ike':
            self.stats['unrecognised'] += 1
            return
        if len(payload) != len(body):
            self.stats['non_esp_marker'] += 1

        message = parse_message(body)
        if message is None:
            self.stats['header_unreadable'] += 1
            return
        if message['major'] != 2:
            # Counted, named and not parsed. The module docstring says why.
            self.stats['ikev1'] += 1
            self.ikev1[message['exchange']] += 1
            PARSE_STATS['ikev2_refused_ikev1'] += 1
            return
        self._absorb(timestamp, key, message)

    def _push_esp(self, key, spi, octets):
        self.esp_packets += 1
        self.esp_bytes += octets
        if len(self.esp_spis) < MAX_ESP_SPIS:
            self.esp_spis[spi.hex()] = True
        else:
            self.stats['esp_spis_dropped'] += 1
        self._note_port(key)

    def _note_port(self, key):
        """
        Where the tunnel is, for the ESP record.

        Also called for a NAT keepalive, which is the only thing some flows
        ever carry: a keepalive-only flow still says an IPsec NAT mapping is
        being held open between two addresses, and a record of that with no
        port in it is weaker than it needs to be.
        """
        if self.esp_port is None:
            self.esp_port = (ESP_PORT if ESP_PORT in (key.sport, key.dport)
                             else key.dport)

    def _absorb(self, timestamp, key, message):
        sa = self.sas.get(message['initiator_spi'])
        if sa is None:
            if len(self.sas) >= MAX_SAS:
                self.stats['sas_dropped'] += 1
                return
            sa = _SecurityAssociation(message['initiator_spi'])
            self.sas[message['initiator_spi']] = sa
        if sa.first_ts is None:
            sa.first_ts = timestamp
        sa.last_ts = timestamp
        sa.messages[message['exchange']] += 1
        sa.message_ids.add(message['message_id'])
        if message['responder_spi'] != '00' * 8:
            sa.responder_spi = message['responder_spi']

        endpoint = _endpoint(key.src, key.sport)
        if message['response']:
            sa.responder_endpoint = sa.responder_endpoint or endpoint
        else:
            sa.initiator_endpoint = sa.initiator_endpoint or endpoint

        if message['exchange_type'] != EXCHANGE_IKE_SA_INIT:
            # Everything after IKE_SA_INIT is inside an SK payload. The
            # exchange type is still readable and still worth counting: an
            # IKE_INTERMEDIATE or IKE_FOLLOWUP_KE is RFC 9370 doing an
            # additional key exchange, which is visible as a *count* even
            # though its contents are not.
            sa.encrypted_exchanges[message['exchange']] += 1
            return

        view = summarise_message(message)
        view['message_id'] = message['message_id']
        bucket = sa.responses if message['response'] else sa.requests
        if len(bucket) < MAX_INIT_MESSAGES:
            bucket.append(view)
        else:
            self.stats['init_messages_dropped'] += 1

    # -- reporting ---------------------------------------------------------
    def finish(self):
        """One document per IKE SA, plus one for ESP and one for IKEv1."""
        documents = []
        for sa in self.sas.values():
            documents.append({'ikev2': self._sa_document(sa)})
        if self.esp_packets or (self.keepalives and not self.sas):
            documents.append({'ikev2': self._esp_document()})
        if self.ikev1:
            documents.append({'ikev2': self._ikev1_document()})
        return documents

    def _sa_document(self, sa):
        first_request = sa.requests[0] if sa.requests else {}
        last_request = sa.requests[-1] if sa.requests else {}
        response = self._successful_response(sa)

        proposed = _view_document(first_request)
        selected = _view_document(response) if response is not None else None

        record = {
            'kind': 'ike',
            'version': '2.0',
            'initiator_spi': sa.initiator_spi,
            'responder_spi': sa.responder_spi,
            'initiator': sa.initiator_endpoint,
            'responder': sa.responder_endpoint,
            'messages': dict(sa.messages),
            'message_ids': sorted(sa.message_ids),
            'proposed': proposed,
            'selected': selected,
        }
        if sa.encrypted_exchanges:
            # Not a failure: it is what an SK payload looks like from outside.
            record['encrypted_exchanges'] = dict(sa.encrypted_exchanges)
        if sa.encrypted_exchanges.get('IKE_INTERMEDIATE') or \
                sa.encrypted_exchanges.get('IKE_FOLLOWUP_KE'):
            record['additional_key_exchanges_performed'] = (
                sa.encrypted_exchanges.get('IKE_INTERMEDIATE', 0)
                + sa.encrypted_exchanges.get('IKE_FOLLOWUP_KE', 0))

        self._add_negotiated(record, sa, first_request, last_request, response)
        self._add_signals(record, first_request, response)
        if self.esp_packets:
            record['esp_packets'] = self.esp_packets
        return record

    @staticmethod
    def _successful_response(sa):
        """
        The IKE_SA_INIT response that actually carries a choice.

        A responder that answers COOKIE or INVALID_KE_PAYLOAD sends no SA
        payload -- it is asking for the request again. Taking the first
        response regardless would report "nothing was selected" for an
        exchange that went on to succeed, and taking the last would hide the
        refusal. So the successful one is the one with proposals in it, and
        the refusals are kept separately as the retry evidence.
        """
        for response in sa.responses:
            if response.get('proposals'):
                return response
        return sa.responses[-1] if sa.responses else None

    def _add_negotiated(self, record, sa, first_request, last_request,
                        response):
        """
        What was agreed, distinguished from what was merely offered.

        The distinction is the whole reason this module keeps both halves. An
        IKE_SA_INIT request offers a menu; until a response has been seen,
        nothing has been negotiated, and reporting the initiator's first
        choice as the session's key exchange would make a one-sided capture
        look like a successful post-quantum negotiation whenever the client
        happened to ask for one. So `kex_group` is populated only from a
        response, and `evidence` says which it was.
        """
        offered = _offered_key_exchange(first_request)
        if offered:
            record['offered_kex_group'] = offered

        retry = None
        for candidate in (response or {}).get('notifies', ()):
            if candidate['type'] == NOTIFY_INVALID_KE_PAYLOAD:
                retry = candidate.get('group_name')
        if retry is None and len(sa.requests) > 1:
            retry = (last_request.get('key_exchange') or {}).get('name')
        if retry and retry != offered:
            record['retry_kex_group'] = retry

        chosen = (response or {}).get('proposals') or []
        if not chosen:
            record['kex_group'] = None
            record['evidence'] = ('request only -- no IKE_SA_INIT response '
                                  'with an SA payload was captured'
                                  if response is None else
                                  'responder sent no SA payload')
            record['proposed_kex_groups'] = sorted({
                name
                for proposal in first_request.get('proposals') or []
                for name in algorithms_of(proposal).get('KE', ())
                if name != 'none'})
            return

        grouped = algorithms_of(chosen[0])
        record['evidence'] = 'IKE_SA_INIT response'
        record['kex_group'] = combined_key_exchange(grouped)
        record['encryption'] = _first(grouped.get('ENCR'))
        record['prf'] = _first(grouped.get('PRF'))
        record['integrity'] = _first(grouped.get('INTEG'))
        record['esn'] = _first(grouped.get('ESN'))
        additional = [name for slot, names in grouped.items()
                      if slot.startswith('ADDKE')
                      for name in names if name != 'none']
        if additional:
            record['additional_kex_groups'] = additional
        weak = _weaknesses(grouped)
        if weak:
            record['weak'] = weak

    @staticmethod
    def _add_signals(record, first_request, response):
        """The notify-borne capabilities, lifted out of both directions."""
        for flag in sorted(set(NOTIFY_FLAGS.values())):
            asked = bool(first_request.get(flag))
            answered = bool((response or {}).get(flag))
            if asked or answered:
                record[flag] = 'agreed' if asked and answered else (
                    'proposed' if asked else 'offered by responder')
        hashes = (first_request.get('signature_hash_algorithms')
                  or (response or {}).get('signature_hash_algorithms'))
        if hashes:
            record['signature_hash_algorithms'] = hashes
        vendor_ids = list(first_request.get('vendor_ids') or [])
        vendor_ids.extend((response or {}).get('vendor_ids') or [])
        if vendor_ids:
            record['vendor_ids'] = vendor_ids[:MAX_VENDOR_IDS]
        errors = [notify['name'] for notify in (response or {}).get(
            'notifies', ()) if notify['error']]
        if errors:
            record['errors'] = errors

    def _esp_document(self):
        """
        The honest report on a tunnel whose contents cannot be read.

        Not a failure to parse: ESP is ciphertext with an opaque SPI in front
        and there is nothing in it to decode, now or ever. It is recorded
        because a readiness report that silently omits the traffic it cannot
        account for is more misleading than one that names it -- "there is a
        VPN between these two addresses carrying N packets and we cannot see
        what it negotiated" is a finding, and if the IKE_SA_INIT was missed
        it may be the only one available.
        """
        return {
            'kind': 'esp',
            'opaque': True,
            'opaque_reason': (
                'ESP carries an opaque SPI and ciphertext; the algorithms '
                'were negotiated in an IKE_SA_INIT that is not in this flow'),
            'esp': {
                'spis': list(self.esp_spis),
                'packets': self.esp_packets,
                'bytes': self.esp_bytes,
                'encapsulation': 'udp',
                'port': self.esp_port,
                'nat_keepalives': self.keepalives,
            },
            'kex_group': None,
        }

    def _ikev1_document(self):
        """IKEv1, named and refused. RFC 9395 deprecated it; that is the finding."""
        return {
            'kind': 'ikev1',
            'version': '1.0',
            'refused': True,
            # `opaque` rather than a third case for the analysis layer to
            # learn: it means the same thing ESP means -- this flow performed
            # a key exchange that this tool cannot account for. Leaving it
            # out would make an IKEv1 session count as "no key exchange
            # performed", which is a different and false claim.
            'opaque': True,
            'opaque_reason': (
                'IKEv1 shares the IKEv2 header and shares nothing below it; '
                'parsing it at IKEv2 offsets would report transforms that '
                'are not there. RFC 9395 deprecates IKEv1.'),
            'messages': dict(self.ikev1),
            'kex_group': None,
            'weak': ['IKEv1 (deprecated by RFC 9395)'],
        }


def _first(names):
    return names[0] if names else None


def _endpoint(address, port):
    """
    'host:port', bracketing IPv6 so the port is not read as another hextet.

    `2001:db8::1:500` is a valid IPv6 address in its own right, so the
    unbracketed form is not merely ugly -- it is a different, parseable and
    wrong answer. RFC 3986 section 3.2.2.
    """
    if ':' in str(address):
        return '[{0}]:{1}'.format(address, port)
    return '{0}:{1}'.format(address, port)


def _offered_key_exchange(request):
    """
    The whole key exchange an initiator tried for, classical half and all.

    The KE payload carries only the transform-type-4 group, so reading the
    offer off it alone reports `x25519` for an initiator that asked for
    `x25519+ml-kem-768` -- and an offer that classifies as `classical`
    cannot be seen to have been refused, which loses exactly the finding a
    readiness report exists for. The additional key exchanges come from the
    first proposal's type 6..12 transforms, taking the first option in each
    slot: IKEv2 proposals are ordered by the sender's preference, and a peer
    that offers `ml-kem-768` before `none` is asking for the KEM.
    """
    offered = (request.get('key_exchange') or {}).get('name')
    parts = [offered] if offered and offered != 'none' else []
    proposals = request.get('proposals') or []
    if proposals:
        grouped = algorithms_of(proposals[0])
        for slot in ('ADDKE{0}'.format(n) for n in range(1, 8)):
            name = _first(grouped.get(slot))
            if name and name != 'none':
                parts.append(name)
    return '+'.join(parts) if parts else None


def _view_document(view):
    """One IKE_SA_INIT half, trimmed to what belongs in a record."""
    if not view:
        return None
    document = {
        'payloads': view.get('payloads', []),
        'proposals': [
            dict(proposal, algorithms=dict(algorithms_of(proposal)))
            for proposal in view.get('proposals', ())],
        'notifies': [notify['name'] for notify in view.get('notifies', ())],
    }
    for optional in ('key_exchange', 'nonce_bytes', 'vendor_ids',
                     'signature_hash_algorithms', 'proposal_count'):
        if view.get(optional) is not None:
            document[optional] = view[optional]
    return document


def _weaknesses(grouped):
    """
    Choices that are already broken, without reference to any quantum computer.

    Separated from the quantum verdict for the same reason
    `cryptomon.analysis` separates RC4 from RSA: an estate still negotiating
    1024-bit MODP or 3DES has a problem this decade, and folding that into
    "classical, like everything else" loses it.
    """
    weak = []
    for slot, broken in (('KE', WEAK_KE_GROUPS), ('ENCR', WEAK_ENCR),
                         ('INTEG', WEAK_INTEG), ('PRF', WEAK_PRF)):
        weak.extend(name for name in grouped.get(slot, ())
                    if name in broken)
    return weak


HANDLER = Ikev2Handler

__all__ = ['HANDLER', 'Ikev2Handler', 'classify_datagram', 'parse_header',
           'parse_message', 'parse_sa', 'parse_proposal', 'parse_transform',
           'parse_attributes', 'parse_notify', 'parse_ke', 'walk_payloads',
           'transform_name', 'key_exchange_name', 'combined_key_exchange',
           'algorithms_of', 'describe_vendor_id', 'looks_like_esp',
           'summarise_message', 'KE_GROUPS', 'ENCR_TRANSFORMS',
           'PRF_TRANSFORMS', 'INTEG_TRANSFORMS', 'NOTIFY_NAMES',
           'EXCHANGE_NAMES', 'PAYLOAD_NAMES', 'TRANSFORM_TYPES',
           'VENDOR_IDS', 'NON_ESP_MARKER', 'IKE_HDR_LEN']
