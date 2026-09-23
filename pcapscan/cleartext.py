"""
The inventory of what is not protected at all.

CryptoMon exists to answer "what fraction of this traffic would survive a
quantum computer". This module answers the question standing next to it:
*what fraction would not survive the person on the next desk*. Both are
findings, and the second is actionable this afternoon.

Every other parser in this repository reports on cryptography that is
present -- a ciphersuite, a key exchange group, a certificate key size. This
one reports on its absence, and on this corpus the absence is the larger
number. Of the 30,531 UDP datagrams in the capture corpus, 11,722 are QUIC
and are handled elsewhere. Of the remaining 18,809 this module identifies
18,742, and **not one of them is encrypted**:

    2,851   no protection at all -- DNS, mDNS, DHCP, NetBIOS, CLDAP, NTP,
            SSDP, and the HSRP interface-state advertisements
   15,867   authenticated with a keyed MD5 digest, and readable
       24   authenticated with HMAC-SHA1, and readable

Reporting "this connection uses RSA-2048, which a quantum computer breaks"
while saying nothing about the sixteen thousand router-redundancy hellos
next to it would be an odd sort of completeness.

Three things shape the design, and the first two are taken directly from
`pcapscan/protocols.py`, which settled them for TCP.

**Detection is by content, never by port.** The `ports` set on the handler
orders the detectors and nothing else. Every protocol here is recognised
from its own bytes -- a magic cookie, a length field that agrees with the
buffer, a name section that walks cleanly to its end -- and the corpus
rewards that: the single most interesting cleartext flow in it sits on UDP
53582, a port no table names, and the second most interesting on 52311.
Where an *address* decides something (mDNS is DNS sent to 224.0.0.251), that
is content too, and it is named in the reason.

**Every identification carries its reason and its confidence.** The same
four rungs as the TCP side, imported from it rather than re-declared, so
that one threshold means one thing across the tool: CERTAIN, STRONG, LIKELY,
WEAK. See `pcapscan/protocols.py` for what each rung is evidence of.

**Nothing secret is written down.** This is the rule that shaped the record
format more than any other. A capture analyser that transcribes an SNMP
community string, an HSRP key, a STUN ICE password or a list of the
hostnames on a segment into its own report has not found a problem, it has
made a second copy of one -- and this project has already made that decision
twice, for SNI (`fapi/app/uploads.py` calls it browsing history) and for
report retention. So:

* An authenticator is recorded as *present, and in the clear*. Never its
  value, never its length in a way that narrows a guess.
* A hostname is never recorded. Not a DNS query name, not an mDNS instance
  name, not a NetBIOS name, not a DHCP option 12, not a CLDAP directory
  value. Names are counted, and distinct names are counted, and that is all.
* What *is* recorded is the **service**, not the identity: the DNS query
  types, the mDNS service types (`_smb._tcp.local`, with any instance label
  in front of them dropped), the NetBIOS suffix byte, the DHCP option
  numbers. "This Mac advertises AFP, SMB, screen sharing and Time Machine to
  the whole segment" is the finding; which Mac it is is not needed to make
  it, and a report that carried both would be harder to circulate than the
  problem it describes.
* Anything that does survive into a document goes through
  `cryptomon.utils.printable_text` first, which exists because a hostile
  hostname once broke the CSV writer outright.

**The verdict.** Each protocol gets one of four answers about its
cryptographic protection. Only the first is a constant this project already
had -- `cryptomon.analysis.NOT_APPLICABLE` -- and it is imported rather than
retyped so the strings cannot drift:

  none                 no confidentiality and no origin authentication.
                       Anyone on the path reads it, and anyone on the path
                       forges it.
  obsolete             a mechanism is present and is broken today by
                       classical cryptanalysis -- keyed MD5, DES. Not
                       nothing, and not something to rely on.
  authenticated only   origin authentication that still holds, and no
                       confidentiality. The contents are public by design.
                       DNSSEC is the honest example: a signed answer is
                       authenticated *and* readable by everyone.
  encrypted            confidentiality, and in every case here integrity
                       with it.

The distinction between `none` and `authenticated only` is the one that
carries weight. HSRP without authentication means anybody on the segment can
become the default gateway; HSRP with it means they cannot, and the traffic
is still entirely readable. Those are different findings and a report that
merged them would be answering neither question.

**Bounds.** Every input here is attacker-chosen bytes behind an upload form.
DNS name compression is the classic: a pointer may point backwards into a
loop and a naive decompressor hangs forever. `_read_name` refuses any
pointer that does not point strictly backwards, which makes a loop
arithmetically impossible rather than merely unlikely, and caps the pointer
count as well. Every other walk here -- record sections, TLV chains, BER
lengths, DHCP options -- is bounded by a constant *and* by the payload
length, and the payload length is the only length that is trusted.
"""
import collections
import hashlib
import os
from typing import NamedTuple

from cryptomon.analysis import NOT_APPLICABLE
from cryptomon.utils import PARSE_STATS, printable_text
# WEAK is deliberately not imported. Nothing in this module reports at it:
# a weak identification of an unprotected protocol is a report row asserting
# an exposure that may not exist, and the reader has no way to tell the two
# apart. Every detector here either earns LIKELY or refuses.
from pcapscan.protocols import CERTAIN, LIKELY, STRONG


# --------------------------------------------------------------------------
# verdicts about protection
# --------------------------------------------------------------------------
# `none` is `cryptomon.analysis.NOT_APPLICABLE`, which that module already
# spells 'none' for a session that performed no key exchange. Re-using the
# string keeps one vocabulary; it is deliberately kept in its own `protection`
# field rather than fed into `key_exchange_verdict`, because "a resumed TLS
# session did not need a key exchange" and "DHCP has no cryptography at all"
# are the same word about very different situations and counting them
# together would be counting an event that did not happen alongside one that
# could not.
#
# The other three do not exist in `cryptomon/analysis.py` and are proposed
# for it; until they are there they live here, so that this module is not
# silently editing a file four other people are building against.
PROTECTION_NONE = NOT_APPLICABLE            # 'none'
PROTECTION_OBSOLETE = 'obsolete'
PROTECTION_AUTHENTICATED = 'authenticated only'
PROTECTION_ENCRYPTED = 'encrypted'

PROTECTIONS = (PROTECTION_NONE, PROTECTION_OBSOLETE, PROTECTION_AUTHENTICATED,
               PROTECTION_ENCRYPTED)

# Worst first: a flow whose datagrams disagree is reported at its weakest,
# because the weakest is the one an attacker picks.
_PROTECTION_ORDER = {name: index for index, name in enumerate(PROTECTIONS)}


# --------------------------------------------------------------------------
# bounds
# --------------------------------------------------------------------------
# What `detect` will accept. LIKELY and above, matching the rung at which
# `pcapscan/protocols.py` says a caller may act on an answer. Below it the
# identification is reported inside the document -- so it is visible -- but
# it never claims the flow.
MIN_CONFIDENCE = LIKELY

# RFC 1035 section 2.3.4 and 3.1. Both are hard limits in the protocol, so a
# name that exceeds either is malformed rather than unusual.
MAX_NAME_LENGTH = 255
MAX_LABEL_LENGTH = 63

# Compression pointers followed while expanding one name. The strictly-
# backwards rule below already makes a loop impossible; this bounds the
# pathological-but-legal case of a name assembled from 200 one-byte hops,
# which costs time without being malformed.
MAX_NAME_POINTERS = 16

# Sections of a DNS message walked, and records walked in total. A message
# claiming 65,535 answers in 40 bytes is the cheap way to make a parser spin.
MAX_QUESTIONS = 16
MAX_RECORDS = 64

# TLVs in an HSRP packet, attributes in a STUN message, options in a DHCP
# packet. Each walk is also bounded by the payload length; these stop a
# zero-length element from being walked forever even when the length
# arithmetic is correct.
MAX_TLVS = 32
MAX_STUN_ATTRIBUTES = 32
MAX_DHCP_OPTIONS = 64

# Distinct names counted per flow before the counter stops growing. Only the
# *count* ever reaches a document -- the names themselves are held to tell
# distinct from repeated and are discarded when the flow ends -- but an
# unbounded set of attacker-chosen names is still a memory cost, and this is
# a process that may be parsing an attacker's capture.
MAX_DISTINCT_NAMES = 256

# Service types and query types kept per flow. A flow offering more than this
# many distinct services is not a flow whose service list is the finding.
MAX_LABELS = 32

# What a recorded label may be. Long enough for
# `_microsoft_mcc._tcp.local` and every service type in the corpus.
MAX_LABEL_CHARS = 64


class Identification(NamedTuple):
    """
    What one datagram is, and what protection it has.

    `reason` is as much the deliverable as `protocol` is, for the reason
    `pcapscan.protocols.Detection` gives: "mDNS" invites the question "says
    who", and "a DNS message whose 2 questions walk cleanly to the end of the
    payload, transaction id 0, sent to 224.0.0.251" answers it in terms a
    reader can check against the capture.

    `protection_reason` is the same courtesy for the verdict, which is the
    part of this record a report quotes.
    """
    protocol: str
    confidence: float
    reason: str
    protection: str
    protection_reason: str
    facts: dict = None
    # Tokens standing for the names this datagram carried -- see
    # `_name_token`. Exists so that a flow can report *how many distinct*
    # names it saw, which is a real measure of how much a broadcast leaks.
    # Not part of `facts`, because `facts` goes into the document and this
    # never does; the handler folds it into a bounded set, emits the size
    # and drops it.
    names: tuple = ()


# --------------------------------------------------------------------------
# small shared helpers
# --------------------------------------------------------------------------
def _u16(buf, offset):
    return (buf[offset] << 8) | buf[offset + 1]


def _u32(buf, offset):
    return ((buf[offset] << 24) | (buf[offset + 1] << 16)
            | (buf[offset + 2] << 8) | buf[offset + 3])


def _text(raw, limit=MAX_LABEL_CHARS):
    """
    Bytes off the wire, rendered safely enough to put in a report.

    latin-1 rather than ascii+replace, because latin-1 maps every byte to
    exactly one code point, so `printable_text`'s escape comes out as a
    reversible `\\xNN` rather than as an escape of the replacement character.
    """
    return printable_text(bytes(raw[:limit]).decode('latin-1'),
                          'cleartext_nonprintable')


def _is_multicast(address, groups):
    return address is not None and str(address).lower() in groups


# --------------------------------------------------------------------------
# DNS wire format -- shared by DNS, mDNS, LLMNR and NetBIOS name service
# --------------------------------------------------------------------------
# All four use RFC 1035 framing, which is why they are parsed once here and
# told apart afterwards from evidence that is actually different: the
# encoding of the first label, the transaction id, and the multicast group
# the datagram was sent to.
DNS_HDR_LEN = 12

# RFC 1035 section 4.1.1 plus the later additions. Anything else is either
# unassigned or a made-up opcode, and both are reasons to refuse.
DNS_OPCODES = {0: 'query', 1: 'iquery', 2: 'status', 4: 'notify',
               5: 'update', 6: 'dso'}

# RFC 6895: 0-10 are assigned, 16-23 exist only with EDNS0. Values in
# between are unassigned and are a refusal.
DNS_RCODES = frozenset(range(0, 11)) | frozenset(range(16, 24))

# The classes in use. mDNS puts the QU/cache-flush bit in the top bit of this
# field, so it is masked off before the test (RFC 6762 sections 5.4, 10.2).
DNS_CLASSES = {1: 'IN', 3: 'CH', 4: 'HS', 254: 'NONE', 255: 'ANY'}

# Named because the *distribution* is a finding and the names are not
# sensitive: 764 of the corpus's 2,134 DNS datagrams are HTTPS-record
# queries, which is the record that carries the ECH configuration, so
# "how much of this network is asking for ECH parameters" is answerable
# from a column this module already has.
DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 41: 'OPT', 43: 'DS', 46: 'RRSIG',
    47: 'NSEC', 48: 'DNSKEY', 50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA',
    59: 'CDS', 60: 'CDNSKEY', 64: 'SVCB', 65: 'HTTPS', 250: 'TSIG',
    251: 'IXFR', 252: 'AXFR', 255: 'ANY', 257: 'CAA',
}

# The record types that make an answer authenticated rather than merely
# asserted. RRSIG is the signature itself; the others are what a validator
# needs to chain it to a trust anchor or to prove a negative answer.
DNSSEC_TYPES = frozenset({43, 46, 47, 48, 50, 51, 59, 60})

RRSIG_TYPE = 46                 # the only record that authenticates an RRset
# 0/1 flags that accumulate across a flow rather than freezing at the first
# datagram. Emitted as ints rather than bools, so they need naming here.
STICKY_FLAGS = frozenset({'dnssec_ok', 'dnssec_signed'})

OPT_TYPE = 41                   # the EDNS0 pseudo-record (RFC 6891)
DNSSEC_OK = 0x8000              # the DO bit, in the OPT record's TTL field

MDNS_GROUPS = frozenset({'224.0.0.251', 'ff02::fb'})
LLMNR_GROUPS = frozenset({'224.0.0.252', 'ff02::1:3'})


def _read_name(buf, offset):
    """
    Expand one (possibly compressed) domain name.

    Returns `(labels, offset just past the name)`, or `(None, None)` when the
    name is malformed. `labels` is a list of raw `bytes`; nothing here
    decodes them, because a domain name is not text and the callers that want
    text run it through `_text` themselves.

    **This is the function a hostile capture attacks.** RFC 1035 compression
    lets a label be replaced by a two-byte pointer to an earlier offset, and
    the obvious implementation follows pointers until it reaches a
    terminator -- which, given a pointer that points at itself, is never. The
    defence here is not a visit set or a step budget but arithmetic: a
    pointer is refused unless it points *strictly backwards* from where it
    was read. The cursor therefore strictly decreases at every pointer and
    only ever advances by a bounded amount between them, so the walk
    terminates for every possible input, including one built specifically to
    make it not. The pointer count and the 255-byte name limit are both still
    enforced on top of that, because a bound that rests on one argument is a
    bound that rests on that argument being right.
    """
    labels = []
    total = 0
    pointers = 0
    cursor = offset
    after = None                 # where the name ends in the *original* run
    limit = len(buf)
    terminated = False
    while cursor < limit:
        length = buf[cursor]
        if length == 0:
            cursor += 1
            terminated = True
            break
        if length & 0xC0 == 0xC0:
            if cursor + 2 > limit:
                PARSE_STATS['cleartext_dns_name_truncated_pointer'] += 1
                return None, None
            target = ((length & 0x3F) << 8) | buf[cursor + 1]
            if after is None:
                # The name occupies two bytes here however far the pointer
                # chain then travels; everything after this is somebody
                # else's bytes.
                after = cursor + 2
            pointers += 1
            if target >= cursor or pointers > MAX_NAME_POINTERS:
                PARSE_STATS['cleartext_dns_name_pointer_loop'] += 1
                return None, None
            cursor = target
            continue
        if length & 0xC0:
            # 0b01 and 0b10 label types were never assigned. A parser that
            # treats them as a length is reading a length that does not exist.
            PARSE_STATS['cleartext_dns_name_reserved_label'] += 1
            return None, None
        if length > MAX_LABEL_LENGTH or cursor + 1 + length > limit:
            PARSE_STATS['cleartext_dns_name_overruns'] += 1
            return None, None
        total += length + 1
        if total > MAX_NAME_LENGTH:
            PARSE_STATS['cleartext_dns_name_too_long'] += 1
            return None, None
        labels.append(bytes(buf[cursor + 1:cursor + 1 + length]))
        cursor += 1 + length
    if not terminated:
        # Ran out of payload without a root label. Truncated, not a name.
        PARSE_STATS['cleartext_dns_name_unterminated'] += 1
        return None, None
    return labels, (after if after is not None else cursor)


class _Message(NamedTuple):
    """A DNS-framed message, as far as its own lengths could be checked."""
    transaction_id: int
    flags: int
    counts: tuple                   # (qd, an, ns, ar)
    questions: tuple                # ((labels, qtype, qclass), ...)
    records: tuple                  # ((labels, rtype, rclass, ttl), ...)
    complete: bool                  # every section walked to the end

    @property
    def is_response(self):
        return bool(self.flags & 0x8000)

    @property
    def opcode(self):
        return (self.flags >> 11) & 0x0F

    @property
    def rcode(self):
        return self.flags & 0x0F


def _parse_dns(payload):
    """
    A DNS-framed message, or None when the bytes contradict the framing.

    Refuses rather than guesses, for the reason `pcapscan/protocols.py`
    gives: a low-confidence wrong answer still puts a row in the report, and
    the cheapest way to make this module lie is to send something that
    half-matches.
    """
    if len(payload) < DNS_HDR_LEN:
        return None
    flags = _u16(payload, 2)
    if ((flags >> 11) & 0x0F) not in DNS_OPCODES:
        return None
    if flags & 0x0040:
        return None                  # the Z bit is reserved and must be zero
    if (flags & 0x0F) not in DNS_RCODES:
        return None
    counts = tuple(_u16(payload, 4 + 2 * i) for i in range(4))
    if not any(counts):
        # A header with four zero counts is four zero fields, and so is a
        # run of zeroes. Every test above passes for `bytes(20)`, and the
        # first version of this reported it as DNS at LIKELY -- along with a
        # STUN message whose magic cookie had been blanked, an NTPv1 packet
        # and a DHCP payload with no cookie. An empty DNS message does exist
        # (a FORMERR response to an unparseable query is one) and it is
        # simply not identifiable; claiming it costs far more than missing
        # it does.
        return None
    if counts[0] > MAX_QUESTIONS or sum(counts[1:]) > MAX_RECORDS:
        # Not a refusal of the protocol -- a message really can carry more --
        # but a refusal to walk it. A claim this large in a datagram this
        # small is the shape of an input built to be expensive.
        #
        # Deliberately *not* counted in PARSE_STATS. This is the line most
        # non-DNS traffic leaves by, and on the corpus it fires 18,360 times
        # in a normal run. A counter that ticks on the majority of a capture
        # is noise sitting in the same dictionary as the counters that mean
        # something, and it would bury them.
        return None

    offset = DNS_HDR_LEN
    questions = []
    for _ in range(counts[0]):
        labels, offset = _read_name(payload, offset)
        if labels is None or offset + 4 > len(payload):
            return None
        questions.append((tuple(labels), _u16(payload, offset),
                          _u16(payload, offset + 2)))
        offset += 4

    records = []
    complete = True
    for _ in range(sum(counts[1:])):
        labels, offset = _read_name(payload, offset)
        if labels is None or offset + 10 > len(payload):
            complete = False
            break
        rtype, rclass = _u16(payload, offset), _u16(payload, offset + 2)
        ttl = _u32(payload, offset + 4)
        rdlength = _u16(payload, offset + 8)
        offset += 10 + rdlength
        if offset > len(payload):
            # The record claims more rdata than was captured. Unrefuted and
            # nothing more: a truncated claim is not a confirmed one.
            complete = False
            records.append((tuple(labels), rtype, rclass, ttl))
            break
        records.append((tuple(labels), rtype, rclass, ttl))
    else:
        complete = offset == len(payload)

    return _Message(_u16(payload, 0), flags, counts, tuple(questions),
                    tuple(records), complete)


def _service_type(labels):
    """
    The service part of an mDNS name, with any instance label dropped.

    `DESKTOP-5F7S8C0._dosvc._tcp.local` is two facts stapled together: a
    machine name, which is somebody's asset inventory, and a service type,
    which is the finding. This keeps the second and discards the first, by
    taking the name from the first label that begins with an underscore --
    the character RFC 6763 reserves for exactly this purpose.

    Returns None for a name with no service label, which is how a plain
    hostname query gets counted without being recorded.
    """
    for index, label in enumerate(labels):
        if label.startswith(b'_'):
            return '.'.join(_text(part, 32) for part in labels[index:])
    return None


def _dns_evidence(message, payload):
    """The clauses and confidence a well-formed DNS message earns."""
    clauses = [
        '{0} message, opcode {1} ({2}), rcode {3}'.format(
            'response' if message.is_response else 'query', message.opcode,
            DNS_OPCODES[message.opcode], message.rcode),
        'section counts {0}/{1}/{2}/{3}'.format(*message.counts),
    ]
    if message.questions and message.complete:
        clauses.append(
            '{0} question name(s) and every record walk cleanly to the end '
            'of the {1}-byte payload'.format(len(message.questions),
                                             len(payload)))
        return clauses, CERTAIN
    if message.questions:
        clauses.append(
            '{0} question name(s) expand within the payload, but a record '
            'section is truncated'.format(len(message.questions)))
        return clauses, STRONG
    # `_parse_dns` refuses a message whose four section counts are all zero,
    # so there is always a question or a record to corroborate the header.
    clauses.append('{0} record name(s) expand within the payload'.format(
        len(message.records)))
    return clauses, STRONG


def _dnssec_state(message):
    """
    (dnssec_ok, signed, clauses) for one message.

    The DO bit says the *resolver* asked for signatures; RRSIG records in the
    answer say it got them. They are different claims and the difference is
    the whole point of looking: a query with DO set and an answer with no
    RRSIG is a zone that is not signed, which is the common case and is
    exactly the finding worth reporting.
    """
    dnssec_ok = False
    signed = False
    clauses = []
    for _labels, rtype, rclass, ttl in message.records:
        if rtype == OPT_TYPE:
            # In an OPT record the class is the requestor's UDP payload size
            # and the TTL is extended-rcode | version | flags.
            if ttl & DNSSEC_OK:
                dnssec_ok = True
            clauses.append('EDNS0 OPT present, payload size {0}, version '
                           '{1}, DO {2}'.format(rclass, (ttl >> 16) & 0xFF,
                                                'set' if ttl & DNSSEC_OK
                                                else 'clear'))
        elif rtype == RRSIG_TYPE:
            # RRSIG and nothing else. The other DNSSEC record types are
            # *material* -- DNSKEY is a public key, DS is a delegation
            # pointer, NSEC proves non-existence -- and a response carrying
            # a DNSKEY with no RRSIG over it is exactly as unauthenticated
            # as any other answer. Treating the whole family as proof of
            # signing meant a plain `dig DNSKEY example.com` came back
            # labelled "authenticated against the zone key", which is a
            # claim this tool should never make when it has not seen a
            # signature.
            signed = True
    for _labels, qtype, _qclass in message.questions:
        if qtype in DNSSEC_TYPES:
            clauses.append('the question asks for {0}'.format(
                DNS_TYPES.get(qtype, qtype)))
    return dnssec_ok, signed, clauses


def _detect_dns_family(payload, destination):
    """DNS, mDNS, LLMNR or NetBIOS-NS -- all RFC 1035 framing."""
    message = _parse_dns(payload)
    if message is None:
        return None
    clauses, confidence = _dns_evidence(message, payload)

    # --- NetBIOS name service -------------------------------------------
    # RFC 1002's first-level encoding: exactly one 32-byte label whose every
    # byte is 'A'..'P', each pair being the two nibbles of one character of
    # the 16-byte NetBIOS name. Nothing else produces that, so it outranks
    # everything else this function could conclude.
    if message.questions or message.records:
        names = [q[0] for q in message.questions] \
                or [r[0] for r in message.records]
        first = names[0][0] if names and names[0] else b''
        if len(first) == 32 and all(0x41 <= b <= 0x50 for b in first):
            return _netbios_ns(message, clauses)

    facts = _dns_facts(message)
    dnssec_ok, signed, dnssec_clauses = _dnssec_state(message)
    clauses += dnssec_clauses
    facts['dnssec_ok'] = int(dnssec_ok)
    facts['dnssec_signed'] = int(signed)

    # --- mDNS and LLMNR --------------------------------------------------
    # Both are DNS sent to a fixed multicast group, and the group is the
    # evidence: it is a field of the datagram, not a convention about a port.
    if _is_multicast(destination, MDNS_GROUPS):
        clauses.append('sent to the mDNS group {0}'.format(destination))
        if message.transaction_id == 0:
            clauses.append('transaction id 0, as RFC 6762 section 18.1 '
                           'requires')
        facts['services'] = _mdns_services(message)
        return Identification(
            'mdns', confidence, '; '.join(clauses), PROTECTION_NONE,
            'mDNS has no authentication and no confidentiality: every name '
            'and service advertised here is readable, and forgeable, by '
            'anything on the link', facts, _names(message))

    if _is_multicast(destination, LLMNR_GROUPS):
        clauses.append('sent to the LLMNR group {0}'.format(destination))
        return Identification(
            'llmnr', confidence, '; '.join(clauses), PROTECTION_NONE,
            'LLMNR has no authentication: an unanswered name query is '
            'answered by whoever replies first, which is the standard '
            'credential-relay foothold on a Windows segment', facts,
            _names(message))

    # --- unicast DNS -----------------------------------------------------
    if signed:
        protection, why = (
            PROTECTION_AUTHENTICATED,
            'the answer carries DNSSEC records, so it is authenticated '
            'against the zone key -- and still entirely public: DNSSEC signs '
            'answers, it does not hide the question')
    elif dnssec_ok:
        protection, why = (
            PROTECTION_NONE,
            'the resolver set the DO bit but the answer carries no '
            'signature, so nothing here is authenticated; the zone is '
            'unsigned or the resolver stripped it')
    else:
        protection, why = (
            PROTECTION_NONE,
            'plain DNS over UDP: the query and the answer are readable and '
            'forgeable by anything on the path, and the query is browsing '
            'history')
    return Identification('dns', confidence, '; '.join(clauses), protection,
                          why, facts, _names(message))


# A per-process key for the name tokens below. Random, and therefore not
# stable across runs, which is the point: a *stable* digest of a hostname is
# a hostname -- the set of names on a corporate network is small enough to
# enumerate, so a fixed hash would be reversible by anyone who got hold of
# the report. Nothing needs the tokens to survive the process; only counts
# do.
_NAME_KEY = os.urandom(16)


def _name_token(labels):
    """
    A token standing for one name, for counting distinct names and nothing
    else.

    Keyed rather than plain, and the key is thrown away when the process
    exits. The first version of this carried the raw labels, which meant
    that anything printing an `Identification` -- a log line, a traceback, a
    debugger, an `assert x == y` failure -- printed a list of the hostnames
    on somebody's network. That is exactly the leak the module docstring
    says it is avoiding, reintroduced one field below the field it is
    avoiding it in.
    """
    digest = hashlib.blake2b(b'\x00'.join(labels), key=_NAME_KEY,
                             digest_size=16)
    return digest.digest()


def _names(message):
    """The question names, as tokens. Never reaches a document."""
    return tuple(_name_token(labels)
                 for labels, _qtype, _qclass in message.questions)


def _dns_facts(message):
    """Query types and counts. No names, ever."""
    types = collections.Counter()
    for _labels, qtype, _qclass in message.questions:
        types[DNS_TYPES.get(qtype, 'TYPE{0}'.format(qtype))] += 1
    return {
        'qtypes': dict(types),
        'questions': len(message.questions),
        'responses': int(message.is_response),
        'rcode': message.rcode,
    }


def _mdns_services(message):
    """The service types advertised or asked for, instance labels removed."""
    services = set()
    for labels, _qtype, _qclass in message.questions:
        service = _service_type(labels)
        if service:
            services.add(service)
    for labels, _rtype, _rclass, _ttl in message.records:
        service = _service_type(labels)
        if service:
            services.add(service)
    return sorted(services)[:MAX_LABELS]


# RFC 1002 section 4.2.1.3 and the suffixes Microsoft assigned on top of it.
# The suffix is the sixteenth byte of the decoded name and says what the
# name is *for*; it is the part of a NetBIOS name that is a finding, and the
# other fifteen bytes are the part that is somebody's machine.
NETBIOS_SUFFIXES = {
    0x00: 'workstation', 0x03: 'messenger', 0x06: 'ras-server',
    0x1B: 'domain-master-browser', 0x1C: 'domain-controllers',
    0x1D: 'master-browser', 0x1E: 'browser-elections',
    0x1F: 'net-dde', 0x20: 'file-server', 0x21: 'ras-client',
    0xBE: 'network-monitor-agent', 0xBF: 'network-monitor-utility',
}

NETBIOS_NS_OPCODES = {0: 'query', 5: 'registration', 6: 'release',
                      7: 'wack', 8: 'refresh'}


def _netbios_suffix(label):
    """The suffix byte of a first-level-encoded name, or None."""
    if len(label) != 32:
        return None
    try:
        decoded = bytes(((label[i] - 0x41) << 4) | (label[i + 1] - 0x41)
                        for i in range(0, 32, 2))
    except ValueError:
        return None
    return decoded[15]


def _netbios_ns(message, clauses):
    opcode = (message.flags >> 11) & 0x0F
    suffixes = collections.Counter()
    names = [labels for labels, _qtype, _qclass in message.questions]
    names += [labels for labels, _rtype, _rclass, _ttl in message.records]
    for labels in names:
        suffix = _netbios_suffix(labels[0] if labels else b'')
        if suffix is not None:
            suffixes[NETBIOS_SUFFIXES.get(
                suffix, '0x{0:02x}'.format(suffix))] += 1
    clauses.append('the first label is 32 bytes of A-P, which is RFC 1002 '
                   'first-level name encoding and nothing else')
    return Identification(
        'netbios-ns', CERTAIN, '; '.join(clauses), PROTECTION_NONE,
        'NetBIOS name service has no authentication: a name query nobody '
        'owns is answered by whoever replies first, and the names it '
        'broadcasts are an inventory of the segment',
        {'opcode': NETBIOS_NS_OPCODES.get(opcode, opcode),
         # The suffix byte says what the name is *for* -- a workstation, a
         # file server, a domain controller group. The other fifteen bytes
         # are somebody's machine name and are not recorded.
         'suffixes': dict(suffixes),
         'names': len(names)},
        tuple(_name_token(labels) for labels in names))


# --------------------------------------------------------------------------
# NetBIOS datagram service (RFC 1002 section 4.4)
# --------------------------------------------------------------------------
NETBIOS_DGM_TYPES = {
    0x10: 'direct-unique', 0x11: 'direct-group', 0x12: 'broadcast',
    0x13: 'error', 0x14: 'query-request', 0x15: 'positive-query-response',
    0x16: 'negative-query-response',
}
NETBIOS_DGM_HDR_LEN = 14
NETBIOS_DGM_PORT = 138


def _detect_netbios_dgm(payload, source):
    """
    A NetBIOS datagram, recognised from the copy of its own address it
    carries.

    The header repeats the sender's IPv4 address and source port inside the
    payload, which is what makes this certain rather than suggestive: a
    header whose embedded address equals the IP source address and whose
    embedded port equals 138 is four bytes and two bytes that had to agree
    with the frame around them, and random bytes do not.
    """
    if len(payload) < NETBIOS_DGM_HDR_LEN:
        return None
    msg_type = payload[0]
    if msg_type not in NETBIOS_DGM_TYPES:
        return None
    embedded = '.'.join(str(b) for b in payload[4:8])
    embedded_port = _u16(payload, 8)
    clauses = ['message type 0x{0:02x} ({1})'.format(
        msg_type, NETBIOS_DGM_TYPES[msg_type])]
    confidence = LIKELY
    if embedded_port == NETBIOS_DGM_PORT:
        clauses.append('the header names source port 138')
        confidence = STRONG
    if source is not None and embedded == str(source):
        clauses.append('the header repeats the frame source address '
                       '{0}'.format(embedded))
        confidence = CERTAIN if confidence == STRONG else STRONG
    if confidence < STRONG:
        return None
    if msg_type in (0x10, 0x11, 0x12):
        length = _u16(payload, 10)
        if length and NETBIOS_DGM_HDR_LEN + length <= len(payload) + 4:
            clauses.append('datagram length {0} fits the {1}-byte '
                           'payload'.format(length, len(payload)))
    return Identification(
        'netbios-dgm', confidence, '; '.join(clauses), PROTECTION_NONE,
        'the NetBIOS datagram service carries SMB browser and mailslot '
        'traffic unauthenticated and unencrypted; the header alone names '
        'the sending host',
        {'message_type': NETBIOS_DGM_TYPES[msg_type]})


# --------------------------------------------------------------------------
# DHCP / BOOTP
# --------------------------------------------------------------------------
DHCP_COOKIE = b'\x63\x82\x53\x63'       # RFC 2131 section 3
DHCP_COOKIE_OFFSET = 236
DHCP_MESSAGE_TYPES = {
    1: 'discover', 2: 'offer', 3: 'request', 4: 'decline', 5: 'ack',
    6: 'nak', 7: 'release', 8: 'inform',
}
# Only the options whose *presence* is a finding are named; the rest are
# reported by number. None of their values are recorded: option 12 is the
# machine's hostname and option 61 is an identifier that is frequently the
# MAC address, and both are the kind of thing this module refuses to copy.
DHCP_OPTIONS = {
    12: 'hostname', 50: 'requested-address', 53: 'message-type',
    54: 'server-identifier', 55: 'parameter-request-list',
    60: 'vendor-class', 61: 'client-identifier', 66: 'tftp-server-name',
    67: 'bootfile-name', 82: 'relay-agent-information',
    90: 'authentication', 150: 'tftp-server-address',
}
DHCP_AUTH_OPTION = 90                   # RFC 3118


def _detect_dhcp(payload):
    if (len(payload) < DHCP_COOKIE_OFFSET + 4
            or payload[DHCP_COOKIE_OFFSET:DHCP_COOKIE_OFFSET + 4]
            != DHCP_COOKIE):
        return None
    op, htype, hlen = payload[0], payload[1], payload[2]
    if op not in (1, 2) or hlen > 16:
        return None
    clauses = [
        'the RFC 2131 magic cookie 0x63825363 at offset 236',
        'op {0} ({1}), hardware type {2}, address length {3}'.format(
            op, 'request' if op == 1 else 'reply', htype, hlen),
    ]
    options, message_type, authenticated = _dhcp_options(payload)
    if message_type:
        clauses.append('option 53 message type {0}'.format(message_type))
    if authenticated:
        protection, why = (
            PROTECTION_AUTHENTICATED,
            'RFC 3118 option 90 is present, so the exchange is '
            'authenticated; it is still readable by anything on the '
            'broadcast domain')
    else:
        protection, why = (
            PROTECTION_NONE,
            'DHCP with no RFC 3118 authentication option: any host on the '
            'segment can answer first and become the gateway and the '
            'resolver, and the broadcast carries the client hostname and '
            'identifier in the clear')
    return Identification(
        'dhcp', CERTAIN if message_type else STRONG, '; '.join(clauses),
        protection, why,
        {'message_type': message_type, 'options': options})


def _dhcp_options(payload):
    """Option *numbers* present, the message type, and whether option 90 is."""
    present = []
    message_type = None
    authenticated = False
    offset = DHCP_COOKIE_OFFSET + 4
    seen = 0
    while offset < len(payload) and seen < MAX_DHCP_OPTIONS:
        code = payload[offset]
        if code == 255:
            break
        if code == 0:
            offset += 1                  # pad
            continue
        if offset + 2 > len(payload):
            break
        length = payload[offset + 1]
        if offset + 2 + length > len(payload):
            PARSE_STATS['cleartext_dhcp_option_overruns'] += 1
            break
        present.append(DHCP_OPTIONS.get(code, str(code)))
        if code == 53 and length == 1:
            message_type = DHCP_MESSAGE_TYPES.get(payload[offset + 2],
                                                  payload[offset + 2])
        elif code == DHCP_AUTH_OPTION and length:
            authenticated = True
        offset += 2 + length
        seen += 1
    return present[:MAX_LABELS], message_type, authenticated


# --------------------------------------------------------------------------
# NTP
# --------------------------------------------------------------------------
# Modes 1-5 share the 48-byte association header below. Modes 6 (control)
# and 7 (private) do not -- they are query interfaces with their own layout,
# and reading their bytes as a stratum and a root delay is reading fields
# that are not there. Mode 6 is handled separately because its count field
# can be checked against the payload; mode 7 is not handled at all, and that
# is recorded rather than guessed at.
NTP_MODES = {1: 'symmetric-active', 2: 'symmetric-passive', 3: 'client',
             4: 'server', 5: 'broadcast'}
NTP_CONTROL_MODE = 6
NTP_HDR_LEN = 48
NTP_CONTROL_HDR_LEN = 12

# NTPv1 and v2 are RFC 958 and RFC 1119, superseded in 1992. Accepting them
# costs two of the three bits of version evidence this detector has, and the
# corpus proved the cost: with 1-4 accepted, 329 QUIC short-header packets
# on port 443 were reported as NTP. Everything deployed is v3 or v4.
NTP_VERSIONS = (3, 4)

# Root delay and root dispersion are 16.16 fixed-point seconds. A server
# whose delay to the root is over 256 seconds is not a server anyone is
# synchronising to, so the high byte of each is zero in every real packet --
# two more bytes that had to agree, and the two that do most of the work in
# keeping QUIC out of this detector.
NTP_MAX_ROOT_SECONDS = 256

# Precision is a signed log2 seconds: -6 is a millisecond clock and -30 a
# nanosecond one. Zero appears in a client request that zeroes everything.
NTP_MIN_PRECISION = -43
# Poll is a log2 interval; RFC 5905 uses 4..17 and a minimal client request
# leaves it zero.
NTP_MAX_POLL = 17
# RFC 5905 appendix A.5.1 / RFC 8573: the legacy MAC is a 4-byte key
# identifier followed by a 128-bit MD5 or 160-bit SHA-1 digest.
NTP_MAC_MD5_LEN = NTP_HDR_LEN + 4 + 16
NTP_MAC_SHA1_LEN = NTP_HDR_LEN + 4 + 20
# RFC 8915 network time security, carried in NTPv4 extension fields.
NTS_FIELD_TYPES = frozenset({0x0104, 0x0204, 0x0304, 0x0404})


def _detect_ntp(payload):
    """
    An NTP association packet, or a mode 6 control message.

    **This detector is the one that had to be rewritten**, and the corpus is
    why. The first version tested the mode and version bits, the stratum and
    a loose range on the poll and precision fields, and on 160,221 packets it
    claimed 496 QUIC short-header packets on port 443 as NTP -- more false
    positives than the corpus has real NTP packets by a factor of 124. A
    detector that wrong is worse than no detector, because it moves the
    wrong answer out of the port number, where everybody knows to distrust
    it, and into a field labelled `confidence`.

    What fixed it was not a tighter range but more *independent* fields that
    had to agree: version 3 or 4 rather than 1 to 4, the high byte of root
    delay and of root dispersion both zero, a precision that is a real log2
    clock resolution, and an exact packet length. Each of those is a byte
    that a QUIC packet's encrypted payload has one chance in 256 of getting
    right, and together they take the expected false-positive count over
    this corpus below one.
    """
    if len(payload) < NTP_HDR_LEN:
        if len(payload) >= NTP_CONTROL_HDR_LEN:
            return _ntp_control(payload)
        return None
    first = payload[0]
    version, mode = (first >> 3) & 0x07, first & 0x07
    if version not in NTP_VERSIONS:
        return None
    if mode == NTP_CONTROL_MODE:
        return _ntp_control(payload)
    if mode not in NTP_MODES:
        return None
    stratum = payload[1]
    if stratum > 16:
        return None
    poll = payload[2] if payload[2] < 128 else payload[2] - 256
    precision = payload[3] if payload[3] < 128 else payload[3] - 256
    if not 0 <= poll <= NTP_MAX_POLL:
        return None
    if not NTP_MIN_PRECISION <= precision <= 0:
        return None
    root_delay, root_dispersion = _u32(payload, 4), _u32(payload, 8)
    if root_delay >> 16 >= NTP_MAX_ROOT_SECONDS \
            or root_dispersion >> 16 >= NTP_MAX_ROOT_SECONDS:
        return None

    clauses = [
        'leap {0}, version {1}, mode {2} ({3})'.format(
            first >> 6, version, mode, NTP_MODES[mode]),
        'stratum {0}, poll {1}, precision {2}'.format(stratum, poll,
                                                      precision),
        'root delay and dispersion both under {0}s'.format(
            NTP_MAX_ROOT_SECONDS),
    ]
    facts = {'mode': NTP_MODES[mode], 'version': version, 'stratum': stratum}

    extra = len(payload) - NTP_HDR_LEN
    if extra == 0:
        clauses.append('exactly {0} bytes: no authenticator and no '
                       'extension fields'.format(NTP_HDR_LEN))
        return Identification(
            'ntp', CERTAIN, '; '.join(clauses), PROTECTION_NONE,
            'an unauthenticated NTP packet: anything on the path can move '
            'this host\'s clock, and the clock is what certificate expiry, '
            'Kerberos ticket lifetimes and every log correlation rest on',
            facts)

    if _ntp_extension_fields(payload):
        clauses.append('NTPv4 extension fields that walk to the end of the '
                       'payload, including an NTS field')
        facts['nts'] = True
        return Identification(
            'ntp', CERTAIN, '; '.join(clauses), PROTECTION_ENCRYPTED,
            'RFC 8915 Network Time Security: the packet is authenticated '
            'and the NTS cookie and the fields it protects are encrypted',
            facts)
    if len(payload) == NTP_MAC_MD5_LEN:
        clauses.append('{0} bytes: a 4-byte key id and a 128-bit '
                       'digest'.format(len(payload)))
        facts['authenticator'] = 'symmetric-key-md5'
        return Identification(
            'ntp', CERTAIN, '; '.join(clauses), PROTECTION_OBSOLETE,
            'a symmetric-key authenticator is present -- so a shared key is '
            'in use, and it is not recorded here -- but the digest is MD5, '
            'which is not a defensible authenticator today; the timestamps '
            'themselves are in the clear either way', facts)
    if len(payload) == NTP_MAC_SHA1_LEN:
        clauses.append('{0} bytes: a 4-byte key id and a 160-bit '
                       'digest'.format(len(payload)))
        facts['authenticator'] = 'symmetric-key-sha1'
        return Identification(
            'ntp', CERTAIN, '; '.join(clauses), PROTECTION_AUTHENTICATED,
            'a symmetric-key authenticator is present, so the packet is '
            'authenticated between two hosts that already share a key; the '
            'timestamps themselves are in the clear', facts)
    # A length that is neither the bare header, a known authenticator, nor a
    # clean extension-field chain. Refused rather than reported: the header
    # fields agreeing is not evidence about bytes this parser cannot account
    # for, and a trailing blob of unknown provenance is exactly how a decoy
    # is built.
    PARSE_STATS['cleartext_ntp_unaccounted_tail'] += 1
    return None


def _ntp_control(payload):
    """
    Mode 6, the control interface, recognised from its own count field.

    Worth its own branch because mode 6 and mode 7 are what made NTP the
    reflection amplifier of 2014, and an inventory that reported "NTP" for
    both a client asking the time and a `monlist` query would be answering a
    much less interesting question.
    """
    if len(payload) < NTP_CONTROL_HDR_LEN:
        return None
    first, second = payload[0], payload[1]
    version, mode = (first >> 3) & 0x07, first & 0x07
    if mode != NTP_CONTROL_MODE or version not in NTP_VERSIONS:
        return None
    opcode = second & 0x1F
    if not 1 <= opcode <= 8:
        return None
    count = _u16(payload, 10)
    # The data count must account for the payload *exactly*, allowing the
    # four-byte padding RFC 5905 appendix B requires and an optional
    # authenticator. Accepting "count fits inside the payload" instead is
    # how the first version of this claimed a 1,200-byte QUIC packet as a
    # mode 6 control message: 764 bytes of claimed data inside 1,200 of
    # payload is not a contradiction, and everything that is not a
    # contradiction gets sent eventually.
    padded = NTP_CONTROL_HDR_LEN + ((count + 3) & ~3)
    if len(payload) not in (padded, padded + 4 + 16, padded + 4 + 20):
        return None
    return Identification(
        'ntp', STRONG,
        'version {0}, mode 6 (control), opcode {1}, data count {2} within '
        'the {3}-byte payload'.format(version, opcode, count, len(payload)),
        PROTECTION_NONE,
        'the NTP control interface, unauthenticated: it answers questions '
        'about the server\'s peers and configuration, and it is the classic '
        'reflection amplifier -- a small query, a large reply, to whatever '
        'source address was asked for',
        {'mode': 'control', 'version': version, 'opcode': opcode})


def _ntp_extension_fields(payload):
    """True when the trailing bytes walk as NTS extension fields."""
    offset = NTP_HDR_LEN
    seen = 0
    found = False
    while offset + 4 <= len(payload) and seen < MAX_TLVS:
        field_type, length = _u16(payload, offset), _u16(payload, offset + 2)
        if length < 4 or length % 4 or offset + length > len(payload):
            return False
        if field_type in NTS_FIELD_TYPES:
            found = True
        offset += length
        seen += 1
    return found and offset == len(payload)


# --------------------------------------------------------------------------
# STUN / TURN
# --------------------------------------------------------------------------
STUN_COOKIE = b'\x21\x12\xa4\x42'       # RFC 5389 section 6
STUN_HDR_LEN = 20
STUN_METHODS = {0x001: 'binding', 0x003: 'allocate', 0x004: 'refresh',
                0x006: 'send', 0x007: 'data', 0x008: 'create-permission',
                0x009: 'channel-bind'}
STUN_CLASSES = {0: 'request', 1: 'indication', 2: 'success', 3: 'error'}
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_MESSAGE_INTEGRITY_SHA256 = 0x001C
ATTR_FINGERPRINT = 0x8028
# Named so that a report can say what the message was for. USERNAME is in
# the list because its *presence* matters; its value is an ICE ufrag, which
# is half of a credential, and it is never recorded.
STUN_ATTRIBUTES = {
    0x0001: 'mapped-address', ATTR_USERNAME: 'username',
    ATTR_MESSAGE_INTEGRITY: 'message-integrity', 0x0009: 'error-code',
    0x000C: 'channel-number', 0x000D: 'lifetime', 0x0012: 'xor-peer-address',
    0x0013: 'data', ATTR_REALM: 'realm', ATTR_NONCE: 'nonce',
    0x0016: 'xor-relayed-address', 0x0019: 'requested-transport',
    0x001A: 'dont-fragment', ATTR_MESSAGE_INTEGRITY_SHA256:
        'message-integrity-sha256', 0x0020: 'xor-mapped-address',
    0x0024: 'priority', 0x0025: 'use-candidate',
    ATTR_FINGERPRINT: 'fingerprint', 0x8022: 'software',
    0x8028: 'fingerprint', 0x8029: 'ice-controlled',
    0x802A: 'ice-controlling',
}


def _detect_stun(payload):
    if len(payload) < STUN_HDR_LEN or payload[4:8] != STUN_COOKIE:
        return None
    if payload[0] & 0xC0:
        return None                      # the two most significant bits are 0
    body = _u16(payload, 2)
    if body % 4:
        return None                      # RFC 5389: always a multiple of four
    raw_type = _u16(payload, 0)
    method = ((raw_type & 0x000F) | ((raw_type & 0x00E0) >> 1)
              | ((raw_type & 0x3E00) >> 2))
    klass = ((raw_type & 0x0010) >> 4) | ((raw_type & 0x0100) >> 7)
    clauses = [
        'the RFC 5389 magic cookie 0x2112a442 at offset 4',
        'message type 0x{0:04x}: {1} {2}'.format(
            raw_type, STUN_METHODS.get(method, 'method-0x{0:03x}'.format(
                method)), STUN_CLASSES[klass]),
        'body length {0} (a multiple of four)'.format(body),
    ]
    attributes = _stun_attributes(payload, body)
    names = [STUN_ATTRIBUTES.get(t, '0x{0:04x}'.format(t))
             for t in attributes]
    if STUN_HDR_LEN + body == len(payload):
        clauses.append('which fills the {0}-byte payload exactly'.format(
            len(payload)))
        confidence = CERTAIN
    else:
        confidence = STRONG

    integrity = (ATTR_MESSAGE_INTEGRITY in attributes
                 or ATTR_MESSAGE_INTEGRITY_SHA256 in attributes)
    facts = {'method': STUN_METHODS.get(method, method),
             'class': STUN_CLASSES[klass],
             'attributes': names[:MAX_LABELS],
             # Recorded as a flag, not as a value. The username is an ICE
             # ufrag and the realm and nonce are the server's half of a
             # long-term credential exchange.
             'credentialled': ATTR_USERNAME in attributes,
             'message_integrity': integrity}
    if integrity:
        return Identification(
            'stun', confidence, '; '.join(clauses), PROTECTION_AUTHENTICATED,
            'MESSAGE-INTEGRITY is present, so the message is authenticated '
            'with a key both ends already share -- and every address, '
            'candidate and username in it is readable by anything on the '
            'path', facts)
    return Identification(
        'stun', confidence, '; '.join(clauses), PROTECTION_NONE,
        'a STUN message with no MESSAGE-INTEGRITY attribute: unauthenticated '
        'and in the clear. What it negotiates -- an ICE candidate pair -- '
        'may go on to carry DTLS-SRTP, but nothing here shows that it does',
        facts)


def _stun_attributes(payload, body):
    """The attribute types present, in order. Never their values."""
    types = []
    offset = STUN_HDR_LEN
    end = min(STUN_HDR_LEN + body, len(payload))
    while offset + 4 <= end and len(types) < MAX_STUN_ATTRIBUTES:
        attr_type, length = _u16(payload, offset), _u16(payload, offset + 2)
        types.append(attr_type)
        # RFC 5389 section 15: attributes are padded to a four-byte boundary
        # and the padding is not counted in the length.
        offset += 4 + ((length + 3) & ~3)
    return types


# --------------------------------------------------------------------------
# HSRP
# --------------------------------------------------------------------------
# Cisco's gateway redundancy protocol, and by a wide margin the largest
# single thing in this corpus's UDP: 16,132 datagrams, 53% of all UDP and
# more than QUIC. What it decides is which router is the default gateway for
# a subnet, which makes its authentication the most consequential
# authentication in the capture.
HSRP_V1_LEN = 20
HSRP_V1_OPCODES = {0: 'hello', 1: 'coup', 2: 'resign', 3: 'advertise'}
HSRP_V1_STATES = {0: 'initial', 1: 'learn', 2: 'listen', 4: 'speak',
                  8: 'standby', 16: 'active'}
# The eight-byte plaintext authentication field of an HSRPv1 hello, and its
# factory default. Cisco's own documentation describes this field as
# providing no security; it is in the clear in every packet.
HSRP_DEFAULT_AUTH = b'cisco\x00\x00\x00'
HSRP_NO_AUTH = b'\x00' * 8
# The TLVs that can follow a v1 hello, and that make up a v2 packet.
HSRP_TLV_GROUP_STATE = 1
HSRP_TLV_INTERFACE_STATE = 2
HSRP_TLV_TEXT_AUTH = 3
HSRP_TLV_MD5_AUTH = 4
HSRP_DIGEST_ALGORITHMS = {1: 'md5'}
HSRP_V2_TLV_LEN = 40
HSRP_GROUPS = frozenset({'224.0.0.2', '224.0.0.102', 'ff02::66'})


def _detect_hsrp(payload, destination=None):
    if len(payload) < 2:
        return None
    if payload[0] == 0:
        return _hsrp_v1(payload, destination)
    if payload[0] in (HSRP_TLV_GROUP_STATE, HSRP_TLV_INTERFACE_STATE):
        return _hsrp_v2(payload, destination)
    return None


def _hsrp_v1(payload, destination):
    """
    An HSRPv1 packet: version 0, then a fixed 20-byte body or an Advertise.

    Field offsets taken from the corpus rather than from memory, which is
    worth saying because they are easy to get wrong and nothing downstream
    would notice: state is byte 2, not byte 4. The first draft of this
    function read the holdtime as the state and still identified every
    packet in the capture, because `0x01` is a valid state. What caught it
    was checking the *relationship* between the fields -- HSRP requires
    holdtime > hellotime > 0 -- which is also what stops this detector from
    claiming the mDNS queries whose first eight bytes are all zeroes.
    """
    opcode = payload[1]
    if opcode not in HSRP_V1_OPCODES:
        return None
    clauses = ['version 0, opcode {0} ({1})'.format(
        opcode, HSRP_V1_OPCODES[opcode])]
    facts = {'version': 1, 'opcode': HSRP_V1_OPCODES[opcode]}

    if opcode == 3:
        return _hsrp_advertise(payload, destination, clauses, facts)

    if len(payload) < HSRP_V1_LEN:
        return None
    state, hellotime, holdtime = payload[2], payload[3], payload[4]
    priority, group, reserved = payload[5], payload[6], payload[7]
    if state not in HSRP_V1_STATES or reserved != 0:
        return None
    if not 0 < hellotime < holdtime:
        # The timers are what make this more than a two-byte match: HSRP
        # will not run with a holdtime at or below the hellotime, and a
        # payload of zeroes cannot satisfy it.
        return None
    clauses.append(
        'state {0} ({1}), hellotime {2}s < holdtime {3}s, priority {4}, '
        'group {5}, reserved byte zero'.format(state, HSRP_V1_STATES[state],
                                               hellotime, holdtime, priority,
                                               group))
    facts['state'] = HSRP_V1_STATES[state]
    facts['group'] = group
    confidence = STRONG

    protection, why, auth_fact = _hsrp_plaintext_auth(bytes(payload[8:16]))
    facts['plaintext_auth'] = auth_fact
    tlvs = _hsrp_tlvs(payload, HSRP_V1_LEN)
    if tlvs:
        facts['tlvs'] = [t[0] for t in tlvs]
    digest = _hsrp_digest_tlv(payload, tlvs)
    if digest:
        clauses.append('followed by an authentication TLV, algorithm '
                       '{0}'.format(digest))
        facts['digest_auth'] = digest
        protection, why = _hsrp_digest_verdict(digest)

    if _is_multicast(destination, HSRP_GROUPS):
        clauses.append('sent to {0}'.format(destination))
        confidence = CERTAIN
    return Identification('hsrp', confidence, '; '.join(clauses), protection,
                          why, facts)


def _hsrp_advertise(payload, destination, clauses, facts):
    """
    Opcode 3, whose body is one TLV with a *two*-byte type and length.

    Not a typo and not consistent with the authentication TLVs above, which
    use one byte for each: the Advertise body predates them. The length
    covers the whole TLV including its own four-byte header, and checking it
    against the payload is what makes this identifiable at all -- there is
    otherwise nothing in an Advertise but small integers.
    """
    if len(payload) < 6:
        return None
    tlv_type, tlv_len = _u16(payload, 2), _u16(payload, 4)
    if tlv_type not in (HSRP_TLV_GROUP_STATE, HSRP_TLV_INTERFACE_STATE):
        return None
    if tlv_len != len(payload) - 2:
        return None
    clauses.append('a type-{0} TLV of {1} bytes, which is exactly the rest '
                   'of the {2}-byte payload'.format(tlv_type, tlv_len,
                                                    len(payload)))
    facts['tlvs'] = [tlv_type]
    confidence = STRONG
    if _is_multicast(destination, HSRP_GROUPS):
        clauses.append('sent to {0}'.format(destination))
        confidence = CERTAIN
    return Identification(
        'hsrp', confidence, '; '.join(clauses), PROTECTION_NONE,
        'an HSRP interface-state advertisement, which carries no '
        'authentication field at all', facts)


def _hsrp_plaintext_auth(auth):
    """
    What the eight-byte cleartext authentication field says. Never its value.

    Three answers, and the third is why this is a separate function: a
    non-default string is a *deployed secret being broadcast in the clear*,
    which is a finding in its own right, and the one thing this must not do
    is put that string in the report.
    """
    if auth == HSRP_NO_AUTH:
        return (PROTECTION_NONE,
                'the cleartext authentication field is empty and no '
                'authentication TLV follows: anything on this segment can '
                'send a higher-priority hello and become the default '
                'gateway for the subnet', 'absent')
    if auth == HSRP_DEFAULT_AUTH:
        return (PROTECTION_NONE,
                'the cleartext authentication field holds the factory '
                'default, which authenticates nothing -- it is published in '
                'the documentation -- so anything on this segment can take '
                'the gateway', 'default')
    return (PROTECTION_NONE,
            'a non-default cleartext authentication string is in use and is '
            'broadcast in every hello. It is not recorded here. It stops '
            'nobody who can read one packet, and it is a secret somebody '
            'chose and may have reused', 'plaintext')


def _hsrp_digest_verdict(algorithm):
    if algorithm == 'md5':
        return (PROTECTION_OBSOLETE,
                'authenticated with a keyed MD5 digest. That is real '
                'authentication and it is the reason an outsider cannot '
                'take the gateway -- but MD5 is not a defensible choice '
                'today, and there is still no confidentiality: the priority, '
                'the group and the virtual address are readable by anything '
                'on the segment')
    return (PROTECTION_AUTHENTICATED,
            'authenticated with a keyed digest ({0}); the packet contents '
            'remain readable by anything on the segment'.format(algorithm))


def _hsrp_tlvs(payload, offset):
    """(type, length, value-offset) for each TLV, bounded both ways."""
    tlvs = []
    while offset + 2 <= len(payload) and len(tlvs) < MAX_TLVS:
        tlv_type, length = payload[offset], payload[offset + 1]
        if length == 0 or offset + 2 + length > len(payload):
            # A zero length would make this loop infinite and an overrunning
            # one would read past the datagram. Not counted, for the reason
            # given at the DNS section-count refusal: this is the ordinary
            # exit for non-HSRP bytes, not an anomaly.
            break
        tlvs.append((tlv_type, length, offset + 2))
        offset += 2 + length
    return tlvs


def _hsrp_digest_tlv(payload, tlvs):
    """
    The algorithm named by an authentication TLV, or None.

    The algorithm is *read from the packet* rather than assumed from the TLV
    type. Type 4 is "authentication" and its first content byte is the
    algorithm number; treating type 4 as a synonym for MD5 would report a
    future SHA-256 TLV as MD5, which is the wrong way round for a verdict
    that says "obsolete".
    """
    for tlv_type, length, value in tlvs:
        if tlv_type == HSRP_TLV_MD5_AUTH and length >= 1 \
                and value < len(payload):
            algorithm = payload[value]
            return HSRP_DIGEST_ALGORITHMS.get(
                algorithm, 'algorithm-{0}'.format(algorithm))
        if tlv_type == HSRP_TLV_TEXT_AUTH:
            return 'text'
    return None


def _hsrp_v2(payload, destination):
    """
    HSRPv2 is a TLV list from byte 0: type 1 (group state) of length 40.

    Recognised so that a v2 deployment is not filed as unidentified; the
    corpus is entirely v1, so this branch has constructed coverage only and
    the tests say so.
    """
    tlvs = _hsrp_tlvs(payload, 0)
    if not tlvs or tlvs[0][0] != HSRP_TLV_GROUP_STATE \
            or tlvs[0][1] != HSRP_V2_TLV_LEN:
        return None
    offset = tlvs[0][2]
    if offset + 3 > len(payload) or payload[offset] != 2:
        return None
    opcode = payload[offset + 1]
    state = payload[offset + 2]
    if opcode not in HSRP_V1_OPCODES:
        return None
    clauses = ['a type-1 group-state TLV of length 40, version 2, opcode {0} '
               '({1}), state {2}'.format(opcode, HSRP_V1_OPCODES[opcode],
                                         state)]
    facts = {'version': 2, 'opcode': HSRP_V1_OPCODES[opcode],
             'tlvs': [t[0] for t in tlvs]}
    digest = _hsrp_digest_tlv(payload, tlvs)
    if digest:
        facts['digest_auth'] = digest
        protection, why = _hsrp_digest_verdict(digest)
        clauses.append('with an authentication TLV naming {0}'.format(digest))
    else:
        protection, why = (
            PROTECTION_NONE,
            'no authentication TLV: anything on this segment can send a '
            'higher-priority hello and become the default gateway')
    if _is_multicast(destination, HSRP_GROUPS):
        clauses.append('sent to {0}'.format(destination))
    return Identification('hsrp', STRONG, '; '.join(clauses), protection, why,
                          facts)


# --------------------------------------------------------------------------
# BER-framed: SNMP and CLDAP
# --------------------------------------------------------------------------
# Both open with a universal constructed SEQUENCE and both are read far
# enough to name the operation and the security mode, and no further. The
# length forms matter: Microsoft's CLDAP uses the four-byte long form even
# for small values, and a parser that only handles the short form reads a
# domain controller's reply as malformed.
BER_SEQUENCE = 0x30
MAX_BER_LENGTH_BYTES = 4


def _ber_length(payload, offset):
    """(length, offset past the length), or (None, None)."""
    if offset >= len(payload):
        return None, None
    first = payload[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > MAX_BER_LENGTH_BYTES \
            or offset + 1 + count > len(payload):
        # Indefinite length (0x80) is legal in BER and is not used by either
        # protocol here; more than four length bytes is a length this
        # datagram could not hold.
        return None, None
    value = 0
    for index in range(count):
        value = (value << 8) | payload[offset + 1 + index]
    return value, offset + 1 + count


def _ber_integer(payload, offset):
    """
    A small non-negative INTEGER, and the offset past it.

    `offset` points at the 0x02 *tag*; the length begins one byte later.
    Getting that off by one is the defect that silently lost every CLDAP
    datagram in the corpus on the first run: the length byte was read as the
    value, the message id came out as 512, and the application tag was then
    looked for in the middle of the id, so ten domain-controller pings were
    reported as unidentified rather than as unauthenticated directory
    traffic. It is in a comment because nothing about the output said the
    parser was wrong -- it said the protocol was absent.
    """
    if offset >= len(payload) or payload[offset] != 0x02:
        return None, None
    length, offset = _ber_length(payload, offset + 1)
    if length is None or not 1 <= length <= 4 \
            or offset + length > len(payload):
        return None, None
    value = 0
    for index in range(length):
        value = (value << 8) | payload[offset + index]
    return value, offset + length


SNMP_VERSIONS = {0: 'v1', 1: 'v2c', 2: 'v2u', 3: 'v3'}
SNMP_FLAG_AUTH = 0x01
SNMP_FLAG_PRIV = 0x02


def _detect_snmp(payload):
    """
    SNMP, and which of its three very different security models is in use.

    The version byte is the whole finding. v1 and v2c authenticate with a
    community string sent in the clear in every packet -- a password that is
    also, on most estates, the same password everywhere. v3 has a real user
    security model with separate authentication and privacy flags, and those
    flags say which of the three v3 modes a deployment actually chose,
    because `authNoPriv` is the common one and it is not encryption.
    """
    if not payload or payload[0] != BER_SEQUENCE:
        return None
    length, offset = _ber_length(payload, 1)
    if length is None:
        return None
    version, offset = _ber_integer(payload, offset)
    if version is None or version not in SNMP_VERSIONS:
        return None
    clauses = ['a BER SEQUENCE of {0} bytes'.format(length),
               'version {0} ({1})'.format(version, SNMP_VERSIONS[version])]
    confidence = LIKELY
    if _ber_span_matches(payload, length):
        clauses.append('whose length accounts for the whole {0}-byte '
                       'payload'.format(len(payload)))
        confidence = STRONG

    if version == 3:
        return _snmp_v3(payload, offset, clauses, confidence)
    # v1/v2c: an OCTET STRING community follows the version.
    if offset < len(payload) and payload[offset] == 0x04:
        community_len, after = _ber_length(payload, offset + 1)
        if community_len is not None and after is not None \
                and after + community_len <= len(payload):
            # The value is deliberately not read. Recording that a community
            # string is present is the finding; recording the string would
            # put a live credential in a report that gets circulated.
            clauses.append('followed by an OCTET STRING community string, '
                           'which is not recorded here')
            confidence = CERTAIN if confidence == STRONG else STRONG
        else:
            return None
    else:
        return None
    return Identification(
        'snmp', confidence, '; '.join(clauses), PROTECTION_NONE,
        'SNMP {0} authenticates with a community string carried in the '
        'clear in every packet. Anyone who can see one packet has the '
        'credential, and on most estates it is the same credential on every '
        'device'.format(SNMP_VERSIONS[version]),
        {'version': SNMP_VERSIONS[version], 'community_in_clear': True})


def _ber_span_matches(payload, length):
    """True when the SEQUENCE's length accounts for the whole payload."""
    _value, header_end = _ber_length(payload, 1)
    return header_end is not None and header_end + length == len(payload)


def _snmp_v3(payload, offset, clauses, confidence):
    """Read msgFlags out of the msgGlobalData SEQUENCE. Nothing else."""
    flags = None
    if offset < len(payload) and payload[offset] == BER_SEQUENCE:
        _length, inner = _ber_length(payload, offset + 1)
        if inner is not None:
            _msg_id, inner = _ber_integer(payload, inner)
            if inner is not None:
                _max_size, inner = _ber_integer(payload, inner)
            if inner is not None and inner + 2 < len(payload) \
                    and payload[inner] == 0x04 and payload[inner + 1] == 1:
                flags = payload[inner + 2]
    if flags is None:
        clauses.append('msgFlags not readable')
        return Identification(
            'snmp', confidence, '; '.join(clauses), PROTECTION_NONE,
            'SNMPv3, but the message flags could not be read, so nothing '
            'here shows that authentication or privacy is in use',
            {'version': 'v3'})
    auth = bool(flags & SNMP_FLAG_AUTH)
    priv = bool(flags & SNMP_FLAG_PRIV)
    mode = ('authPriv' if priv and auth else
            'authNoPriv' if auth else 'noAuthNoPriv')
    clauses.append('msgFlags 0x{0:02x}: {1}'.format(flags, mode))
    facts = {'version': 'v3', 'security_level': mode}
    if priv and auth:
        return Identification(
            'snmp', STRONG, '; '.join(clauses), PROTECTION_ENCRYPTED,
            'SNMPv3 authPriv: authenticated and encrypted under the user '
            'security model', facts)
    if auth:
        return Identification(
            'snmp', STRONG, '; '.join(clauses), PROTECTION_AUTHENTICATED,
            'SNMPv3 authNoPriv: authenticated, and every OID and value in '
            'the message is readable on the path', facts)
    return Identification(
        'snmp', STRONG, '; '.join(clauses), PROTECTION_NONE,
        'SNMPv3 noAuthNoPriv: the version supports real security and this '
        'deployment turned it off', facts)


# LDAP operations, by their APPLICATION tag (RFC 4511 section 4.2 onwards).
LDAP_OPERATIONS = {
    0x60: 'bindRequest', 0x61: 'bindResponse', 0x63: 'searchRequest',
    0x64: 'searchResEntry', 0x65: 'searchResDone', 0x67: 'modifyResponse',
    0x69: 'addResponse', 0x73: 'searchResRef', 0x77: 'extendedRequest',
    0x78: 'extendedResponse',
}
# The attribute that makes a CLDAP search a domain-controller locator ping.
# The name is a schema constant, not a value, so it is safe to look for and
# safe to name.
NETLOGON_MARKER = b'etlogon'


# Messages walked in one CLDAP datagram. A domain-controller reply carries
# two -- a searchResEntry and a searchResDone -- and nothing sane carries
# many.
MAX_LDAP_MESSAGES = 8


def _detect_cldap(payload):
    """
    Connectionless LDAP: whole LDAPMessages, in one datagram.

    *Messages*, plural, and that turned out to matter. A domain controller's
    reply to a netlogon ping is a searchResEntry followed immediately by a
    searchResDone in the same datagram, so checking one outer length against
    the payload reports every request as certain and every reply as merely
    likely -- half the conversation downgraded by a correct parse of the
    wrong shape. Walking the chain is also the strongest evidence available
    here: a sequence of BER lengths that lands exactly on the end of the
    datagram is several independent numbers agreeing, which is what CERTAIN
    is meant to mean.
    """
    if not payload or payload[0] != BER_SEQUENCE:
        return None
    operations = []
    offset = 0
    while offset < len(payload) and len(operations) < MAX_LDAP_MESSAGES:
        if payload[offset] != BER_SEQUENCE:
            break
        length, after = _ber_length(payload, offset + 1)
        if length is None or after + length > len(payload):
            break
        message_id, body = _ber_integer(payload, after)
        if message_id is None or body >= len(payload):
            break
        operation = payload[body]
        if operation not in LDAP_OPERATIONS:
            break
        operations.append((message_id, operation))
        offset = after + length
    if not operations:
        return None

    clauses = [
        'a BER SEQUENCE, message id {0}, then application tag 0x{1:02x} '
        '({2})'.format(operations[0][0], operations[0][1],
                       LDAP_OPERATIONS[operations[0][1]]),
    ]
    if offset == len(payload):
        clauses.append(
            '{0} LDAPMessage(s) whose lengths land exactly on the end of the '
            '{1}-byte datagram'.format(len(operations), len(payload)))
        confidence = CERTAIN
    else:
        clauses.append('but the message chain stops at offset {0} of {1}, '
                       'short of the end'.format(offset, len(payload)))
        confidence = LIKELY
    netlogon = NETLOGON_MARKER in payload
    if netlogon:
        clauses.append('carrying the netlogon attribute, so this is a '
                       'domain-controller locator ping')
    return Identification(
        'cldap', confidence, '; '.join(clauses), PROTECTION_NONE,
        'connectionless LDAP runs over UDP with no TLS and, in the form seen '
        'here, no bind: the directory names, domain GUID, domain SID and '
        'controller hostnames it exchanges are readable by anything on the '
        'path, and none of the values are recorded here',
        {'operations': [LDAP_OPERATIONS[op] for _id, op in operations],
         'netlogon': netlogon})


# --------------------------------------------------------------------------
# text protocols: SSDP and syslog
# --------------------------------------------------------------------------
SSDP_STARTS = (b'M-SEARCH * HTTP/1.1', b'NOTIFY * HTTP/1.1',
               b'HTTP/1.1 200 OK')
SSDP_HEADERS = (b'\nST:', b'\nNT:', b'\nUSN:', b'\nMAN:', b'\nNTS:')
SSDP_GROUPS = frozenset({'239.255.255.250', 'ff02::c', 'ff05::c'})


def _detect_ssdp(payload, destination=None):
    """HTTP request syntax over UDP, which is SSDP and nothing else."""
    head = bytes(payload[:256])
    start = None
    for candidate in SSDP_STARTS:
        if head.startswith(candidate):
            start = candidate
            break
    if start is None:
        return None
    upper = head.upper()
    headers = [h for h in SSDP_HEADERS if h in upper]
    clauses = ['the request line {0!r}'.format(_text(start, 32))]
    if headers:
        clauses.append('with {0} SSDP header(s)'.format(len(headers)))
        confidence = CERTAIN
    elif start.startswith(b'HTTP/'):
        # `HTTP/1.1 200 OK` on its own is a status line, not SSDP. An
        # M-SEARCH response always carries ST and USN; without them this is
        # some other HTTP-shaped thing over UDP and naming it would be a
        # guess dressed as a finding.
        return None
    else:
        confidence = STRONG
    if _is_multicast(destination, SSDP_GROUPS):
        clauses.append('sent to the SSDP group {0}'.format(destination))
    return Identification(
        'ssdp', confidence, '; '.join(clauses), PROTECTION_NONE,
        'SSDP is HTTP over UDP with no authentication: the device '
        'descriptions it advertises, and the URL they are fetched from, are '
        'chosen by whoever answers first',
        {'method': _text(start.split(b' ')[0], 16)})


# RFC 3164 / RFC 5424. PRI is facility * 8 + severity, so 0..191, written
# with no leading zero.
SYSLOG_MAX_PRI = 191
SYSLOG_MONTHS = (b'Jan', b'Feb', b'Mar', b'Apr', b'May', b'Jun', b'Jul',
                 b'Aug', b'Sep', b'Oct', b'Nov', b'Dec')


def _detect_syslog(payload):
    if len(payload) < 5 or payload[0:1] != b'<':
        return None
    close = payload.find(b'>', 1, 6)
    if close < 0:
        return None
    digits = bytes(payload[1:close])
    if not digits.isdigit() or (len(digits) > 1 and digits[0:1] == b'0'):
        return None
    pri = int(digits)
    if pri > SYSLOG_MAX_PRI:
        return None
    rest = bytes(payload[close + 1:close + 21])
    clauses = ['a priority field <{0}>: facility {1}, severity {2}'.format(
        pri, pri // 8, pri % 8)]
    version = None
    if len(rest) > 1 and rest[0:1].isdigit() and rest[1:2] == b' ':
        version = int(rest[0:1])
        clauses.append('followed by RFC 5424 version {0}'.format(version))
        confidence = CERTAIN
    elif rest[:3] in SYSLOG_MONTHS:
        clauses.append('followed by an RFC 3164 timestamp')
        confidence = CERTAIN
    else:
        clauses.append('but neither an RFC 5424 version digit nor an RFC '
                       '3164 timestamp follows it')
        confidence = LIKELY
    return Identification(
        'syslog', confidence, '; '.join(clauses), PROTECTION_NONE,
        'syslog over UDP has no authentication, no integrity and no '
        'confidentiality, and no delivery guarantee either: the audit trail '
        'is readable in transit and can be forged or suppressed by anything '
        'on the path',
        {'facility': pri // 8, 'severity': pri % 8, 'version': version})


# --------------------------------------------------------------------------
# BigFix / BES agent discovery
# --------------------------------------------------------------------------
# Here for the reason `pcapscan/protocols.py` gives for carrying STUN: there
# is exactly one of these in the corpus, and without it the answer to "what
# else is on this network in the clear" is "one flow, unidentified", which
# invites the reader to assume a detector failure rather than read a finding.
# It costs two literal comparisons.
BES_PREFIX = b'BES'
BES_SUFFIX = b'DONE'


def _detect_bigfix(payload):
    if not payload.startswith(BES_PREFIX) or len(payload) < 12:
        return None
    if not bytes(payload[3:5]).isdigit():
        return None
    if not payload.endswith(BES_SUFFIX):
        return None
    return Identification(
        'bigfix', STRONG,
        'opens with {0!r} and ends with the {1!r} terminator, which is the '
        'BigFix agent/relay discovery datagram'.format(
            _text(payload[:5], 8), _text(BES_SUFFIX, 8)),
        PROTECTION_NONE,
        'BigFix relay discovery is unauthenticated UDP. What it discovers is '
        'the relay an endpoint then takes its management commands from',
        {'version': _text(payload[3:5], 4)})


# --------------------------------------------------------------------------
# identify
# --------------------------------------------------------------------------
# In priority order, used only to break a tie between two detectors that
# returned the same confidence. Every detector runs on every datagram rather
# than the first match winning, so that ordering cannot quietly decide an
# answer -- the bytes do, through the confidence. This is the shape
# `pcapscan/protocols.py::detect` uses and the reasoning is the same: all of
# these bail within two or three comparisons.
_DETECTORS = (
    ('stun', lambda payload, src, dst: _detect_stun(payload)),
    ('dhcp', lambda payload, src, dst: _detect_dhcp(payload)),
    ('dns', lambda payload, src, dst: _detect_dns_family(payload, dst)),
    ('netbios-dgm', lambda payload, src, dst: _detect_netbios_dgm(payload,
                                                                  src)),
    ('hsrp', lambda payload, src, dst: _detect_hsrp(payload, dst)),
    ('ntp', lambda payload, src, dst: _detect_ntp(payload)),
    ('cldap', lambda payload, src, dst: _detect_cldap(payload)),
    ('snmp', lambda payload, src, dst: _detect_snmp(payload)),
    ('ssdp', lambda payload, src, dst: _detect_ssdp(payload, dst)),
    ('syslog', lambda payload, src, dst: _detect_syslog(payload)),
    ('bigfix', lambda payload, src, dst: _detect_bigfix(payload)),
)


def identify(payload, key=None):
    """
    What one datagram is, and what protects it. Returns None or an
    `Identification`.

    `key` is a `pcapscan.datagrams.DatagramKey`, or anything with `.src` and
    `.dst`, or None. The addresses are used where an address is genuinely
    evidence -- mDNS is DNS sent to 224.0.0.251, a NetBIOS datagram repeats
    its own source address in its header -- and never as a substitute for
    reading the bytes. The *ports* are not used at all.

    Never raises. Every refusal is counted in `cryptomon.utils.PARSE_STATS`.
    """
    try:
        payload = bytes(payload)
    except TypeError:
        PARSE_STATS['cleartext_payload_not_bytes'] += 1
        return None
    if not payload:
        return None
    source = getattr(key, 'src', None)
    destination = getattr(key, 'dst', None)

    best = None
    for index, (_name, detector) in enumerate(_DETECTORS):
        try:
            found = detector(payload, source, destination)
        except Exception:                # noqa: BLE001
            # A detector is handed attacker-chosen bytes on every datagram of
            # every capture. One that raises is a defect and is counted as
            # one, but it must not take the other detectors -- or the scan --
            # down with it.
            PARSE_STATS['cleartext_detector_error_' + _name] += 1
            continue
        if found is None:
            continue
        if best is None or (found.confidence, -index) > (best[0].confidence,
                                                         -best[1]):
            best = (found, index)
    if best is None:
        PARSE_STATS['cleartext_unidentified'] += 1
        return None
    return best[0]


# --------------------------------------------------------------------------
# the handler
# --------------------------------------------------------------------------
class CleartextHandler:
    """
    One UDP flow's worth of "what is this, and what protects it".

    The router gives each flow its own instance, pushes datagrams to it and
    asks for documents at the end. Every datagram is identified, not only the
    first: a flow whose datagrams disagree about what they are is a fact
    worth having, and it is the only way to notice a port carrying two
    protocols.
    """

    name = 'cleartext'

    # A hint for detector ordering and nothing else -- the router sorts
    # handlers whose `ports` intersect the flow to the front. Deliberately
    # excludes 443: QUIC owns that ordering, and nothing here would accept a
    # QUIC packet anyway (the corpus's 11,722 of them are the test that says
    # so). Every protocol below is recognised on any port, including the two
    # in this corpus that sit on ports no table names.
    ports = frozenset({
        53, 67, 68, 69, 123, 137, 138, 161, 162, 389, 514,
        1900, 1985, 2029, 3478, 3479, 3480, 5353, 5355,
    })

    @staticmethod
    def detect(payload, key=None):
        """Does this flow's first non-empty datagram look like cleartext?"""
        found = identify(payload, key)
        return found is not None and found.confidence >= MIN_CONFIDENCE

    def __init__(self):
        self.datagrams = 0
        self.octets = 0
        self.unidentified = 0
        self.protocols = collections.Counter()
        self.protections = collections.Counter()
        self.confidence = {}
        self.reasons = {}
        self.protection_reasons = {}
        self.facts = {}
        # Held to tell a repeated name from a new one, bounded, and never
        # emitted: only `len()` reaches a document. See the module docstring.
        self._names = set()
        self._names_seen = 0
        self._names_capped = False

    def push(self, timestamp, payload, key, datagram=None):
        self.datagrams += 1
        self.octets += len(payload)
        found = identify(payload, key)
        if found is None:
            self.unidentified += 1
            return
        protocol = found.protocol
        self.protocols[protocol] += 1
        self.protections[(protocol, found.protection)] += 1
        # The strongest reason is the one kept, so a flow whose first
        # datagram was truncated is still described by the one that was not.
        if found.confidence >= self.confidence.get(protocol, 0.0):
            self.confidence[protocol] = found.confidence
            self.reasons[protocol] = found.reason
        self.protection_reasons.setdefault(
            (protocol, found.protection), found.protection_reason)
        self._merge_facts(protocol, found.facts or {})
        self._count_names(found.names)

    def _count_names(self, names):
        for labels in names:
            self._names_seen += 1
            if len(self._names) < MAX_DISTINCT_NAMES:
                self._names.add(labels)
            elif labels not in self._names:
                self._names_capped = True

    def _merge_facts(self, protocol, facts):
        kept = self.facts.setdefault(protocol, {})
        for name, value in facts.items():
            if isinstance(value, dict):
                bucket = kept.setdefault(name, {})
                for label, count in value.items():
                    if len(bucket) < MAX_LABELS or label in bucket:
                        bucket[label] = bucket.get(label, 0) + count
            elif isinstance(value, list):
                bucket = kept.setdefault(name, [])
                for label in value:
                    if label not in bucket and len(bucket) < MAX_LABELS:
                        bucket.append(label)
            elif isinstance(value, bool):
                kept[name] = kept.get(name, False) or value
            elif isinstance(value, int) and name in ('questions', 'responses',
                                                     'names'):
                kept[name] = kept.get(name, 0) + value
            elif name in STICKY_FLAGS:
                # 0/1 flags that must latch on rather than freeze. These are
                # emitted as `int(...)` rather than bool, so they miss the
                # bool branch above and used to hit `setdefault` -- which
                # pinned them to whatever the *first* datagram said. A DNS
                # flow of (query with DO set) then (response carrying an
                # RRSIG) therefore reported `dnssec_signed: 0`, having just
                # seen the signature.
                kept[name] = max(kept.get(name, 0), value)
            elif kept.get(name) is None:
                # A later real value replaces a None; a later None never
                # replaces a real value. `setdefault` did neither: it pinned
                # the field to whatever the *first* datagram said, and DHCP's
                # `message_type` is legitimately None on a datagram with no
                # option 53, so the flow then reported None for ever. Note
                # this still records the key when the first value is None --
                # "seen, and empty" and "never seen" are different answers.
                kept[name] = value

    def _protection_reason(self, protocol, protection):
        """Why this flow earned its verdict, and from which protocol."""
        exact = self.protection_reasons.get((protocol, protection))
        if exact:
            return exact
        # Whichever protocol earned the verdict. Sorted by how much of the
        # flow it accounts for, then by name, rather than taken in insertion
        # order -- otherwise which protocol gets credited for a shared
        # verdict depends on the order datagrams happened to arrive in, and
        # the same capture could describe the same flow two ways.
        candidates = [(other, reason)
                      for (other, found), reason in
                      self.protection_reasons.items()
                      if found == protection and reason]
        if not candidates:
            return None
        other, reason = max(
            candidates, key=lambda item: (self.protocols.get(item[0], 0),
                                          item[0]))
        if other == protocol:
            return reason
        return '{0} ({1})'.format(reason, other)

    def finish(self):
        """
        One document for the flow, or none when nothing was recognised.

        `datagrams` and `bytes` count what this handler was *given*, which
        is not the same as what was on the wire: the router stops delivering
        after `pcapscan.datagrams.MAX_DATAGRAMS`, and on this corpus that
        turns four HSRP flows carrying 16,132 datagrams into four documents
        reporting 64 each. That cap is inherited and deliberate, and the
        honest thing is to name the field for what it holds rather than to
        imply a total the handler never saw. The router's `flows_capped`
        counter is where "and there was more" is recorded.
        """
        if not self.protocols:
            return ()
        protocol, _count = self.protocols.most_common(1)[0]
        protection = self._worst_protection()
        block = {
            'protocol': protocol,
            'confidence': self.confidence.get(protocol),
            'reason': self.reasons.get(protocol),
            'protection': protection,
            # Looked up by the verdict alone when the flow's most-common
            # protocol did not earn it. A mixed flow is expected here --
            # three authenticated STUN datagrams plus one MD5-authenticated
            # NTP datagram is `obsolete` on NTP's account, not STUN's -- and
            # keying on (protocol, protection) meant that pair had never
            # been recorded, so the reason came back None and the verdict
            # read as though STUN had earned it. The verdict is about the
            # flow; so is its reason.
            'protection_reason': self._protection_reason(protocol,
                                                         protection),
            'datagrams': self.datagrams,
            'bytes': self.octets,
            'identified': sum(self.protocols.values()),
            'unidentified': self.unidentified,
            protocol: self.facts.get(protocol) or {},
        }
        if self._names_seen:
            # How much this flow leaked, without saying what. `names` counts
            # every name carried and `distinct_names` how many of them were
            # different, because "400 datagrams naming one host" and "400
            # naming four hundred" are very different disclosures.
            block['names'] = self._names_seen
            block['distinct_names'] = len(self._names)
            if self._names_capped:
                block['distinct_names_capped'] = True
        breakdown = self._protection_breakdown()
        if len(breakdown) > 1:
            # The flow's datagrams did not agree. `protection` above is the
            # weakest of them, because the weakest is the one an attacker
            # picks -- but reporting only that would erase the fact that the
            # rest were protected. The corpus has exactly this case: an HSRP
            # group whose hellos carry an MD5 authentication TLV and whose
            # interface-state advertisements carry none.
            block['protections'] = breakdown
        if len(self.protocols) > 1:
            # Two protocols on one flow. Rare, and exactly the thing a
            # port-based inventory cannot see, so it is named rather than
            # averaged away.
            block['also'] = dict(self.protocols)
        return ({'cleartext': block},)

    def _protection_breakdown(self):
        """How many datagrams earned each verdict."""
        counts = collections.Counter()
        for (_protocol, protection), count in self.protections.items():
            counts[protection] += count
        return dict(counts)

    def _worst_protection(self):
        """The weakest verdict any datagram in the flow earned."""
        verdicts = {protection for _protocol, protection in self.protections}
        return min(verdicts, key=lambda v: _PROTECTION_ORDER.get(v, 0))


HANDLER = CleartextHandler


__all__ = ['CleartextHandler', 'HANDLER', 'Identification', 'identify',
           'PROTECTION_AUTHENTICATED', 'PROTECTION_ENCRYPTED',
           'PROTECTION_NONE', 'PROTECTION_OBSOLETE', 'PROTECTIONS',
           'MIN_CONFIDENCE']
