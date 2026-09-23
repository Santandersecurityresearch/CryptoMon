"""
What UDP carries in the clear, and whether this module can be made to lie.

Three kinds of test here and the split is the point.

**Constructed inputs** for the protocols the capture corpus does not
contain. The corpus holds HSRP, DNS, mDNS, DHCP, NetBIOS name and datagram
service, CLDAP, NTP, STUN, SSDP and one BigFix discovery datagram; it holds
no SNMP, no syslog, no LLMNR, no HSRPv2, no DNSSEC-signed answer and no NTP
authenticator. Those branches therefore have exactly the coverage written
here, and saying so is more useful than implying a corpus validation that
does not exist.

**Corpus bytes**, committed as short hex literals taken from the captures,
for the protocols the corpus does contain. They are short enough to read and
they are the actual wire bytes, so a change that stops recognising real
traffic fails here rather than in a measurement nobody re-runs. The HSRP
sample in particular is the one that proves a field-offset claim: state is
byte 2, and a parser that reads byte 4 still identifies the packet.

**Negative tests, which carry the most weight.** A detector that says
"probably DNS" about everything is worse than no detector, because it moves
the wrong answer from the port number -- where everybody knows to distrust
it -- into a field labelled `confidence`. So: random bytes, zeros, the
empty payload, QUIC-shaped payloads, and the specific attacks each parser
invites. The DNS compression pointer loop is the first test in the file for
a reason: it is the one input here that could hang a worker thread rather
than return a wrong answer, and a hang behind an upload form is a denial of
service against the whole tool.
"""
import collections
import os
import struct

import pytest

from cryptomon.analysis import NOT_APPLICABLE
from cryptomon.utils import PARSE_STATS, reset_parse_stats
from pcapscan.cleartext import (CERTAIN, HANDLER, LIKELY, MAX_DISTINCT_NAMES,
                                MIN_CONFIDENCE, PROTECTION_AUTHENTICATED,
                                PROTECTION_ENCRYPTED, PROTECTION_NONE,
                                PROTECTION_OBSOLETE, PROTECTIONS, STRONG,
                                CleartextHandler, Identification, _read_name,
                                identify)
from pcapscan.datagrams import DatagramKey

from fuzzing import mutate, seeded

# Marked per class rather than on the module. Everything here is fast and
# needs no fixture -- except `test_the_corpus_udp_inventory` at the bottom,
# which walks 160,000 packets when the corpus is present. The smoke set is
# the merge gate and something slow in it costs every PR, so that one test
# is deliberately left out of it.
SMOKE = pytest.mark.smoke

# Budget for the mutation pass. Small enough for the merge gate, large
# enough that a bound which stopped holding would show up;
# tests/tools/fuzz.py is where a real campaign belongs.
FUZZ_CASES = 1500


def key(sport=5000, dport=53, src='10.0.0.5', dst='10.0.0.1'):
    return DatagramKey(src, sport, dst, dport)


# --------------------------------------------------------------------------
# the input that could hang rather than be wrong
# --------------------------------------------------------------------------
class TestNameExpansion:
    """
    RFC 1035 compression, and the loop it makes possible.

    `_read_name` refuses a pointer that does not point strictly backwards,
    which makes a loop arithmetically impossible. These assert that, and
    assert the ordinary cases still work -- a defence that also refuses
    valid compression would quietly stop this module recognising real DNS.
    """

    pytestmark = SMOKE

    def test_self_referential_pointer_is_refused(self):
        # A pointer at offset 12 pointing at offset 12. The naive
        # implementation follows it forever.
        payload = bytes(12) + b'\xc0\x0c'
        assert _read_name(payload, 12) == (None, None)

    def test_forward_pointer_is_refused(self):
        payload = bytes(12) + b'\xc0\x10' + bytes(8)
        assert _read_name(payload, 12) == (None, None)

    def test_two_pointers_in_a_cycle_are_refused(self):
        # 12 -> 16 -> 12. Both hops are legal on their own; the cycle is not,
        # and the strictly-backwards rule breaks it at the forward hop.
        payload = bytearray(24)
        payload[12:14] = b'\xc0\x10'
        payload[16:18] = b'\xc0\x0c'
        assert _read_name(bytes(payload), 12) == (None, None)

    def test_backward_pointer_is_followed(self):
        payload = b'\x03www\x07example\x03com\x00' + b'\xc0\x00'
        labels, after = _read_name(payload, len(payload) - 2)
        assert labels == [b'www', b'example', b'com']
        assert after == len(payload)

    def test_name_length_is_capped(self):
        # 300 bytes of one-byte labels: each is legal, the total is not.
        payload = b'\x01a' * 300 + b'\x00'
        assert _read_name(payload, 0) == (None, None)

    def test_reserved_label_type_is_refused(self):
        assert _read_name(b'\x80abc\x00', 0) == (None, None)

    def test_unterminated_name_is_refused(self):
        assert _read_name(b'\x03www', 0) == (None, None)

    def test_label_overrunning_the_buffer_is_refused(self):
        assert _read_name(b'\x3fshort', 0) == (None, None)

    @pytest.mark.parametrize('depth', [1, 8, 20, 64])
    def test_chained_backward_pointers_terminate(self, depth):
        """
        A chain of legal backward pointers is bounded, not followed forever.

        Every hop here points strictly backwards, so the loop defence does
        not fire; MAX_NAME_POINTERS is what stops it, and the test asserts
        only that the call returns.
        """
        payload = bytearray(b'\x01a\x00')
        offsets = [0]
        for _ in range(depth):
            offsets.append(len(payload))
            payload += struct.pack('>H', 0xC000 | offsets[-2])
        labels, _after = _read_name(bytes(payload), offsets[-1])
        assert labels is None or labels == [b'a']


# --------------------------------------------------------------------------
# constructed messages
# --------------------------------------------------------------------------
def dns_name(name):
    out = b''
    for label in name.encode('ascii').split(b'.'):
        out += bytes([len(label)]) + label
    return out + b'\x00'


def dns_query(name='example.com', qtype=1, transaction_id=0x1234,
              flags=0x0100, additional=b'', arcount=0):
    header = struct.pack('>HHHHHH', transaction_id, flags, 1, 0, 0, arcount)
    return header + dns_name(name) + struct.pack('>HH', qtype, 1) + additional


def dns_record(name, rtype, ttl=60, rdata=b'\x7f\x00\x00\x01', rclass=1):
    return (dns_name(name) + struct.pack('>HHIH', rtype, rclass, ttl,
                                         len(rdata)) + rdata)


def opt_record(payload_size=4096, dnssec_ok=False):
    ttl = 0x8000 if dnssec_ok else 0
    return b'\x00' + struct.pack('>HHIH', 41, payload_size, ttl, 0)


class TestDns:
    pytestmark = SMOKE

    def test_a_query_is_certain(self):
        found = identify(dns_query(), key())
        assert found.protocol == 'dns'
        assert found.confidence == CERTAIN
        assert found.protection == PROTECTION_NONE
        assert 'A' in found.facts['qtypes']

    def test_the_query_name_is_not_recorded(self):
        found = identify(dns_query('secret-internal-host.example.com'),
                         key())
        # Everything that can reach a document, plus the whole record: the
        # `names` field holds keyed tokens, not labels, so even a repr of
        # the Identification is safe to print.
        assert 'secret-internal-host' not in repr(found)
        assert 'secret-internal-host' not in found.reason
        assert 'secret-internal-host' not in repr(found.facts)

    def test_do_bit_without_signatures_is_still_unprotected(self):
        payload = dns_query(additional=opt_record(dnssec_ok=True), arcount=1)
        found = identify(payload, key())
        assert found.facts['dnssec_ok'] == 1
        assert found.facts['dnssec_signed'] == 0
        assert found.protection == PROTECTION_NONE
        assert 'no signature' in found.protection_reason

    def test_edns0_without_the_do_bit_is_reported(self):
        payload = dns_query(additional=opt_record(dnssec_ok=False),
                            arcount=1)
        found = identify(payload, key())
        assert found.facts['dnssec_ok'] == 0
        assert 'DO clear' in found.reason

    def test_an_rrsig_answer_is_authenticated_not_encrypted(self):
        header = struct.pack('>HHHHHH', 0x1234, 0x8180, 1, 2, 0, 0)
        body = (dns_name('example.com') + struct.pack('>HH', 1, 1)
                + dns_record('example.com', 1)
                + dns_record('example.com', 46, rdata=b'\x00' * 20))
        found = identify(header + body, key(5000, 53))
        assert found.protocol == 'dns'
        assert found.facts['dnssec_signed'] == 1
        assert found.protection == PROTECTION_AUTHENTICATED
        # The distinction the brief asks for, asserted in the text a reader
        # of the report would see.
        assert 'does not hide the question' in found.protection_reason

    def test_a_query_type_the_table_does_not_name_keeps_its_number(self):
        found = identify(dns_query(qtype=9999), key())
        assert 'TYPE9999' in found.facts['qtypes']

    def test_https_record_queries_are_named(self):
        found = identify(dns_query(qtype=65), key())
        assert found.facts['qtypes'] == {'HTTPS': 1}

    def test_reserved_z_bit_is_refused(self):
        assert identify(dns_query(flags=0x0140), key()) is None

    def test_unassigned_opcode_is_refused(self):
        assert identify(dns_query(flags=0x7800), key()) is None

    def test_unassigned_rcode_is_refused(self):
        assert identify(dns_query(flags=0x800C), key()) is None

    def test_a_question_count_the_payload_cannot_hold_is_refused(self):
        header = struct.pack('>HHHHHH', 1, 0x0100, 4, 0, 0, 0)
        assert identify(header + dns_name('a.com') + b'\x00\x01\x00\x01',
                        key()) is None


class TestMdnsAndLlmnr:
    pytestmark = SMOKE

    def test_mdns_is_decided_by_the_group_not_the_port(self):
        payload = struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0) \
            + dns_name('_smb._tcp.local') + struct.pack('>HH', 12, 1)
        # Deliberately not on port 5353: the address is the evidence.
        found = identify(payload, key(40000, 40001, dst='224.0.0.251'))
        assert found.protocol == 'mdns'
        assert found.facts['services'] == ['_smb._tcp.local']

    def test_the_instance_label_is_dropped_and_the_service_kept(self):
        payload = struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0) \
            + dns_name('DESKTOP-5F7S8C0._dosvc._tcp.local') \
            + struct.pack('>HH', 12, 1)
        found = identify(payload, key(5353, 5353, dst='224.0.0.251'))
        assert found.facts['services'] == ['_dosvc._tcp.local']
        assert 'DESKTOP' not in repr(found.facts)

    def test_a_plain_hostname_query_records_no_service(self):
        payload = struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0) \
            + dns_name('Someones-MacBook-Pro.local') \
            + struct.pack('>HH', 1, 1)
        found = identify(payload, key(5353, 5353, dst='ff02::fb'))
        assert found.protocol == 'mdns'
        assert found.facts['services'] == []
        assert 'MacBook' not in repr(found.facts)

    def test_llmnr_group(self):
        payload = dns_query('wpad', transaction_id=0x4242)
        found = identify(payload, key(50000, 5355, dst='224.0.0.252'))
        assert found.protocol == 'llmnr'
        assert found.protection == PROTECTION_NONE
        assert 'relay' in found.protection_reason

    def test_the_same_bytes_unicast_are_plain_dns(self):
        payload = dns_query('wpad', transaction_id=0x4242)
        assert identify(payload, key(50000, 53)).protocol == 'dns'


def netbios_name(name, suffix=0x00):
    padded = name.ljust(15)[:15].encode('ascii') + bytes([suffix])
    encoded = bytearray()
    for byte in padded:
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    return bytes([32]) + bytes(encoded) + b'\x00'


class TestNetbios:
    pytestmark = SMOKE

    def test_name_query_is_certain_and_records_only_the_suffix(self):
        payload = struct.pack('>HHHHHH', 0x95A2, 0x0110, 1, 0, 0, 0) \
            + netbios_name('WORKSTATION01') + struct.pack('>HH', 32, 1)
        found = identify(payload, key(137, 137, dst='10.0.0.255'))
        assert found.protocol == 'netbios-ns'
        assert found.confidence == CERTAIN
        assert found.facts['suffixes'] == {'workstation': 1}
        assert 'WORKSTATION01' not in repr(found.facts)

    def test_domain_controller_suffix_is_named(self):
        payload = struct.pack('>HHHHHH', 1, 0x0110, 1, 0, 0, 0) \
            + netbios_name('CORP', 0x1C) + struct.pack('>HH', 32, 1)
        found = identify(payload, key(137, 137, dst='10.0.0.255'))
        assert found.facts['suffixes'] == {'domain-controllers': 1}

    def test_datagram_service_needs_its_own_address_back(self):
        payload = (b'\x11\x02\xe0\xea' + bytes([10, 67, 5, 40])
                   + struct.pack('>HHH', 138, 187, 0)
                   + netbios_name('SENDER') + netbios_name('CORP', 0x1D))
        found = identify(payload, key(138, 138, src='10.67.5.40',
                                      dst='10.67.5.47'))
        assert found.protocol == 'netbios-dgm'
        assert found.confidence == CERTAIN

    def test_a_datagram_claiming_somebody_elses_address_is_weaker(self):
        payload = (b'\x11\x02\xe0\xea' + bytes([192, 168, 9, 9])
                   + struct.pack('>HHH', 138, 187, 0)
                   + netbios_name('SENDER') + netbios_name('CORP', 0x1D))
        found = identify(payload, key(138, 138, src='10.67.5.40',
                                      dst='10.67.5.47'))
        assert found.protocol == 'netbios-dgm'
        assert found.confidence == STRONG

    def test_an_unknown_message_type_is_refused(self):
        assert identify(b'\x99' + bytes(20), key(138, 138)) is None


def dhcp(message_type=1, options=b'', op=1):
    fixed = bytearray(236)
    fixed[0], fixed[1], fixed[2] = op, 1, 6
    body = bytes(fixed) + b'\x63\x82\x53\x63'
    body += bytes([53, 1, message_type]) + options + b'\xff'
    return body


class TestDhcp:
    pytestmark = SMOKE

    def test_discover_is_certain(self):
        found = identify(dhcp(), key(68, 67, dst='255.255.255.255'))
        assert found.protocol == 'dhcp'
        assert found.confidence == CERTAIN
        assert found.facts['message_type'] == 'discover'
        assert found.protection == PROTECTION_NONE

    def test_the_hostname_option_is_named_but_not_read(self):
        options = bytes([12, 8]) + b'LAPTOP01'
        found = identify(dhcp(options=options), key(68, 67))
        assert 'hostname' in found.facts['options']
        assert 'LAPTOP01' not in repr(found.facts)

    def test_rfc3118_authentication_option_changes_the_verdict(self):
        options = bytes([90, 4]) + b'\x01\x02\x03\x04'
        found = identify(dhcp(options=options), key(68, 67))
        assert found.protection == PROTECTION_AUTHENTICATED

    def test_an_option_overrunning_the_payload_stops_the_walk(self):
        found = identify(dhcp(options=bytes([12, 200])), key(68, 67))
        assert found.protocol == 'dhcp'

    def test_a_missing_cookie_is_refused(self):
        payload = bytes(236) + b'\x00\x00\x00\x00' + b'\xff'
        assert identify(payload, key(68, 67)) is None


def ntp(mode=3, version=4, stratum=0, poll=0, precision=0, tail=b''):
    head = bytearray(48)
    head[0] = (version << 3) | mode
    head[1] = stratum
    head[2] = poll & 0xFF
    head[3] = precision & 0xFF
    return bytes(head) + tail


class TestNtp:
    pytestmark = SMOKE

    def test_a_bare_client_request_is_certain_and_unprotected(self):
        found = identify(ntp(), key(50000, 123))
        assert found.protocol == 'ntp'
        assert found.confidence == CERTAIN
        assert found.protection == PROTECTION_NONE

    def test_md5_authenticator_is_obsolete_not_authenticated(self):
        found = identify(ntp(tail=bytes(4 + 16)), key(123, 123))
        assert found.protection == PROTECTION_OBSOLETE
        assert found.facts['authenticator'] == 'symmetric-key-md5'

    def test_sha1_authenticator_is_authenticated_only(self):
        found = identify(ntp(tail=bytes(4 + 20)), key(123, 123))
        assert found.protection == PROTECTION_AUTHENTICATED

    def test_nts_extension_fields_are_encrypted(self):
        field = struct.pack('>HH', 0x0104, 36) + bytes(32)
        found = identify(ntp(tail=field), key(50000, 123))
        assert found.protection == PROTECTION_ENCRYPTED
        assert found.facts['nts'] is True

    def test_ntp_v1_and_v2_are_refused(self):
        # Accepting them cost 329 false positives over the corpus.
        assert identify(ntp(version=1), key(50000, 123)) is None
        assert identify(ntp(version=2), key(50000, 123)) is None

    def test_a_root_delay_of_hours_is_refused(self):
        head = bytearray(ntp(mode=4, stratum=2, poll=6, precision=-20 & 0xFF))
        head[4:8] = struct.pack('>I', 0x0100_0000)
        assert identify(bytes(head), key(123, 50000)) is None

    def test_an_unaccounted_tail_is_refused_not_downgraded(self):
        reset_parse_stats()
        assert identify(ntp(tail=bytes(7)), key(50000, 123)) is None
        assert PARSE_STATS['cleartext_ntp_unaccounted_tail'] == 1

    def test_control_mode_needs_its_count_to_match(self):
        good = struct.pack('>BBHHHH', (4 << 3) | 6, 2, 1, 0, 0, 0) \
            + struct.pack('>H', 0)
        found = identify(good, key(50000, 123))
        assert found.protocol == 'ntp'
        assert 'amplifier' in found.protection_reason
        # The same header with a count that does not account for the payload
        # is what a 1,200-byte QUIC packet looked like.
        bad = struct.pack('>BBHHHH', (4 << 3) | 6, 2, 1, 0, 0, 0) \
            + struct.pack('>H', 764) + bytes(1188)
        assert identify(bad, key(50000, 443)) is None


def stun(method=0x001, attributes=b'', klass=0):
    raw_type = ((method & 0x0F) | ((method & 0x70) << 1)
                | ((method & 0xF80) << 2)
                | ((klass & 1) << 4) | ((klass & 2) << 7))
    return (struct.pack('>HH', raw_type, len(attributes)) + b'\x21\x12\xa4\x42'
            + bytes(12) + attributes)


def stun_attribute(attr_type, value):
    padded = value + bytes((4 - len(value) % 4) % 4)
    return struct.pack('>HH', attr_type, len(value)) + padded


class TestStun:
    pytestmark = SMOKE

    def test_a_binding_request_without_integrity_is_unprotected(self):
        found = identify(stun(), key(50000, 3478))
        assert found.protocol == 'stun'
        assert found.confidence == CERTAIN
        assert found.protection == PROTECTION_NONE
        assert found.facts['method'] == 'binding'

    def test_message_integrity_makes_it_authenticated(self):
        attrs = stun_attribute(0x0008, bytes(20))
        found = identify(stun(attributes=attrs), key(50000, 3478))
        assert found.protection == PROTECTION_AUTHENTICATED
        assert found.facts['message_integrity'] is True

    def test_the_ice_username_is_flagged_not_recorded(self):
        attrs = stun_attribute(0x0006, b'haqH:Vgj+')
        found = identify(stun(attributes=attrs), key(50000, 3478))
        assert found.facts['credentialled'] is True
        assert 'haqH' not in repr(found)

    def test_a_body_length_that_is_not_a_multiple_of_four_is_refused(self):
        payload = bytearray(stun())
        payload[2:4] = struct.pack('>H', 3)
        assert identify(bytes(payload), key(50000, 3478)) is None

    def test_a_missing_cookie_is_refused(self):
        payload = bytearray(stun())
        payload[4:8] = b'\x00\x00\x00\x00'
        assert identify(bytes(payload), key(50000, 3478)) is None


def hsrp_v1(opcode=0, state=16, hellotime=1, holdtime=3, priority=105,
            group=100, auth=b'\x00' * 8, tlvs=b''):
    return (bytes([0, opcode, state, hellotime, holdtime, priority, group, 0])
            + auth + bytes([10, 0, 0, 1]) + tlvs)


HSRP_MD5_TLV = (bytes([4, 28, 1, 0]) + b'\x00\x00' + bytes([10, 0, 0, 2])
                + bytes(4) + bytes(16))


class TestHsrp:
    pytestmark = SMOKE

    def test_a_hello_with_no_authentication_can_be_taken_over(self):
        found = identify(hsrp_v1(), key(1985, 1985, dst='224.0.0.2'))
        assert found.protocol == 'hsrp'
        assert found.confidence == CERTAIN
        assert found.protection == PROTECTION_NONE
        assert found.facts['plaintext_auth'] == 'absent'
        assert 'default gateway' in found.protection_reason

    def test_the_factory_default_string_authenticates_nothing(self):
        found = identify(hsrp_v1(auth=b'cisco\x00\x00\x00'),
                         key(1985, 1985, dst='224.0.0.2'))
        assert found.facts['plaintext_auth'] == 'default'
        assert found.protection == PROTECTION_NONE

    def test_a_deployed_plaintext_key_is_flagged_never_quoted(self):
        found = identify(hsrp_v1(auth=b'Tr0ub4d\x00'),
                         key(1985, 1985, dst='224.0.0.2'))
        assert found.facts['plaintext_auth'] == 'plaintext'
        assert 'Tr0ub4d' not in repr(found)
        assert 'not recorded here' in found.protection_reason

    def test_an_md5_tlv_is_obsolete_rather_than_authenticated(self):
        found = identify(hsrp_v1(tlvs=HSRP_MD5_TLV),
                         key(1985, 1985, dst='224.0.0.2'))
        assert found.facts['digest_auth'] == 'md5'
        assert found.protection == PROTECTION_OBSOLETE

    def test_the_digest_algorithm_is_read_from_the_packet(self):
        tlv = bytearray(HSRP_MD5_TLV)
        tlv[2] = 3
        found = identify(hsrp_v1(tlvs=bytes(tlv)),
                         key(1985, 1985, dst='224.0.0.2'))
        assert found.facts['digest_auth'] == 'algorithm-3'
        assert found.protection == PROTECTION_AUTHENTICATED

    def test_the_timers_are_what_refuse_a_run_of_zeroes(self):
        # holdtime must exceed hellotime. Without this an mDNS query, whose
        # first eight bytes are zero, is a valid HSRP hello.
        assert identify(hsrp_v1(hellotime=0, holdtime=0),
                        key(1985, 1985)) is None
        assert identify(hsrp_v1(hellotime=3, holdtime=1),
                        key(1985, 1985)) is None

    def test_a_non_zero_reserved_byte_is_refused(self):
        payload = bytearray(hsrp_v1())
        payload[7] = 1
        assert identify(bytes(payload), key(1985, 1985)) is None

    def test_an_advertise_needs_its_tlv_length_to_match(self):
        good = bytes([0, 3]) + struct.pack('>HH', 1, 14) + bytes(10)
        found = identify(good, key(1985, 1985, dst='224.0.0.2'))
        assert found.protocol == 'hsrp'
        assert found.facts['opcode'] == 'advertise'
        bad = bytes([0, 3]) + struct.pack('>HH', 1, 99) + bytes(10)
        assert identify(bad, key(1985, 1985, dst='224.0.0.2')) is None

    def test_hsrp_v2_group_state(self):
        # Constructed only: the corpus is entirely v1.
        tlv = bytes([1, 40, 2, 0, 16]) + bytes(37)
        found = identify(tlv, key(1985, 1985, dst='224.0.0.2'))
        assert found.protocol == 'hsrp'
        assert found.facts['version'] == 2


def ber_sequence(body):
    return b'\x30' + _ber_len(len(body)) + body


def _ber_len(length):
    if length < 0x80:
        return bytes([length])
    return b'\x84' + struct.pack('>I', length)


def ber_integer(value):
    raw = struct.pack('>H', value)
    return b'\x02' + bytes([len(raw)]) + raw


class TestCldapAndSnmp:
    """
    Constructed only for SNMP: there is not one SNMP packet in the corpus.
    """

    pytestmark = SMOKE

    def test_a_cldap_search_request(self):
        body = ber_integer(169) + b'\x63' + _ber_len(4) + b'\x04\x00\x0a\x01'
        found = identify(ber_sequence(body), key(50000, 389))
        assert found.protocol == 'cldap'
        assert found.confidence == CERTAIN
        assert found.facts['operations'] == ['searchRequest']
        assert found.protection == PROTECTION_NONE

    def test_two_messages_in_one_datagram_still_reach_certain(self):
        entry = ber_sequence(ber_integer(169) + b'\x64' + _ber_len(2)
                             + b'\x04\x00')
        done = ber_sequence(ber_integer(169) + b'\x65' + _ber_len(2)
                            + b'\x0a\x01')
        found = identify(entry + done, key(389, 50000))
        assert found.confidence == CERTAIN
        assert found.facts['operations'] == ['searchResEntry',
                                             'searchResDone']

    def test_a_netlogon_ping_is_named_without_quoting_the_domain(self):
        body = (ber_integer(169) + b'\x63' + _ber_len(20)
                + b'\x04\x08netlogon' + b'\x04\x08CORP\x00\x00\x00\x00')
        found = identify(ber_sequence(body), key(50000, 389))
        assert found.facts['netlogon'] is True
        assert 'CORP' not in repr(found.facts)

    def test_an_unknown_application_tag_is_refused(self):
        body = ber_integer(1) + b'\x7f' + _ber_len(2) + b'\x00\x00'
        assert identify(ber_sequence(body), key(50000, 389)) is None

    def test_snmp_v2c_community_is_flagged_never_recorded(self):
        body = (b'\x02\x01\x01' + b'\x04\x06public'
                + b'\xa0' + _ber_len(2) + b'\x02\x00')
        found = identify(ber_sequence(body), key(50000, 161))
        assert found.protocol == 'snmp'
        assert found.facts['version'] == 'v2c'
        assert found.facts['community_in_clear'] is True
        assert 'public' not in repr(found)
        assert found.protection == PROTECTION_NONE

    def test_snmp_v1_is_the_same_verdict(self):
        body = (b'\x02\x01\x00' + b'\x04\x07private'
                + b'\xa0' + _ber_len(2) + b'\x02\x00')
        found = identify(ber_sequence(body), key(50000, 161))
        assert found.facts['version'] == 'v1'
        assert 'private' not in repr(found)

    @pytest.mark.parametrize('flags,expected,level', [
        (0x03, PROTECTION_ENCRYPTED, 'authPriv'),
        (0x01, PROTECTION_AUTHENTICATED, 'authNoPriv'),
        (0x00, PROTECTION_NONE, 'noAuthNoPriv'),
    ])
    def test_snmp_v3_security_level_decides_the_verdict(self, flags,
                                                        expected, level):
        globals_block = ber_sequence(
            b'\x02\x02\x00\x01' + b'\x02\x02\x05\xc0'
            + bytes([0x04, 1, flags]) + b'\x02\x01\x03')
        body = b'\x02\x01\x03' + globals_block
        found = identify(ber_sequence(body), key(50000, 161))
        assert found.protocol == 'snmp'
        assert found.facts['security_level'] == level
        assert found.protection == expected


class TestTextProtocols:
    pytestmark = SMOKE

    def test_ssdp_m_search(self):
        payload = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                   b'MAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\n\r\n')
        found = identify(payload, key(50000, 1900, dst='239.255.255.250'))
        assert found.protocol == 'ssdp'
        assert found.confidence == CERTAIN

    def test_syslog_rfc5424(self):
        payload = b'<34>1 2003-10-11T22:14:15.003Z host su - ID47 - message'
        found = identify(payload, key(50000, 514))
        assert found.protocol == 'syslog'
        assert found.facts == {'facility': 4, 'severity': 2, 'version': 1}
        assert found.protection == PROTECTION_NONE

    def test_syslog_rfc3164(self):
        payload = b'<13>Oct 11 22:14:15 host message'
        assert identify(payload, key(50000, 514)).confidence == CERTAIN

    def test_a_priority_above_191_is_refused(self):
        assert identify(b'<999>Oct 11 22:14:15 host m', key(50000, 514)) \
            is None

    def test_a_leading_zero_priority_is_refused(self):
        assert identify(b'<034>1 x', key(50000, 514)) is None

    def test_bigfix_discovery(self):
        found = identify(b'BES10\x00\x00\x00\x00\x00\x00\x00DONE',
                         key(50000, 52311))
        assert found.protocol == 'bigfix'

    def test_bes_without_the_terminator_is_refused(self):
        assert identify(b'BES10' + bytes(12), key(50000, 52311)) is None


# --------------------------------------------------------------------------
# negatives
# --------------------------------------------------------------------------
class TestRefusals:
    pytestmark = SMOKE

    def test_empty_payload(self):
        assert identify(b'', key()) is None
        assert HANDLER.detect(b'', key()) is False

    def test_all_zeroes(self):
        for length in (1, 8, 20, 48, 512):
            assert identify(bytes(length), key()) is None

    def test_all_ones(self):
        for length in (1, 8, 20, 48, 512):
            assert identify(b'\xff' * length, key()) is None

    def test_a_payload_that_is_not_bytes_is_counted_not_raised(self):
        reset_parse_stats()
        assert identify(object(), key()) is None
        assert PARSE_STATS['cleartext_payload_not_bytes'] == 1

    def test_no_key_at_all(self):
        assert identify(dns_query(), None).protocol == 'dns'

    def test_random_bytes_are_almost_never_claimed(self):
        """
        The headline negative. 8,000 random payloads over the lengths this
        module sees, and the acceptance rate has to stay near zero -- a
        module whose job is to name unprotected traffic is only useful if a
        name means something.
        """
        rnd = seeded('cleartext-random')
        claimed = collections.Counter()
        for _ in range(8000):
            length = rnd.choice([1, 4, 12, 20, 48, 64, 128, 512, 1200])
            payload = bytes(rnd.randrange(256) for _ in range(length))
            found = identify(payload, key(rnd.randrange(65536),
                                          rnd.randrange(65536)))
            if found is not None:
                claimed[found.protocol] += 1
        assert sum(claimed.values()) < 8, claimed

    def test_quic_shaped_payloads_are_never_claimed(self):
        """
        QUIC is the other handler's traffic and the corpus is 11,722
        packets of it. A short-header QUIC packet is a first byte with the
        0x40 fixed bit set and then ciphertext, so this is the shape that
        matters most.
        """
        rnd = seeded('cleartext-quic')
        claimed = 0
        for _ in range(2500):
            first = 0x40 | rnd.randrange(0x40)
            body = bytes(rnd.randrange(256)
                         for _ in range(rnd.randrange(20, 1350)))
            if identify(bytes([first]) + body, key(50000, 443)) is not None:
                claimed += 1
        assert claimed == 0


class TestFuzz:
    """
    Mutated real messages. The bound being tested is that nothing raises and
    nothing hangs; correctness of the answer is not the question here.
    """

    pytestmark = SMOKE

    def seeds(self):
        return [
            dns_query(),
            dns_query(additional=opt_record(dnssec_ok=True), arcount=1),
            struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0)
            + dns_name('_smb._tcp.local') + struct.pack('>HH', 12, 1),
            struct.pack('>HHHHHH', 1, 0x0110, 1, 0, 0, 0)
            + netbios_name('WS01') + struct.pack('>HH', 32, 1),
            dhcp(options=bytes([12, 4]) + b'HOST'),
            ntp(),
            ntp(tail=bytes(20)),
            stun(attributes=stun_attribute(0x0008, bytes(20))),
            hsrp_v1(tlvs=HSRP_MD5_TLV),
            ber_sequence(ber_integer(1) + b'\x63' + _ber_len(2) + b'\x04\x00'),
            b'<34>1 2003-10-11T22:14:15.003Z host su - ID47 - m',
            b'M-SEARCH * HTTP/1.1\r\nST: upnp:rootdevice\r\n\r\n',
        ]

    def test_mutated_messages_never_raise(self):
        rnd = seeded('cleartext-fuzz')
        seeds = self.seeds()
        addresses = ['10.0.0.1', '224.0.0.251', '224.0.0.2', '255.255.255.255',
                     'ff02::fb', None]
        for _ in range(FUZZ_CASES):
            payload = mutate(rnd.choice(seeds), rnd)
            flow = DatagramKey(rnd.choice(addresses), rnd.randrange(65536),
                               rnd.choice(addresses), rnd.randrange(65536))
            found = identify(payload, flow)
            if found is not None:
                assert found.protection in PROTECTIONS
                assert 0.0 < found.confidence <= 1.0

    def test_mutated_messages_never_leak_a_raw_label(self):
        """
        A mutated name could end up anywhere a reason string is built. The
        rule is that a name never reaches a document, so this asserts the
        marker strings the seeds carry never appear in one.
        """
        rnd = seeded('cleartext-leak')
        handler = CleartextHandler()
        marker = b'SECRETHOST'
        seeds = [dns_query('SECRETHOST.example.com'),
                 struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0)
                 + dns_name('SECRETHOST._smb._tcp.local')
                 + struct.pack('>HH', 12, 1),
                 dhcp(options=bytes([12, 10]) + marker)]
        for _ in range(FUZZ_CASES):
            payload = mutate(rnd.choice(seeds), rnd)
            handler.push(0.0, payload, key(5353, 5353, dst='224.0.0.251'))
        for document in handler.finish():
            assert marker.decode() not in repr(document)


# --------------------------------------------------------------------------
# the handler
# --------------------------------------------------------------------------
class TestHandler:
    pytestmark = SMOKE

    def test_the_seam_contract(self):
        assert HANDLER is CleartextHandler
        assert CleartextHandler.name == 'cleartext'
        assert 443 not in CleartextHandler.ports
        assert isinstance(CleartextHandler.ports, frozenset)
        assert callable(CleartextHandler.detect)

    def test_detect_accepts_likely_and_above(self):
        assert MIN_CONFIDENCE == LIKELY
        assert CleartextHandler.detect(dns_query(), key()) is True

    def test_a_flow_becomes_one_document(self):
        handler = CleartextHandler()
        handler.push(1.0, dns_query('a.example.com'), key(50000, 53))
        handler.push(1.5, dns_query('b.example.com'), key(53, 50000))
        documents = list(handler.finish())
        assert len(documents) == 1
        block = documents[0]['cleartext']
        assert block['protocol'] == 'dns'
        assert block['datagrams'] == 2
        assert block['names'] == 2
        assert block['distinct_names'] == 2
        assert block['protection'] == PROTECTION_NONE

    def test_a_flow_with_nothing_recognised_emits_nothing(self):
        handler = CleartextHandler()
        handler.push(1.0, b'\x01\x02\x03\x04', key(50000, 9999))
        assert list(handler.finish()) == []

    def test_disagreeing_datagrams_report_the_weakest_and_say_so(self):
        handler = CleartextHandler()
        flow = key(1985, 1985, dst='224.0.0.2')
        handler.push(1.0, hsrp_v1(tlvs=HSRP_MD5_TLV), flow)
        handler.push(1.1, bytes([0, 3]) + struct.pack('>HH', 1, 14)
                     + bytes(10), flow)
        block = list(handler.finish())[0]['cleartext']
        assert block['protection'] == PROTECTION_NONE
        assert block['protections'] == {PROTECTION_NONE: 1,
                                        PROTECTION_OBSOLETE: 1}

    def test_two_protocols_on_one_flow_are_both_named(self):
        handler = CleartextHandler()
        flow = key(5353, 5353, dst='224.0.0.251')
        handler.push(1.0, dns_query(), key(50000, 53))
        handler.push(1.1, struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0)
                     + dns_name('_smb._tcp.local')
                     + struct.pack('>HH', 12, 1), flow)
        block = list(handler.finish())[0]['cleartext']
        assert set(block['also']) == {'dns', 'mdns'}

    def test_distinct_names_are_bounded(self):
        handler = CleartextHandler()
        for index in range(MAX_DISTINCT_NAMES + 50):
            handler.push(1.0, dns_query('h{0}.example.com'.format(index)),
                         key(50000, 53))
        block = list(handler.finish())[0]['cleartext']
        assert block['distinct_names'] == MAX_DISTINCT_NAMES
        assert block['distinct_names_capped'] is True
        assert block['names'] == MAX_DISTINCT_NAMES + 50

    def test_the_document_carries_no_names_at_all(self):
        handler = CleartextHandler()
        handler.push(1.0, dns_query('very-distinctive-name.example.com'),
                     key(50000, 53))
        assert 'very-distinctive-name' not in repr(list(handler.finish()))

    def test_push_never_raises_on_hostile_bytes(self):
        rnd = seeded('cleartext-handler-fuzz')
        handler = CleartextHandler()
        for _ in range(500):
            payload = bytes(rnd.randrange(256)
                            for _ in range(rnd.randrange(0, 200)))
            handler.push(0.0, payload, key(rnd.randrange(65536),
                                           rnd.randrange(65536)))
        list(handler.finish())


# --------------------------------------------------------------------------
# vocabulary
# --------------------------------------------------------------------------
class TestVocabulary:
    pytestmark = SMOKE

    def test_none_is_the_constant_analysis_already_had(self):
        """
        The one verdict this module did not have to invent. The other three
        are proposed for cryptomon/analysis.py; until they are there this
        asserts the reuse rather than a copy, so the strings cannot drift.
        """
        assert PROTECTION_NONE is NOT_APPLICABLE
        assert PROTECTION_NONE == 'none'

    def test_every_verdict_is_in_the_published_tuple(self):
        assert set(PROTECTIONS) == {PROTECTION_NONE, PROTECTION_OBSOLETE,
                                    PROTECTION_AUTHENTICATED,
                                    PROTECTION_ENCRYPTED}

    def test_the_confidence_ladder_is_the_tcp_ladder(self):
        from pcapscan import protocols
        assert (CERTAIN, STRONG, LIKELY) == (protocols.CERTAIN,
                                             protocols.STRONG,
                                             protocols.LIKELY)

    def test_an_identification_is_self_describing(self):
        found = identify(dns_query(), key())
        assert isinstance(found, Identification)
        assert found.reason and found.protection_reason
        # The names field exists for counting and must never be a dict key
        # that reaches a document; see the handler tests above.
        assert isinstance(found.names, tuple)


# --------------------------------------------------------------------------
# the corpus, as committed bytes
# --------------------------------------------------------------------------
# Real payloads lifted from the capture corpus, short enough to read. They
# are here because a measurement nobody re-runs is not a regression test:
# these fail the moment this module stops recognising traffic it was built
# against. Hostnames and addresses in them are from the project's own
# captures and are already in the repository's fixtures.
CORPUS = {
    'hsrp-hello-md5': (
        '000010010369640000000000000000000ab44981041c010000000ab44982'
        '000000004b86d1951447dbb91c133b1705fb15f4'),
    'hsrp-advertise': '00030001000e02000000000100000000',
    'ntp-client': '23' + '00' * 47,
    'ntp-server-gps': (
        '240106eb000000000000001d47505373eb048bc532574a0d0000000000000000'
        'eb048bccdd790a4beb048bccdd79cc5f'),
    'dhcp-discover': (
        '01010600b9ffc733' + '00' * 28 + 'f024081021b9' + '00' * 194
        + '63825363' + '350101' + 'ff'),
}


class TestCorpusBytes:
    pytestmark = SMOKE

    def test_hsrp_hello_is_md5_authenticated_not_plaintext(self):
        """
        The corpus contradicts the common belief about HSRP.

        All 15,867 hellos in the capture carry an empty plaintext
        authentication field and a type-4 MD5 authentication TLV. Not one
        carries the literal string `cisco`.
        """
        payload = bytes.fromhex(CORPUS['hsrp-hello-md5'])
        found = identify(payload, key(1985, 1985, dst='224.0.0.2'))
        assert found.protocol == 'hsrp'
        assert found.confidence == CERTAIN
        assert found.facts['plaintext_auth'] == 'absent'
        assert found.facts['digest_auth'] == 'md5'
        assert found.facts['state'] == 'active'
        assert found.facts['group'] == 100
        assert found.protection == PROTECTION_OBSOLETE

    def test_hsrp_state_is_byte_two(self):
        """
        A parser reading the state at byte 4 gets `0x03` -- not a valid
        state, so it would refuse; at byte 5 it gets `0x69`, also invalid.
        This pins the offset against a real packet rather than against
        memory.
        """
        payload = bytes.fromhex(CORPUS['hsrp-hello-md5'])
        assert payload[2] == 16 and payload[3] == 1 and payload[4] == 3

    def test_hsrp_advertise_from_the_corpus(self):
        found = identify(bytes.fromhex(CORPUS['hsrp-advertise']),
                         key(1985, 1985, dst='224.0.0.2'))
        assert found.facts['opcode'] == 'advertise'
        assert found.protection == PROTECTION_NONE

    def test_ntp_client_and_server_from_the_corpus(self):
        client = identify(bytes.fromhex(CORPUS['ntp-client']),
                          key(50416, 123))
        assert client.protocol == 'ntp' and client.facts['mode'] == 'client'
        server = identify(bytes.fromhex(CORPUS['ntp-server-gps']),
                          key(123, 50416))
        assert server.facts['mode'] == 'server'
        assert server.facts['stratum'] == 1
        assert server.protection == PROTECTION_NONE

    def test_dhcp_discover_from_the_corpus(self):
        found = identify(bytes.fromhex(CORPUS['dhcp-discover']),
                         key(68, 67, dst='255.255.255.255'))
        assert found.protocol == 'dhcp'
        assert found.facts['message_type'] == 'discover'


# --------------------------------------------------------------------------
# the corpus, when it is here
# --------------------------------------------------------------------------
# CryptomonData/ is not committed (it is in .gitignore), so these are skipped
# in CI and run on a developer machine that has it. They are what turns the
# numbers in the module docstring into something a change can invalidate.
CORPUS_ROOT = os.environ.get('CRYPTOMON_CORPUS')


@pytest.mark.skipif(not CORPUS_ROOT or not os.path.isdir(CORPUS_ROOT),
                    reason='set CRYPTOMON_CORPUS to the capture corpus')
def test_the_corpus_udp_inventory():
    """
    The measurement, as an assertion: no QUIC flow is ever claimed here.

    That is the property that matters when four UDP handlers share one
    router. The counts are asserted loosely -- this is about the module not
    stealing another handler's traffic, not about the exact capture.
    """
    import glob

    from cryptomon.parsers.framing import decode_datagram
    from pcapscan.reader import Reader

    claimed_on_443 = 0
    identified = collections.Counter()
    for path in sorted(glob.glob(os.path.join(CORPUS_ROOT, '**', '*.pcap'),
                                 recursive=True)):
        with Reader(path) as reader:
            for packet in reader:
                datagram = decode_datagram(packet.data, packet.linktype)
                if datagram is None:
                    continue
                source = datagram.endpoints['src']
                destination = datagram.endpoints['dst']
                payload = bytes(packet.data[datagram.payload_offset:
                                            datagram.payload_end])
                if not payload:
                    continue
                flow = DatagramKey(
                    source.get('ipv4') or source.get('ipv6'), source['port'],
                    destination.get('ipv4') or destination.get('ipv6'),
                    destination['port'])
                found = identify(payload, flow)
                if found is None:
                    continue
                identified[found.protocol] += 1
                if 443 in (flow.sport, flow.dport):
                    claimed_on_443 += 1
    # The property that matters when four UDP handlers share one router.
    assert claimed_on_443 == 0
    # Every capture directory this could be pointed at has DNS in it;
    # HSRP lives only in `sandbox/`, so it is not asserted here.
    assert identified['dns'] > 0
    assert sum(identified.values()) > 0
