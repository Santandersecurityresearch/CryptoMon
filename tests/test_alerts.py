"""
TLS alerts: the names, and the judgement about which ones are findings.

Naming the codes is a table and would need little testing on its own. What
is tested here is the judgement built on top of it, because both of its
failure modes are silent. Report close_notify and every clean shutdown in a
capture becomes an incident; miss the post-quantum correlation and the one
finding the tool exists to produce is a row in a table of numbers.
"""
import pytest

from cryptomon.alerts import (ALERT_DESCRIPTIONS, CRYPTOGRAPHIC, ORDINARY,
                              PQ_HANDSHAKE_FAILURE, SHUTDOWN, describe,
                              describe_description, describe_level, findings,
                              is_finding, offered_post_quantum, severity,
                              summarise)

pytestmark = pytest.mark.smoke


def record(*alerts, **tls):
    """A session record carrying the given (level, description) alerts."""
    if alerts:
        tls['alerts'] = [{'level': level, 'description': description}
                         for level, description in alerts]
    return {'ptype': 'session', 'ts': 1700000000.0,
            'eth': {'src': {'ipv4': '10.0.0.1', 'port': 50000},
                    'dst': {'ipv4': '93.184.216.34', 'port': 443}},
            'tls': tls}


# --------------------------------------------------------------------------
# naming
# --------------------------------------------------------------------------
@pytest.mark.parametrize("code,name", [
    (0, 'close_notify'),
    (10, 'unexpected_message'),
    (20, 'bad_record_mac'),
    (40, 'handshake_failure'),
    (42, 'bad_certificate'),
    (43, 'unsupported_certificate'),
    (44, 'certificate_revoked'),
    (45, 'certificate_expired'),
    (46, 'certificate_unknown'),
    (47, 'illegal_parameter'),
    (48, 'unknown_ca'),
    (49, 'access_denied'),
    (50, 'decode_error'),
    (51, 'decrypt_error'),
    (70, 'protocol_version'),
    (71, 'insufficient_security'),
    (80, 'internal_error'),
    (86, 'inappropriate_fallback'),
    (90, 'user_canceled'),
    (109, 'missing_extension'),
    (110, 'unsupported_extension'),
    (112, 'unrecognized_name'),
    (113, 'bad_certificate_status_response'),
    (116, 'certificate_required'),
    (120, 'no_application_protocol'),
])
def test_every_named_code(code, name):
    """
    The registry, spelled as RFC 8446 section 6.2 spells it. A report that
    renames an alert cannot be compared with a packet capture, which is the
    first thing anyone reading it will want to do.
    """
    assert describe_description(code) == name


def test_the_registry_is_complete_enough_to_be_useful():
    """
    Retired code points are in the table too. A peer still sending
    no_certificate_RESERVED should be named, not reported as unknown -- the
    name is the evidence of how old the stack on the other end is.
    """
    assert ALERT_DESCRIPTIONS[41] == 'no_certificate_RESERVED'
    assert ALERT_DESCRIPTIONS[115] == 'unknown_psk_identity'
    assert len(ALERT_DESCRIPTIONS) >= 35


@pytest.mark.parametrize("code", [7, 200, 255])
def test_an_unknown_code_keeps_its_number(code):
    """
    Collapsing every unrecognised alert into one 'Unknown' bucket loses the
    only thing that could identify it afterwards. Same rule as
    describe_codepoint() in cryptomon/utils.py.
    """
    label = describe_description(code)
    assert str(code) in label
    assert label.startswith('Unknown')


def test_two_unknown_codes_do_not_collide():
    assert describe_description(200) != describe_description(201)


def test_levels_are_named_and_an_invented_one_is_kept():
    assert describe_level(1) == 'warning'
    assert describe_level(2) == 'fatal'
    assert '3' in describe_level(3)


def test_naming_never_raises_on_rubbish():
    """
    These integers came off the wire. A parser that raises on the third
    field of an attacker-supplied record loses the whole session.
    """
    for value in (None, 'forty', -1, 3.5, (1, 2)):
        assert describe_description(value).startswith('Unknown')
        assert describe_level(value).startswith('Unknown')


# --------------------------------------------------------------------------
# close_notify is not an incident
# --------------------------------------------------------------------------
def test_close_notify_is_never_a_finding():
    """
    The failure this prevents is the expensive one: close_notify is how a
    TLS connection is supposed to end, so reporting it turns every clean
    shutdown into an incident and buries the real findings under them.
    """
    assert severity({'level': 1, 'description': 0}) == SHUTDOWN
    assert not is_finding({'level': 1, 'description': 0})
    assert findings([record((1, 0))]) == []


def test_close_notify_is_not_a_finding_even_when_sent_as_fatal():
    """
    The level byte is advisory in TLS 1.3 and some stacks send close_notify
    at level 2. It is still the end of a connection.
    """
    assert not is_finding({'level': 2, 'description': 0})


def test_a_summary_counts_the_shutdowns_it_excluded():
    """
    Excluding them silently would be indistinguishable from failing to
    parse them. The count is what makes the exclusion auditable.
    """
    summary = summarise([record((1, 0)), record((2, 40)), record()])
    assert summary['sessions'] == 3
    assert summary['sessions_with_alerts'] == 2
    assert summary['clean_shutdowns'] == 1
    assert summary['alerts']['close_notify'] == 1
    assert len(summary['findings']) == 1


# --------------------------------------------------------------------------
# severity
# --------------------------------------------------------------------------
@pytest.mark.parametrize("code", [40, 70, 71, 86, 120])
def test_the_cryptographic_alerts(code):
    assert severity({'level': 2, 'description': code}) == CRYPTOGRAPHIC


@pytest.mark.parametrize("code", [46, 45, 48, 90, 112, 80])
def test_ordinary_alerts_are_reported_but_not_as_crypto(code):
    """
    An expired certificate is a real problem and a finding; it is not a
    finding about which algorithms are deployed, and filing it under one
    heading with handshake_failure would dilute both.
    """
    alert = {'level': 2, 'description': code}
    assert severity(alert) == ORDINARY
    assert is_finding(alert)


def test_a_mac_failure_is_not_filed_as_a_cryptographic_finding():
    """
    bad_record_mac fires after the algorithms were agreed: it is a bug or a
    corrupt path, not a verdict on anybody's cryptography.
    """
    assert severity({'level': 2, 'description': 20}) == ORDINARY


def test_severity_reads_the_description_not_the_level():
    """A handshake_failure sent at level 1 has still refused the handshake."""
    assert severity({'level': 1, 'description': 40}) == CRYPTOGRAPHIC


def test_alerts_can_be_dicts_tuples_or_namedtuples():
    """
    The record holds dicts, pcapscan holds namedtuples and tests write
    tuples. Converting in every caller would be three chances to get it
    wrong.
    """
    from pcapscan.records import Alert
    assert severity(Alert(2, 40)) == CRYPTOGRAPHIC
    assert severity((2, 40)) == CRYPTOGRAPHIC
    assert severity({'level': 2, 'description': 40}) == CRYPTOGRAPHIC
    assert describe(Alert(2, 40))['name'] == 'handshake_failure'


# --------------------------------------------------------------------------
# the correlation this PR exists for
# --------------------------------------------------------------------------
def test_a_post_quantum_offer_then_handshake_failure_is_its_own_finding():
    """
    The finding the module is for. A client that offered ML-KEM and got a
    fatal handshake_failure has met a peer or a middlebox that cannot cope
    with the key share, and the report has to say so loudly enough that
    somebody goes and looks -- which means not filing it beside every other
    failed handshake.
    """
    found = findings([record((2, 40), hostname='pq.example',
                             proposed={'groups': ['X25519MLKEM768',
                                                  'x25519']})])
    assert len(found) == 1
    assert found[0]['kind'] == PQ_HANDSHAKE_FAILURE
    assert found[0]['alert']['name'] == 'handshake_failure'
    assert found[0]['offered_post_quantum'] == ['X25519MLKEM768']


def test_the_finding_carries_enough_to_act_on():
    """
    A finding nobody can chase is a statistic. Host, address, port, time and
    the offer are what turns it into a ticket.
    """
    found = findings([record((2, 40), hostname='pq.example',
                             proposed={'groups': ['X25519MLKEM768']})])[0]
    assert found['hostname'] == 'pq.example'
    assert found['address'] == '93.184.216.34'
    assert found['port'] == 443
    assert found['ts'] == 1700000000.0


def test_a_handshake_failure_without_a_post_quantum_offer_is_not_correlated():
    """
    Most failed handshakes have nothing to do with post-quantum. Claiming
    them would inflate the one number the tool is trusted for.
    """
    found = findings([record((2, 40), hostname='plain.example',
                             proposed={'groups': ['x25519', 'secp256r1']})])
    assert found[0]['kind'] != PQ_HANDSHAKE_FAILURE
    assert found[0]['severity'] == CRYPTOGRAPHIC
    assert found[0]['offered_post_quantum'] == []


def test_a_post_quantum_offer_with_an_ordinary_alert_is_not_correlated():
    """
    35 of the 42 alerted sessions in the corpus had offered a post-quantum
    group, because current browsers offer one on every connection. Treating
    "offered PQ" as the finding would report 11 expired-certificate warnings
    as post-quantum intolerance.
    """
    found = findings([record((2, 46), hostname='cert.example',
                             proposed={'groups': ['X25519MLKEM768']})])
    assert found[0]['kind'] != PQ_HANDSHAKE_FAILURE
    assert found[0]['severity'] == ORDINARY


def test_inappropriate_fallback_is_its_own_finding():
    """
    86 is downgrade protection firing (RFC 7507): something retried at a
    lower version and was caught. Two of these are in the corpus. Folding
    them in with the rest would lose the only alert that is evidence of an
    attempted downgrade rather than of a preference.
    """
    found = findings([record((2, 86), hostname='fallback.example')])
    assert found[0]['kind'] == 'inappropriate_fallback'
    assert found[0]['severity'] == CRYPTOGRAPHIC


def test_the_offer_is_found_wherever_the_record_puts_it():
    """
    A server that refuses the connection never sends a HelloRetryRequest, so
    `offered_kex_group` is absent and the only evidence of what the client
    wanted is in its proposal. Reading one field alone loses most of the
    correlation.
    """
    assert offered_post_quantum(
        record(proposed={'groups': ['X25519MLKEM768']})) \
        == ['X25519MLKEM768']
    assert offered_post_quantum(
        record(proposed={'kex_group': 'X25519Kyber768Draft00'})) \
        == ['X25519Kyber768Draft00']
    assert offered_post_quantum(
        record(offered_kex_group='SecP256r1MLKEM768')) \
        == ['SecP256r1MLKEM768']
    assert offered_post_quantum(record(kex_group='x25519')) == []


def test_hybrid_counts_as_a_post_quantum_offer():
    """
    Every post-quantum key exchange on the wire today is hybrid, and it is
    the hybrid key share's *size* that the intolerant middleboxes choke on.
    Requiring a pure post-quantum group would find nothing, ever.
    """
    assert offered_post_quantum(
        record(proposed={'groups': ['X25519MLKEM768']}))


def test_the_same_group_is_not_reported_twice():
    """It appears in the proposal and in the key share; it is one offer."""
    assert offered_post_quantum(
        record(proposed={'groups': ['X25519MLKEM768'],
                         'kex_group': 'X25519MLKEM768'},
               kex_group='X25519MLKEM768')) == ['X25519MLKEM768']


def test_records_without_alerts_and_ssh_records_are_skipped():
    """summarise() runs over whole captures; most records have no alerts."""
    ssh = {'ptype': 'session', 'ts': 1.0, 'eth': {},
           'ssh': {'KEXalgs': ['sntrup761x25519-sha512@openssh.com']}}
    summary = summarise([record(), ssh])
    assert summary['sessions'] == 2
    assert summary['findings'] == []


def test_a_corpus_shaped_summary_adds_up():
    """
    The shape of the corpus measurement, in miniature: a mix of correlated
    failures, ordinary certificate alerts and a fallback. The counts have to
    agree with each other, because a report shows both the totals and the
    findings and a reader will check one against the other.
    """
    records = (
        [record((2, 40), hostname='pq.example',
                proposed={'groups': ['X25519MLKEM768']})] * 24
        + [record((2, 40), hostname='plain.example')] * 5
        + [record((2, 46), hostname='cert.example',
                  proposed={'groups': ['X25519MLKEM768']})] * 11
        + [record((2, 86), hostname='fallback.example')] * 2
        + [record() for _ in range(1218)])
    summary = summarise(records)
    assert summary['sessions'] == 1260
    assert summary['sessions_with_alerts'] == 42
    assert summary['alerts'] == {'handshake_failure': 29,
                                 'certificate_unknown': 11,
                                 'inappropriate_fallback': 2}
    assert summary['post_quantum_offered_with_alert'] == 35
    assert summary['kinds'][PQ_HANDSHAKE_FAILURE] == 24
    assert summary['kinds']['inappropriate_fallback'] == 2
    assert len(summary['findings']) == 42
    assert summary['clean_shutdowns'] == 0
