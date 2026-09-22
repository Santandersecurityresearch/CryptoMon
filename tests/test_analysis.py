"""
The analysis layer: what the records mean.

Counting is arithmetic and needs little testing. The classification is the
part worth pinning down, because every number the tool publishes rests on it
and because the failure mode is a confident wrong answer rather than an
error.
"""
import pathlib

import pytest

from cryptomon.analysis import (CLASSICAL, HYBRID, NOT_APPLICABLE,
                                POST_QUANTUM, SYMMETRIC, UNKNOWN, Summary,
                                analyse, classify_algorithm,
                                classify_certificate, classify_ciphersuite,
                                classify_key_exchange, symmetric_label,
                                symmetric_strength)
from pcapscan.sessions import iter_sessions

pytestmark = pytest.mark.smoke

STREAMS = pathlib.Path(__file__).resolve().parent / "fixtures" / "streams"


# --------------------------------------------------------------------------
# the judgement
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,verdict", [
    # pure post-quantum
    ('ML-KEM-768', POST_QUANTUM),
    ('mlkem1024', POST_QUANTUM),
    ('ML-DSA-65', POST_QUANTUM),
    ('SPHINCS+-SHA2-128s', POST_QUANTUM),
    ('Kyber768', POST_QUANTUM),
    # hybrid: a post-quantum primitive combined with a classical one
    ('X25519MLKEM768', HYBRID),
    ('X25519Kyber768Draft00', HYBRID),
    ('SecP256r1MLKEM768', HYBRID),
    ('SecP384r1MLKEM1024', HYBRID),
    ('sntrup761x25519-sha512@openssh.com', HYBRID),
    ('mlkem768x25519-sha256', HYBRID),
    # classical
    ('x25519', CLASSICAL),
    ('secp256r1', CLASSICAL),
    ('ffdhe3072', CLASSICAL),
    ('brainpoolP384r1', CLASSICAL),
    ('rsa_pss_rsae_sha256', CLASSICAL),
    ('ecdsa_secp521r1_sha512', CLASSICAL),
    ('ed25519', CLASSICAL),
    ('sha256WithRSAEncryption', CLASSICAL),
    ('curve25519-sha256', CLASSICAL),
    ('ecdh-sha2-nistp384', CLASSICAL),
    ('diffie-hellman-group14-sha256', CLASSICAL),
    ('ssh-dss', CLASSICAL),
    # nothing is guessed
    ('Unknown (0xfefe)', UNKNOWN),
    ('GREASE', UNKNOWN),
    (None, UNKNOWN),
    ('', UNKNOWN),
])
def test_classification(name, verdict):
    assert classify_algorithm(name) == verdict


def test_hybrid_is_neither_of_the_other_two():
    """
    Every post-quantum key exchange in the corpus is hybrid. Calling those
    post-quantum overstates deployment; calling them classical erases the
    work. The distinction is the finding.
    """
    assert classify_algorithm('X25519MLKEM768') == HYBRID
    assert classify_algorithm('X25519MLKEM768') != POST_QUANTUM
    assert classify_algorithm('X25519MLKEM768') != CLASSICAL


def test_an_ssh_hybrid_is_not_mistaken_for_pure_post_quantum():
    """
    sntrup761x25519 is sntrup761 *and* x25519. Missing the SSH spelling of
    the classical half would report the most interesting SSH traffic in
    existence as fully post-quantum.
    """
    assert classify_algorithm('sntrup761x25519-sha512@openssh.com') == HYBRID
    assert classify_algorithm('sntrup761') == POST_QUANTUM


def test_no_key_exchange_is_its_own_answer():
    """A resumed session performed none; that is not 'unknown'."""
    assert classify_key_exchange(None) == NOT_APPLICABLE
    assert classify_key_exchange('x25519') == CLASSICAL


# --------------------------------------------------------------------------
# symmetric ciphers are a different question
# --------------------------------------------------------------------------
@pytest.mark.parametrize("suite,bits,after", [
    ('TLS_AES_256_GCM_SHA384', 256, 128),
    ('TLS_AES_128_GCM_SHA256', 128, 64),
    ('TLS_CHACHA20_POLY1305_SHA256', 256, 128),
    ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 128, 64),
])
def test_grover_halves_rather_than_breaks(suite, bits, after):
    """
    Grover is a square-root speed-up on exhaustive search, not a break.
    Listing AES-128 as "quantum-vulnerable" alongside RSA-2048 would be
    wrong by many orders of magnitude.
    """
    _cipher, before, remaining = symmetric_strength(suite)
    assert (before, remaining) == (bits, after)


def test_a_broken_cipher_is_not_described_as_grover_weakened():
    """RC4 is not waiting for a quantum computer."""
    label = symmetric_label('TLS_RSA_WITH_RC4_128_SHA')
    assert 'broken' in label
    assert 'Grover' not in label


def test_a_suite_naming_no_cipher_gets_no_strength():
    assert symmetric_strength('TLS_UNKNOWN_SUITE') == (None, None, None)
    assert symmetric_label('TLS_UNKNOWN_SUITE') is None


def test_a_tls13_suite_is_symmetric_not_unknown():
    """
    TLS 1.3 moved the key exchange out of the ciphersuite, so the name says
    nothing about it. "unknown" would read as "unrecognised", which is a
    different claim.
    """
    assert classify_ciphersuite('TLS_AES_256_GCM_SHA384') == SYMMETRIC
    assert classify_ciphersuite('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256') \
        == CLASSICAL


# --------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------
def test_a_certificate_verdict_carries_its_size():
    """
    Every RSA key is broken by Shor; which ones get replaced first is not
    decided at random, and "RSA" alone cannot inform that.
    """
    verdict, label = classify_certificate(
        {'public_key_algorithm': 'RSA', 'public_key_size': 2048})
    assert (verdict, label) == (CLASSICAL, 'RSA-2048')


def test_an_ec_certificate_is_judged_on_its_curve():
    verdict, label = classify_certificate(
        {'public_key_algorithm': 'EC', 'public_key_size': 256,
         'public_key_curve': 'secp256r1'})
    assert (verdict, label) == (CLASSICAL, 'EC-256')


def test_an_unparsed_certificate_is_unknown_not_classical():
    verdict, _label = classify_certificate({'parse_error': 'ValueError'})
    assert verdict == UNKNOWN


# --------------------------------------------------------------------------
# summarising
# --------------------------------------------------------------------------
def record(**tls):
    return {'ptype': 'session', 'ts': 1.0,
            'eth': {'src': {'ipv4': '10.0.0.1', 'port': 5},
                    'dst': {'ipv4': '10.0.0.2', 'port': 443}},
            'tls': tls}


def test_resumed_sessions_do_not_count_as_key_exchanges():
    """
    Half the corpus resumes. Dividing quantum-safe key exchanges by *all*
    sessions rather than by the ones that performed a key exchange
    understates readiness by the resumption rate -- roughly a factor of two.
    """
    summary = analyse([
        record(kex_group='X25519MLKEM768', resumption='fresh'),
        record(kex_group=None, resumption='resumed'),
        record(kex_group=None, resumption='resumed'),
    ])
    readiness = summary.readiness()
    assert readiness['sessions'] == 3
    assert readiness['key_exchanges_performed'] == 1
    assert readiness['no_key_exchange'] == 2
    assert readiness['quantum_safe_fraction'] == 1.0


def test_a_refused_post_quantum_offer_is_counted_as_a_downgrade():
    summary = analyse([record(hostname='pq.test',
                              offered_kex_group='X25519Kyber768Draft00',
                              retry_kex_group='secp256r1',
                              kex_group='secp256r1')])
    assert summary.readiness()['post_quantum_refused'] == 1
    assert summary.downgrades[0]['forced'] == 'secp256r1'


def test_a_classical_offer_that_is_retried_is_not_a_downgrade():
    """
    Most HelloRetryRequests have nothing to do with post-quantum -- a server
    preferring secp384r1 to x25519 is just a preference.
    """
    summary = analyse([record(offered_kex_group='x25519',
                              retry_kex_group='secp384r1',
                              kex_group='secp384r1')])
    assert summary.readiness()['post_quantum_refused'] == 0


def test_deprecated_versions_are_counted_separately():
    summary = analyse([record(tls_versions='TLSv1.0'),
                       record(tls_versions='TLSv1.3')])
    assert summary.readiness()['deprecated_tls_versions'] == 1


def test_the_fraction_is_none_rather_than_zero_when_nothing_happened():
    """Zero out of zero is not zero per cent."""
    assert analyse([]).readiness()['quantum_safe_fraction'] is None


def test_the_inventory_records_where_each_algorithm_was_seen():
    """
    CycloneDX evidence.occurrences wants provenance, and "observed in this
    capture, talking to this host" is the strongest claim a network observer
    can make.
    """
    summary = analyse([record(hostname='seen.test', kex_group='x25519')])
    entry = next(a for a in summary.inventory if a['name'] == 'x25519')
    assert entry['kind'] == 'key-exchange'
    assert entry['verdict'] == CLASSICAL
    assert entry['occurrences'][0]['hostname'] == 'seen.test'
    assert entry['occurrences'][0]['address'] == '10.0.0.2'


def test_occurrences_are_bounded():
    from cryptomon.analysis import MAX_OCCURRENCES
    summary = analyse([record(hostname='x', kex_group='x25519')
                       for _ in range(MAX_OCCURRENCES + 50)])
    entry = summary.inventory[0]
    assert entry['count'] == MAX_OCCURRENCES + 50
    assert len(entry['occurrences']) == MAX_OCCURRENCES


def test_ssh_records_are_summarised_too():
    summary = analyse([{'ptype': 'session', 'ts': 1.0, 'eth': {},
                        'ssh': {'KEXalgs': ['sntrup761x25519-sha512@openssh.com',
                                            'curve25519-sha256']}}])
    assert summary.protocols['ssh'] == 1
    verdicts = {a['name']: a['verdict'] for a in summary.inventory}
    assert verdicts['sntrup761x25519-sha512@openssh.com'] == HYBRID
    assert verdicts['curve25519-sha256'] == CLASSICAL


# --------------------------------------------------------------------------
# end to end, on the fixtures
# --------------------------------------------------------------------------
def test_the_fixtures_summarise_as_expected():
    records = []
    for path in sorted(STREAMS.glob("*.pcap")):
        records.extend(iter_sessions(path))
    summary = analyse(records)
    readiness = summary.readiness()
    assert readiness['sessions'] == 3
    # Two TLS 1.2 handshakes on secp256r1 and one forced there by an HRR.
    assert readiness['classical'] == 3
    assert readiness['post_quantum_refused'] == 1
    # Four certificates, all RSA, none of which survives Shor.
    assert readiness['certificates_quantum_vulnerable'] == 4
    assert readiness['certificates_post_quantum'] == 0


def test_the_summary_is_plain_data():
    """PR-25 serialises this into a CBOM and PR-36 into JSON for a page."""
    import json
    summary = analyse(iter_sessions(STREAMS / "tls12_certificate.pcap"))
    assert isinstance(summary, Summary)
    assert json.loads(json.dumps(summary.as_dict()))['readiness']['sessions'] == 1
