"""
Session pairing: one record per handshake.

The three committed stream fixtures carry a complete handshake each, so the
end-to-end assertions here are about real traffic. Resumption, orientation and
SSH are driven from constructed streams, because the corpus does not contain a
resumed TLS 1.2 handshake in a small enough capture to commit, and contains no
SSH at all.
"""
import pathlib
import sys

import pytest

from pcapscan.reassembly import FlowKey
from pcapscan.sessions import (EXT_PRE_SHARED_KEY, Session, SessionBuilder,
                               iter_sessions, parse_ssh_stream)

pytestmark = pytest.mark.smoke

STREAMS = pathlib.Path(__file__).resolve().parent / "fixtures" / "streams"
KEY = FlowKey('10.0.0.1', 50000, '10.0.0.2', 443)


def sessions(name):
    return list(iter_sessions(STREAMS / f"{name}.pcap"))


# --------------------------------------------------------------------------
# one record per handshake, from real conversations
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["tls12_certificate",
                                  "tls12_split_certificate",
                                  "tls13_hello_retry"])
def test_one_connection_yields_one_record(name):
    """
    The live tool emits a row per parsed frame. tls13_hello_retry alone has
    four hellos in it, which is four unrelated rows there and one handshake
    here.
    """
    assert len(sessions(name)) == 1


def test_proposed_and_selected_are_both_kept():
    record = sessions("tls12_certificate")[0]['tls']
    assert record['hostname'] == 'sha384.badssl.com'
    # what was offered
    assert 'X25519MLKEM768' in record['proposed']['groups']
    assert len(record['proposed']['ciphersuites']) > 10
    # what was chosen
    assert record['selected']['ciphersuite'] == \
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    assert record['ciphersuite'] == record['selected']['ciphersuite']


def test_a_refused_post_quantum_offer_is_recorded_as_refused():
    """
    The case the whole session layer exists for. Row by row, a server that
    refuses X25519Kyber768Draft00 and one that accepts it look identical:
    both produce a ClientHello offering it. The difference is only visible
    once the two directions are joined.
    """
    record = sessions("tls13_hello_retry")[0]['tls']
    assert record['hello_retry_request'] is True
    assert record['offered_kex_group'] == 'X25519Kyber768Draft00'
    assert record['retry_kex_group'] == 'secp256r1'
    assert record['kex_group'] == 'secp256r1'      # what was actually used
    assert record['proposed']['kex_group'] == 'X25519Kyber768Draft00'


def test_tls12_takes_its_group_from_the_server_key_exchange():
    """
    TLS 1.2 does not name the group in the ServerHello -- it is in the
    ServerKeyExchange, a message the single-frame path never had in front of
    it. Reading only the ServerHello leaves kex_group null on every TLS 1.2
    connection, which is precisely where classical-only key exchange lives.
    """
    record = sessions("tls12_certificate")[0]['tls']
    assert record['selected'].get('kex_group') is None   # not in the hello
    assert record['kex_group'] == 'secp256r1'            # but recorded anyway


def test_certificates_are_carried_when_there_is_no_x509_parser(monkeypatch):
    """
    `cryptography` is optional, and so is pcapscan.certificates with it.
    Without them the chain is kept as raw DER rather than dropped, so a
    later pass -- or the person reading the output -- still has the bytes.

    Setting the module to None in sys.modules is what an absent install
    looks like to an importer: `from pcapscan.certificates import ...`
    raises ImportError.
    """
    monkeypatch.setitem(sys.modules, 'pcapscan.certificates', None)
    record = sessions("tls12_certificate")[0]['tls']
    assert 'certificates' not in record
    chain = record['certificates_der']
    assert chain and len(chain[0]) > 2000


def test_a_supplied_certificate_parser_is_used():
    seen = []

    def parser(body):
        seen.append(len(body))
        return [{'stub': True}]

    records = list(iter_sessions(STREAMS / "tls12_certificate.pcap",
                                 certificate_parser=parser))
    assert records[0]['tls']['certificates'] == [{'stub': True}]
    assert seen and seen[0] > 2000


def test_a_tls13_certificate_is_marked_unreadable_not_absent():
    """
    In TLS 1.3 the certificate is inside the encrypted flight. "No
    certificate was sent" and "the certificate cannot be read from a
    capture" are different claims, and a readiness report that conflated
    them would undercount the certificates in use.
    """
    record = sessions("tls13_hello_retry")[0]['tls']
    assert record.get('certificates_unreadable') is True
    assert 'certificates' not in record


# --------------------------------------------------------------------------
# the shape of the record
# --------------------------------------------------------------------------
def test_the_legacy_paths_still_hold_the_selected_values():
    """
    Stored documents and the API's queries use tls.ciphersuite,
    tls.kex_group and tls.hostname. A new record shape that moved them would
    orphan every query written against the existing data.
    """
    record = sessions("tls13_hello_retry")[0]
    assert set(record) >= {'ptype', 'eth', 'ts', 'tls'}
    assert record['eth']['src'] == {'ipv4': '10.176.24.102', 'port': 49492}
    assert record['eth']['dst'] == {'ipv4': '152.199.2.76', 'port': 443}
    assert isinstance(record['tls']['ciphersuite'], str)
    assert isinstance(record['ts'], float)


def test_a_session_record_validates_against_the_stored_model():
    """A session document is still a TLSDataModel, so it can be written."""
    from fapi.app.models import TLSDataModel

    record = sessions("tls12_certificate")[0]
    model = TLSDataModel(ptype=record['ptype'], eth=record['eth'],
                         tls={'ciphersuite': record['tls']['ciphersuite']})
    assert model.eth.dst.port == 443


def test_duration_is_recorded():
    record = sessions("tls12_certificate")[0]
    assert 0 < record['duration'] < 5


# --------------------------------------------------------------------------
# resumption
# --------------------------------------------------------------------------
def make_session(**server_hello):
    session = Session(KEY, 1.0)
    session.protocol = 'tls'
    session.client_hellos.append({'hostname': 'example.test'})
    session.server_hellos.append(server_hello)
    return session


def test_tls13_resumption_is_read_from_the_server_extension():
    session = make_session(tls_versions=['TLSv1.3'],
                           extensions=[43, 51, EXT_PRE_SHARED_KEY])
    state, evidence = session.resumption()
    assert state == 'resumed'
    assert 'pre_shared_key' in evidence


def test_tls13_without_pre_shared_key_is_fresh():
    session = make_session(tls_versions=['TLSv1.3'], extensions=[43, 51])
    assert session.resumption()[0] == 'fresh'


def test_tls12_abbreviated_handshake_is_inferred_as_resumed():
    """
    TLS 1.2 gives no positive signal, so this is an inference from the
    absence of a Certificate -- and the record says so, because a statistic
    built on it should be able to report which evidence it rests on.
    """
    session = make_session(tls_versions='TLSv1.2', extensions=[])
    session.encrypted_after_hello = True
    state, evidence = session.resumption()
    assert state == 'resumed'
    assert evidence.startswith('inferred')


def test_tls12_with_a_certificate_is_fresh():
    session = make_session(tls_versions='TLSv1.2', extensions=[])
    session.certificate_messages.append(b'\x00' * 100)
    assert session.resumption() == ('fresh', 'certificate sent')


def test_an_incomplete_handshake_is_unknown_not_guessed():
    session = make_session(tls_versions='TLSv1.2', extensions=[])
    assert session.resumption()[0] == 'unknown'
    assert Session(KEY, 1.0).resumption()[0] == 'unknown'


def test_resumed_sessions_have_no_key_exchange_to_report():
    """
    Half the corpus resumes. A resumed session performs no key exchange, so
    counting it as one counts an event that did not happen -- which is why
    this has to be labelled rather than left to the reader.
    """
    session = make_session(tls_versions=['TLSv1.3'],
                           extensions=[EXT_PRE_SHARED_KEY])
    assert session.key_exchange_group() is None
    assert session.resumption()[0] == 'resumed'


# --------------------------------------------------------------------------
# orientation
# --------------------------------------------------------------------------
def test_the_client_side_is_identified_without_a_syn():
    """
    A capture that began mid-connection has no SYN to point at the client.
    Getting this backwards puts the ClientHello in the server slot, and
    every 'selected' value in the record becomes a proposal.
    """
    builder = SessionBuilder()
    server_first = FlowKey('10.0.0.2', 443, '10.0.0.1', 50000)
    key, from_client = builder._orient(server_first)
    assert key == server_first.reverse()
    assert from_client is False
    # and the client's own direction then maps onto the same session
    builder.sessions[key] = Session(key, 0.0)
    assert builder._orient(key) == (key, True)


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------
def ssh_stream(banner=b'SSH-2.0-OpenSSH_9.6', lists=None):
    lists = lists or [b'curve25519-sha256,sntrup761x25519-sha512@openssh.com',
                      b'ssh-ed25519,rsa-sha2-512',
                      b'chacha20-poly1305@openssh.com', b'aes256-gcm@openssh.com',
                      b'hmac-sha2-256', b'hmac-sha2-512']
    body = bytes([20]) + b'\x00' * 16
    for item in lists:
        body += len(item).to_bytes(4, 'big') + item
    padding = b'\x00' * 8
    payload = bytes([len(padding)]) + body + padding
    packet = len(payload).to_bytes(4, 'big') + payload
    return banner + b'\r\n' + packet


def test_ssh_kexinit_lists_are_read_from_the_stream():
    parsed = parse_ssh_stream(ssh_stream())
    assert parsed['banner'] == 'SSH-2.0-OpenSSH_9.6'
    assert 'sntrup761x25519-sha512@openssh.com' in parsed['KEXalgs']
    assert parsed['ServerHostKeyAlgos'] == ['ssh-ed25519', 'rsa-sha2-512']
    assert parsed['MACalgosServer2Client'] == ['hmac-sha2-512']


def test_ssh_with_only_a_banner_yields_only_a_banner():
    parsed = parse_ssh_stream(b'SSH-2.0-OpenSSH_9.6\r\n')
    assert parsed == {'banner': 'SSH-2.0-OpenSSH_9.6'}


def test_ssh_without_a_banner_terminator_yields_nothing():
    assert parse_ssh_stream(b'SSH-2.0-' + b'x' * 400) == {}


def test_a_truncated_ssh_packet_yields_the_banner_and_no_lists():
    """
    Half a KEXINIT is not a shorter KEXINIT. The banner arrived whole and is
    reported; the algorithm lists did not, and reporting the first few would
    understate what the peer supports.
    """
    blob = ssh_stream()
    parsed = parse_ssh_stream(blob[:len(blob) // 2])
    assert parsed == {'banner': 'SSH-2.0-OpenSSH_9.6'}


# --------------------------------------------------------------------------
# accounting
# --------------------------------------------------------------------------
def test_the_builder_counts_what_it_dropped():
    builder = SessionBuilder()
    list(iter_sessions(STREAMS / "tls12_certificate.pcap", builder=builder))
    assert builder.stats['frames'] > 0
    assert builder.stats['sessions_emitted'] == 1
    assert builder.stats['capture_packets'] == builder.stats['frames']
