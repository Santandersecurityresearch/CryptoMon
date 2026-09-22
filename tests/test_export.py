"""
Writing records out.

The assertions that matter are about compatibility and about not losing
things: the NDJSON records have to stay loadable into the collection the live
tool already writes, bytes have to survive a format with no byte type, and an
empty capture has to produce a valid empty file rather than a broken one.
"""
import io
import json

import pytest

from cryptomon.analysis import analyse
from pcapscan.export import (CSV_COLUMNS, flatten, write_csv, write_json,
                             write_ndjson)

pytestmark = pytest.mark.smoke


def session(**tls):
    return {
        'ptype': 'session',
        'ts': 1733875200.5,
        'duration': 0.25,
        'eth': {'src': {'ipv4': '10.0.0.1', 'port': 51000},
                'dst': {'ipv4': '93.184.216.34', 'port': 443}},
        'tls': dict({'hostname': 'example.test',
                     'ciphersuite': 'TLS_AES_256_GCM_SHA384',
                     'kex_group': 'X25519MLKEM768',
                     'tls_versions': ['TLSv1.3'],
                     'resumption': 'fresh'}, **tls),
    }


# --------------------------------------------------------------------------
# NDJSON -- the format the rest of the system already speaks
# --------------------------------------------------------------------------
def test_ndjson_is_one_record_per_line():
    buffer = io.StringIO()
    assert write_ndjson([session(), session()], buffer) == 2
    lines = buffer.getvalue().splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)['ptype'] == 'session' for line in lines)


def test_ndjson_keeps_the_document_shape_the_live_tool_writes():
    """
    So that the offline path feeds the same collection, and `mongoimport`
    needs no translation step in between.
    """
    buffer = io.StringIO()
    write_ndjson([session()], buffer)
    record = json.loads(buffer.getvalue())
    assert record['eth']['src']['ipv4'] == '10.0.0.1'
    assert record['eth']['dst']['port'] == 443
    assert record['tls']['ciphersuite'] == 'TLS_AES_256_GCM_SHA384'
    assert isinstance(record['ts'], float)


def test_writing_streams_rather_than_buffering():
    """
    A capture with a million handshakes must not have to be held in memory
    to be written. The writer pulls from the iterator, so consuming it
    lazily has to work.
    """
    produced = []

    def records():
        for i in range(3):
            produced.append(i)
            yield session()

    buffer = io.StringIO()
    iterator = records()
    write_ndjson(iterator, buffer)
    assert produced == [0, 1, 2]
    assert buffer.getvalue().count('\n') == 3


def test_raw_der_survives_a_format_with_no_byte_type():
    """
    Without a parser installed, sessions carry the chain as raw DER. Dropping
    it on export would be worse than encoding it, and crashing would be worse
    than both.
    """
    buffer = io.StringIO()
    write_ndjson([session(certificates_der=[b'\x30\x82\x01\x00'])], buffer)
    encoded = json.loads(buffer.getvalue())['tls']['certificates_der'][0]
    import base64
    assert base64.b64decode(encoded['__base64__']) == b'\x30\x82\x01\x00'


def test_an_unencodable_value_still_raises():
    """base64 is for bytes, not a licence to swallow anything."""
    with pytest.raises(TypeError):
        write_ndjson([{'bad': object()}], io.StringIO())


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def test_json_carries_metadata_records_and_summary():
    records = [session(), session(kex_group='secp256r1')]
    buffer = io.StringIO()
    assert write_json(records, buffer, analyse(records), source='c.pcap') == 2
    document = json.loads(buffer.getvalue())
    assert set(document) == {'meta', 'sessions', 'summary'}
    assert document['meta']['source'] == 'c.pcap'
    assert len(document['sessions']) == 2
    assert document['summary']['readiness']['key_exchanges_performed'] == 2
    assert document['summary']['readiness']['hybrid'] == 1


def test_json_without_a_summary_is_still_valid():
    buffer = io.StringIO()
    write_json([session()], buffer)
    assert 'summary' not in json.loads(buffer.getvalue())


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------
def test_csv_has_a_header_and_one_row_per_session():
    buffer = io.StringIO()
    assert write_csv([session(), session()], buffer) == 2
    lines = buffer.getvalue().strip().splitlines()
    assert lines[0].split(',') == CSV_COLUMNS
    assert len(lines) == 3


def test_csv_carries_the_verdict_next_to_the_group():
    """
    The column the report is about. Sorting by it is the whole reason this
    format exists.
    """
    row = flatten(session())
    assert row['kex_group'] == 'X25519MLKEM768'
    assert row['kex_verdict'] == 'hybrid'


def test_the_verdict_is_computed_not_stored():
    """
    A better classification table should improve the report without
    re-reading the captures, so the verdict is derived at export time rather
    than frozen into the record.
    """
    record = session()
    assert 'kex_verdict' not in record['tls']
    assert flatten(record)['kex_verdict'] == 'hybrid'


def test_csv_keeps_a_readable_time_beside_the_epoch_one():
    """A format that cannot round-trip is a format that loses data."""
    row = flatten(session())
    assert row['ts'] == 1733875200.5
    assert row['time'].startswith('2024-12-11T')


def test_lists_are_joined_not_dropped():
    row = flatten(session(proposed={'groups': ['X25519MLKEM768', 'x25519'],
                                    'ciphersuites': ['a', 'b', 'c']}))
    assert row['proposed_groups'] == 'X25519MLKEM768;x25519'
    assert row['proposed_ciphersuites'] == 3


def test_a_refused_offer_has_its_own_columns():
    row = flatten(session(hello_retry_request=True,
                          offered_kex_group='X25519Kyber768Draft00',
                          retry_kex_group='secp256r1',
                          kex_group='secp256r1'))
    assert row['offered_kex_group'] == 'X25519Kyber768Draft00'
    assert row['retry_kex_group'] == 'secp256r1'
    assert row['kex_verdict'] == 'classical'


def test_the_leaf_certificate_fills_the_certificate_columns():
    row = flatten(session(certificates=[
        {'subject': 'CN=leaf.test', 'issuer': 'CN=CA',
         'public_key_algorithm': 'RSA', 'public_key_size': 2048,
         'not_after': '2025-01-01T00:00:00+00:00'},
        {'subject': 'CN=CA'}]))
    assert row['certificate_subject'] == 'CN=leaf.test'
    assert row['certificate_key'] == 'RSA-2048'
    assert row['certificate_count'] == 2


def test_an_ssh_record_fills_the_same_columns():
    """
    One table, both protocols. A separate SSH CSV would mean nobody looks at
    it.
    """
    row = flatten({
        'ptype': 'session', 'ts': 1.0, 'duration': 0.0,
        'eth': {'src': {'ipv4': '10.0.0.1', 'port': 5000},
                'dst': {'ipv4': '10.0.0.2', 'port': 22}},
        'ssh': {'KEXalgs': ['sntrup761x25519-sha512@openssh.com',
                            'curve25519-sha256'],
                'EncryptionAlgosClient2Server': ['chacha20-poly1305@openssh.com'],
                'banners': {'server': 'SSH-2.0-OpenSSH_9.6'}}})
    assert row['protocol'] == 'ssh'
    assert row['hostname'] == 'SSH-2.0-OpenSSH_9.6'
    assert 'sntrup761x25519' in row['kex_group']
    assert set(row['kex_verdict'].split(';')) == {'hybrid', 'classical'}


# --------------------------------------------------------------------------
# nothing in, something valid out
# --------------------------------------------------------------------------
def test_an_empty_capture_produces_valid_empty_output():
    buffer = io.StringIO()
    assert write_ndjson([], buffer) == 0
    assert buffer.getvalue() == ''

    buffer = io.StringIO()
    write_json([], buffer, analyse([]))
    assert json.loads(buffer.getvalue())['sessions'] == []

    buffer = io.StringIO()
    write_csv([], buffer)
    assert buffer.getvalue().strip().split(',') == CSV_COLUMNS


def test_a_record_with_almost_nothing_in_it_still_flattens():
    row = flatten({'ptype': 'session'})
    assert set(row) <= set(CSV_COLUMNS)
    assert row['hostname'] is None
    assert row['kex_verdict'] == 'none'
