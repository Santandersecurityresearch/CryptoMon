"""
Writing session records out: NDJSON, JSON and CSV.

The first thing in this pipeline anybody can use without writing Python, so
the formats are chosen for what they have to plug into rather than for
elegance.

**NDJSON is the primary format**, and its records keep the document shape the
live tool already writes -- `ptype`, `eth.src.ipv4`, `tls.ciphersuite` and
the rest in the same places. That is not nostalgia: it means the offline path
feeds the same collection as the live path, and

    python -m pcapscan capture.pcap -f ndjson | mongoimport --collection cryptomon

works without a translation step. One record per line also means the output
streams, so a capture with a million handshakes does not have to be held in
memory to be written.

**JSON** adds the analysis summary alongside the records, for the case where
the file is the deliverable. It streams too -- the array is written as it is
produced and the summary appended at the end -- so the only difference in
cost is the summary itself.

**CSV** is flat, lossy and deliberately so. It exists because the people who
most need to read "which of our connections would survive a quantum
computer" open things in a spreadsheet, and a nested document is not that.
Columns were chosen so that sorting by any one of them answers a question
somebody actually asks.

Two encoding decisions worth stating. Raw DER is base64'd rather than
dropped, because JSON has no byte type and losing the certificate would be
worse than encoding it. Timestamps stay as the float epoch value the existing
documents use, and CSV gains a readable ISO column beside it rather than
replacing it -- a format that cannot round-trip is a format that quietly
loses data.
"""
import base64
import csv
import datetime
import json

from cryptomon.analysis import classify_key_exchange

# One row per session. Ordered so that the identifying columns come first and
# the verdict is visible without scrolling, because that is the column the
# report is about.
CSV_COLUMNS = [
    'ts', 'time', 'duration',
    'src', 'src_port', 'dst', 'dst_port',
    'protocol', 'hostname',
    'tls_version', 'ciphersuite', 'kex_group', 'kex_verdict',
    'resumption', 'hello_retry_request',
    'offered_kex_group', 'retry_kex_group',
    'certificate_subject', 'certificate_issuer', 'certificate_key',
    'certificate_not_after', 'certificate_count',
    'proposed_groups', 'proposed_ciphersuites', 'alerts',
]

LIST_SEPARATOR = ';'


def _encode(value):
    """JSON default: bytes become base64, everything else raises as usual."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {'__base64__': base64.b64encode(bytes(value)).decode('ascii')}
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    raise TypeError(
        '{0} is not JSON serialisable'.format(type(value).__name__))


def write_ndjson(records, stream):
    """One record per line. Returns how many were written."""
    written = 0
    for record in records:
        stream.write(json.dumps(record, default=_encode, sort_keys=True))
        stream.write('\n')
        written += 1
    return written


def write_json(records, stream, summary=None, source=None):
    """
    One document: metadata, the records, and the analysis summary.

    Written incrementally rather than built up and dumped, so that this costs
    the same as NDJSON plus the summary. `summary` is a
    cryptomon.analysis.Summary, or None to leave it out.
    """
    stream.write('{\n')
    meta = {'tool': 'pcapscan', 'source': str(source) if source else None,
            'generated': datetime.datetime.now(
                datetime.timezone.utc).isoformat()}
    stream.write('  "meta": ')
    stream.write(json.dumps(meta, default=_encode, sort_keys=True))
    stream.write(',\n  "sessions": [\n')
    written = 0
    for record in records:
        if written:
            stream.write(',\n')
        stream.write('    ')
        stream.write(json.dumps(record, default=_encode, sort_keys=True))
        written += 1
    stream.write('\n  ]')
    if summary is not None:
        stream.write(',\n  "summary": ')
        stream.write(json.dumps(summary.as_dict(), default=_encode,
                                sort_keys=True))
    stream.write('\n}\n')
    return written


def _join(values):
    if not values:
        return ''
    return LIST_SEPARATOR.join(str(v) for v in values)


def flatten(record):
    """One session record as a flat dict of CSV_COLUMNS."""
    eth = record.get('eth') or {}
    src, dst = eth.get('src') or {}, eth.get('dst') or {}
    tls = record.get('tls') or {}
    ssh = record.get('ssh') or {}
    proposed = tls.get('proposed') or {}
    certificates = tls.get('certificates') or []
    leaf = certificates[0] if certificates else {}

    timestamp = record.get('ts')
    versions = tls.get('tls_versions')
    row = {
        'ts': timestamp,
        'time': (datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc).isoformat()
            if isinstance(timestamp, (int, float)) else None),
        'duration': record.get('duration'),
        'src': src.get('ipv4') or src.get('ipv6'),
        'src_port': src.get('port'),
        'dst': dst.get('ipv4') or dst.get('ipv6'),
        'dst_port': dst.get('port'),
        'protocol': 'ssh' if ssh else 'tls',
        'hostname': tls.get('hostname'),
        'tls_version': _join(versions) if isinstance(versions, list)
                       else versions,
        'ciphersuite': tls.get('ciphersuite'),
        'kex_group': tls.get('kex_group'),
        # The verdict is computed here rather than stored on the record,
        # because it is a judgement about the data and not part of it --
        # re-running the analysis with a better table should change the
        # report without rewriting the captures.
        'kex_verdict': classify_key_exchange(tls.get('kex_group')),
        'resumption': tls.get('resumption'),
        'hello_retry_request': tls.get('hello_retry_request'),
        'offered_kex_group': tls.get('offered_kex_group'),
        'retry_kex_group': tls.get('retry_kex_group'),
        'certificate_subject': leaf.get('subject'),
        'certificate_issuer': leaf.get('issuer'),
        'certificate_key': (
            '{0}-{1}'.format(leaf.get('public_key_algorithm'),
                             leaf.get('public_key_size'))
            if leaf.get('public_key_algorithm') else None),
        'certificate_not_after': leaf.get('not_after'),
        'certificate_count': len(certificates) or (
            len(tls.get('certificates_der') or []) or None),
        'proposed_groups': _join(proposed.get('groups')),
        'proposed_ciphersuites': len(proposed.get('ciphersuites') or []) or None,
        'alerts': _join('{0}/{1}'.format(a.get('level'), a.get('description'))
                        for a in tls.get('alerts') or []),
    }
    if ssh:
        row['ciphersuite'] = _join(ssh.get('EncryptionAlgosClient2Server'))
        row['kex_group'] = _join(ssh.get('KEXalgs'))
        row['kex_verdict'] = _join(
            sorted({classify_key_exchange(a)
                    for a in ssh.get('KEXalgs') or []}))
        row['hostname'] = (ssh.get('banners') or {}).get('server')
    return row


def write_csv(records, stream, columns=None):
    """Flat rows, one per session. Returns how many were written."""
    columns = columns or CSV_COLUMNS
    writer = csv.DictWriter(stream, fieldnames=columns, extrasaction='ignore')
    writer.writeheader()
    written = 0
    for record in records:
        writer.writerow(flatten(record))
        written += 1
    return written


WRITERS = {
    'ndjson': write_ndjson,
    'json': write_json,
    'csv': write_csv,
}
