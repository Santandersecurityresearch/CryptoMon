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

from cryptomon.alerts import describe as describe_alert
from cryptomon.analysis import classify_key_exchange

# One row per session. Ordered so that the identifying columns come first and
# the verdict is visible without scrolling, because that is the column the
# report is about.
CSV_COLUMNS = [
    'ts', 'time', 'duration',
    'src', 'src_port', 'dst', 'dst_port',
    'protocol', 'hostname', 'ech', 'ja4', 'ja4s',
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


def _readable_time(timestamp):
    """
    An ISO rendering of an epoch timestamp, or None when there is not one.

    A capture file's timestamp field is four bytes of whatever the file says,
    so a corrupt one lands outside the year range datetime can represent and
    `fromtimestamp` raises -- taking down the export after every packet in
    the capture had already parsed successfully. Found by fuzzing whole
    capture files.

    The raw value stays in the `ts` column beside this one, so degrading to
    None loses nothing: `ts` is the data and this is a convenience rendering
    of it.
    """
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
        return None
    try:
        return datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _alert_label(alert):
    """
    One alert as a readable cell: `fatal handshake_failure (server)`.

    Named rather than numbered. "2/40" in a spreadsheet is a lookup somebody
    has to do by hand, and the direction is the part that carries the
    finding -- it separates a server refusing our key share from us refusing
    its parameters, which is precisely the ambiguity that makes a
    post-quantum correlation a lead rather than a conclusion.
    """
    described = describe_alert(alert)
    label = '{0} {1}'.format(described['level_name'], described['name'])
    sender = alert.get('from_client')
    if sender is None:
        return label
    return '{0} ({1})'.format(label, 'client' if sender else 'server')


def _join(values):
    if not values:
        return ''
    return LIST_SEPARATOR.join(str(v) for v in values)


def _protocol_name(record, ssh, tls):
    """
    What this row's flow actually carried.

    Not 'tls' by default. The UDP handlers emit records with neither a `tls`
    nor an `ssh` block -- an unprotected DNS, HSRP or DHCP flow has no
    ciphersuite to put in one -- and labelling those 'tls' puts a row in the
    spreadsheet claiming a TLS session that never happened. On the capture
    corpus that is 1,058 of them.
    """
    if ssh:
        return 'ssh'
    if record.get('quic'):
        # A QUIC record carries a full `tls` block -- that is the point, it
        # *is* TLS 1.3 -- so the test below would answer 'tls' and lose the
        # transport. The handshake is the same; what carried it is not.
        return 'quic'
    if tls:
        return 'tls'
    cleartext = record.get('cleartext')
    if isinstance(cleartext, dict) and cleartext.get('protocol'):
        return str(cleartext['protocol'])
    return None


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
        'time': _readable_time(timestamp),
        'duration': record.get('duration'),
        'src': src.get('ipv4') or src.get('ipv6'),
        'src_port': src.get('port'),
        'dst': dst.get('ipv4') or dst.get('ipv6'),
        'dst_port': dst.get('port'),
        'protocol': _protocol_name(record, ssh, tls),
        'hostname': tls.get('hostname'),
        # Next to the hostname, because it is the qualifier on it: once a
        # server accepts ECH the name to its left is the public outer one.
        'ech': tls.get('ech'),
        'ja4': tls.get('ja4'),
        'ja4s': tls.get('ja4s'),
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
        # Named, not numbered. "2/40" in a spreadsheet column is a lookup
        # somebody has to do by hand; "fatal handshake_failure (client)" is
        # the finding. The direction matters most of all -- it separates a
        # server refusing our key share from us refusing its parameters.
        'alerts': _join(_alert_label(a) for a in tls.get('alerts') or []),
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
