"""
The command line: `python -m pcapscan capture.pcap`.

This ships before any UI because it is the thing that gets automated. A web
form is used by whoever is sitting in front of it; a command that reads a
capture and writes NDJSON on stdout is used by a cron job, a CI step and a
pipeline someone writes six months from now without asking.

    python -m pcapscan capture.pcap                     readable report
    python -m pcapscan capture.pcap -f csv -o out.csv   for a spreadsheet
    python -m pcapscan *.pcapng -f ndjson | mongoimport --collection cryptomon
    zcat big.pcap.gz | python -m pcapscan - -f json     from a pipe

Several captures can be given at once and are analysed as one body of
traffic, because "what does our estate negotiate" is rarely a question about
a single file.

Formats are *discovered* rather than listed, so that an output format whose
dependencies are not installed is absent from `--help` rather than present
and broken.
"""
import argparse
import contextlib
import sys

from cryptomon.analysis import CLASSICAL, HYBRID, POST_QUANTUM, Summary
from cryptomon.parsers.framing import decode_frame
from pcapscan.export import WRITERS, write_csv, write_json, write_ndjson
from pcapscan.reader import CaptureError, Reader
from pcapscan.reassembly import Reassembler
from pcapscan.sessions import SessionBuilder

DEFAULT_FORMAT = 'summary'

EXIT_OK = 0
EXIT_ERROR = 1


def available_formats():
    """
    Output formats this installation can actually produce.

    Discovered rather than hard-coded: pcapscan.cbom needs its own
    dependencies, and an option that appears in --help and then fails is
    worse than one that is not offered.
    """
    formats = dict(WRITERS)
    formats['summary'] = None            # handled separately; not a writer
    try:
        from pcapscan.cbom import write_cbom
    except ImportError:
        pass
    else:
        formats['cbom'] = write_cbom
    return formats


def build_parser():
    parser = argparse.ArgumentParser(
        prog='pcapscan',
        description='Read TLS and SSH handshakes out of a packet capture and '
                    'report what cryptography they negotiated.',
        epilog='Reassembles TCP, so it sees the handshakes a single-packet '
               'reader cannot: whole ClientHellos, whole certificate chains, '
               'and the second exchange of a HelloRetryRequest.')
    parser.add_argument('captures', nargs='+', metavar='CAPTURE',
                        help="pcap or pcapng file, gzipped or not; '-' reads "
                             "standard input")
    parser.add_argument('-f', '--format', default=DEFAULT_FORMAT,
                        choices=sorted(available_formats()),
                        help='output format (default: %(default)s)')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='write here instead of standard output')
    parser.add_argument('--no-certificates', action='store_true',
                        help='skip X.509 parsing and keep the raw chain')
    parser.add_argument('--max-stream-bytes', type=int, default=None,
                        metavar='N',
                        help='per-direction reassembly buffer (default: 16384; '
                             'raise it only for a capture with unusually large '
                             'certificate chains)')
    parser.add_argument('--max-flows', type=int, default=None, metavar='N',
                        help='connections tracked at once (default: 2048)')
    parser.add_argument('--stats', action='store_true',
                        help='write reader and reassembler counters to stderr')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='suppress per-file progress on stderr')
    return parser


@contextlib.contextmanager
def _output(path):
    if not path or path == '-':
        yield sys.stdout
        return
    with open(path, 'w', newline='', encoding='utf-8') as handle:
        yield handle


def _source(name):
    if name == '-':
        return sys.stdin.buffer
    return name


def _records(captures, builder, quiet):
    """
    Every session across every capture, as one stream.

    Several files are fed to one builder and finished once at the end, rather
    than finished per file: `tcpdump -C` rotates a capture mid-connection, and
    finishing after each part would report the two halves of one handshake as
    two incomplete sessions.

    A generator, so the writers stay streaming -- though note that sessions
    only become complete when their connection does, so nothing is emitted
    until the last file has been read.
    """
    for capture in captures:
        try:
            with Reader(_source(capture)) as reader:
                for packet in reader:
                    frame = decode_frame(packet.data, packet.linktype)
                    if frame is None:
                        builder.stats['frames_undecodable'] += 1
                        continue
                    builder.stats['frames'] += 1
                    builder.push(packet.timestamp, packet.data, frame)
                for name, value in reader.stats.items():
                    # `Counter.update` *adds*, so passing an
                    # already-accumulated total here would compound it on
                    # every file. Increment each counter once instead.
                    builder.stats['capture_' + name] += value
        except (CaptureError, OSError) as exc:
            # One unreadable file among several must not lose the others, and
            # must not be passed over in silence either.
            print('pcapscan: {0}: {1}'.format(capture, exc), file=sys.stderr)
            builder.stats['captures_unreadable'] += 1
            continue
        if not quiet:
            print('pcapscan: read {0}'.format(capture), file=sys.stderr)
    yield from builder.finish()


def _collect(records, summary):
    """Pass records through, summarising as they go. One traversal."""
    for record in records:
        summary.add(record)
        yield record


def format_summary(summary):
    """The readable report: what was negotiated, and what that means."""
    readiness = summary.readiness()
    lines = ['', 'Sessions                {0}'.format(readiness['sessions'])]
    for protocol, count in sorted(summary.protocols.items()):
        lines.append('  {0:<21} {1}'.format(protocol, count))

    performed = readiness['key_exchanges_performed']
    lines += ['', 'Key exchange']
    lines.append('  performed             {0}'.format(performed))
    lines.append('  none (resumed)        {0}'.format(
        readiness['no_key_exchange']))
    for verdict, key in ((POST_QUANTUM, 'post_quantum'), (HYBRID, 'hybrid'),
                         (CLASSICAL, 'classical'), ('unknown', 'unknown')):
        count = readiness[key]
        share = ' ({0:.1f}%)'.format(100 * count / performed) if performed \
            else ''
        lines.append('  {0:<21} {1}{2}'.format(verdict, count, share))
    if readiness['quantum_safe_fraction'] is not None:
        lines.append('  quantum-safe          {0:.1f}% of key exchanges '
                     'performed'.format(
                         100 * readiness['quantum_safe_fraction']))

    if summary.downgrades:
        lines += ['', 'Post-quantum offers refused by the server ({0})'.format(
            len(summary.downgrades))]
        seen = {}
        for downgrade in summary.downgrades:
            pair = (downgrade['offered'], downgrade['forced'])
            seen[pair] = seen.get(pair, 0) + 1
        for (offered, forced), count in sorted(seen.items(),
                                               key=lambda kv: -kv[1]):
            lines.append('  {0} -> {1}   x{2}'.format(offered, forced, count))

    if summary.certificate_keys:
        lines += ['', 'Certificate keys']
        for label, count in summary.certificate_keys.most_common():
            lines.append('  {0:<21} {1}'.format(label, count))
        lines.append('  quantum-vulnerable    {0} of {1}'.format(
            readiness['certificates_quantum_vulnerable'],
            sum(summary.certificate_keys.values())))
    if readiness['certificates_unreadable']:
        lines.append('  unreadable (TLS 1.3)  {0} sessions'.format(
            readiness['certificates_unreadable']))

    if summary.tls_versions:
        lines += ['', 'TLS versions']
        for version, count in summary.tls_versions.most_common():
            lines.append('  {0:<21} {1}'.format(version, count))
    if readiness['deprecated_tls_versions']:
        lines.append('  deprecated (RFC 8996) {0}'.format(
            readiness['deprecated_tls_versions']))
    if readiness['broken_symmetric_ciphers']:
        lines.append('')
        lines.append('Broken symmetric ciphers  {0}'.format(
            readiness['broken_symmetric_ciphers']))

    lines += ['', 'Algorithms observed']
    for entry in summary.inventory:
        lines.append('  {0:<14} {1:<36} {2:<13} {3}'.format(
            entry['kind'], entry['name'][:36], entry['verdict'],
            entry['count']))
    lines.append('')
    return '\n'.join(lines)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    reassembler = Reassembler(
        **{name: value for name, value in
           (('max_stream_bytes', args.max_stream_bytes),
            ('max_flows', args.max_flows)) if value})
    # A parser of `None` is the honest way to say "do not look at the
    # certificates"; sessions.py then keeps the DER rather than dropping it.
    certificate_parser = (lambda _body: []) if args.no_certificates else None
    builder = SessionBuilder(reassembler, certificate_parser)

    summary = Summary()
    records = _collect(_records(args.captures, builder, args.quiet), summary)

    try:
        with _output(args.output) as stream:
            if args.format == 'summary':
                # The report needs the whole summary, so the records are
                # consumed for their effect and discarded.
                for _record in records:
                    pass
                stream.write(format_summary(summary))
            elif args.format == 'json':
                write_json(records, stream, summary,
                           source=', '.join(args.captures))
            elif args.format == 'csv':
                write_csv(records, stream)
            elif args.format == 'ndjson':
                write_ndjson(records, stream)
            else:
                writer = available_formats()[args.format]
                # A CBOM is a statement about the whole body of traffic, so
                # its writer is given the summary rather than the stream.
                for _record in records:
                    pass
                writer(summary, stream, source=', '.join(args.captures))
    except BrokenPipeError:                       # `| head`, and nothing more
        return EXIT_OK
    except (OSError, CaptureError) as exc:
        print('pcapscan: {0}'.format(exc), file=sys.stderr)
        return EXIT_ERROR

    if args.stats:
        print('pcapscan: {0}'.format(
            dict(sorted(builder.stats.items()))), file=sys.stderr)
        print('pcapscan: {0}'.format(reassembler.summary()), file=sys.stderr)
    if builder.stats.get('captures_unreadable'):
        return EXIT_ERROR
    return EXIT_OK
