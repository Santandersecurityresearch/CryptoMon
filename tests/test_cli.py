"""
The command line.

Driven through `main()` with an argv list rather than a subprocess, so a
failure points at a line rather than at an exit code. The one thing worth
asserting about the process boundary -- that `python -m pcapscan` resolves --
is checked separately and cheaply.
"""
import json
import pathlib
import subprocess
import sys

import pytest

from pcapscan.cli import available_formats, build_parser, format_summary, main
from pcapscan.sessions import iter_sessions
from cryptomon.analysis import analyse

pytestmark = pytest.mark.smoke

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
STREAMS = HERE / "fixtures" / "streams"
CERT = str(STREAMS / "tls12_certificate.pcap")
RETRY = str(STREAMS / "tls13_hello_retry.pcap")


def run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --------------------------------------------------------------------------
# the default: a report a person reads
# --------------------------------------------------------------------------
def test_the_default_output_is_a_readable_report(capsys):
    code, out, _err = run([CERT, '-q'], capsys)
    assert code == 0
    assert 'Sessions' in out
    assert 'Key exchange' in out
    # The report is about algorithms, not about who was talked to. Hostnames
    # are browsing history and belong in the record, not in the summary.
    assert 'sha384.badssl.com' not in out
    assert 'sha384WithRSAEncryption' in out
    assert 'RSA-2048' in out


def test_a_refused_post_quantum_offer_is_in_the_report(capsys):
    """
    The finding the tool exists to surface, and it should not need a flag to
    see it.
    """
    _code, out, _err = run([RETRY, '-q'], capsys)
    assert 'Post-quantum offers refused' in out
    assert 'X25519Kyber768Draft00 -> secp256r1' in out


def test_the_report_gives_the_denominator_it_used(capsys):
    """
    "14% quantum-safe" is meaningless without saying 14% of what. Resumed
    sessions perform no key exchange, and counting them would roughly halve
    the figure.
    """
    _code, out, _err = run([CERT, '-q'], capsys)
    assert 'performed' in out
    assert 'of key exchanges performed' in out


# --------------------------------------------------------------------------
# machine formats
# --------------------------------------------------------------------------
def test_ndjson_is_one_json_object_per_line(capsys):
    code, out, _err = run([CERT, RETRY, '-f', 'ndjson', '-q'], capsys)
    assert code == 0
    records = [json.loads(line) for line in out.splitlines()]
    assert len(records) == 2
    assert {r['tls']['hostname'] for r in records} == {'sha384.badssl.com',
                                                       'cdn.bizible.com'}


def test_json_carries_the_summary(capsys):
    code, out, _err = run([CERT, '-f', 'json', '-q'], capsys)
    assert code == 0
    document = json.loads(out)
    assert document['summary']['readiness']['sessions'] == 1
    assert CERT in document['meta']['source']


def test_csv_has_a_header_and_a_row(capsys):
    code, out, _err = run([CERT, '-f', 'csv', '-q'], capsys)
    assert code == 0
    lines = out.strip().splitlines()
    assert lines[0].startswith('ts,time,duration,src')
    assert len(lines) == 2


def test_output_goes_to_a_file_when_asked(tmp_path, capsys):
    target = tmp_path / 'out.ndjson'
    code, out, _err = run([CERT, '-f', 'ndjson', '-o', str(target), '-q'],
                          capsys)
    assert code == 0
    assert out == ''
    assert json.loads(target.read_text())['ptype'] == 'session'


# --------------------------------------------------------------------------
# several captures are one body of traffic
# --------------------------------------------------------------------------
def test_several_captures_are_analysed_together(capsys):
    """
    "What does our estate negotiate" is rarely a question about one file,
    and totalling per-file reports by hand is how people get it wrong.
    """
    code, out, _err = run([CERT, RETRY, '-f', 'json', '-q'], capsys)
    assert code == 0
    assert json.loads(out)['summary']['readiness']['sessions'] == 2


def test_each_capture_is_counted_once(capsys):
    """
    Feeding several files to one builder and finishing after each would
    re-emit everything seen so far: three files would report six sessions.
    """
    split = str(STREAMS / "tls12_split_certificate.pcap")
    _code, out, _err = run([CERT, RETRY, split, '-f', 'ndjson', '-q'], capsys)
    assert len(out.splitlines()) == 3


def test_the_same_capture_twice_is_one_connection_not_two(capsys):
    """
    A replayed file is the same connection replayed -- same four-tuple, same
    initial sequence number. Reporting it twice would be double-counting, so
    the second pass is absorbed as a retransmission of the first.
    """
    _code, out, _err = run([CERT, CERT, '-f', 'ndjson', '-q'], capsys)
    assert len(out.splitlines()) == 1


# --------------------------------------------------------------------------
# failure
# --------------------------------------------------------------------------
def test_an_unreadable_file_does_not_lose_the_others(tmp_path, capsys):
    rubbish = tmp_path / 'notes.txt'
    rubbish.write_text('this is not a capture')
    code, out, err = run([str(rubbish), CERT, '-f', 'ndjson', '-q'], capsys)
    assert 'notes.txt' in err
    assert len(out.splitlines()) == 1     # the good one still came through
    assert code == 1                      # ...and the failure is still visible


def test_a_missing_file_is_reported(tmp_path, capsys):
    code, _out, err = run([str(tmp_path / 'absent.pcap'), '-q'], capsys)
    assert code == 1
    assert 'absent.pcap' in err


def test_stats_go_to_stderr_when_asked(capsys):
    _code, out, err = run([CERT, '-f', 'ndjson', '-q', '--stats'], capsys)
    assert 'capture_packets' in err
    assert 'segments' in err
    assert 'capture_packets' not in out    # never mixed into the output


def test_progress_is_quiet_when_asked(capsys):
    _code, _out, err = run([CERT, '-f', 'ndjson', '-q'], capsys)
    assert 'read' not in err
    _code, _out, err = run([CERT, '-f', 'ndjson'], capsys)
    assert 'read' in err


# --------------------------------------------------------------------------
# options
# --------------------------------------------------------------------------
def test_certificate_parsing_can_be_skipped(capsys):
    _code, out, _err = run([CERT, '-f', 'ndjson', '-q', '--no-certificates'],
                           capsys)
    tls = json.loads(out)['tls']
    assert not tls.get('certificates')


def test_the_reassembly_limits_are_reachable_from_the_command_line(capsys):
    """
    A capture with unusually large certificate chains is the case for
    raising this, and needing to edit the source for it would be absurd.
    """
    code, out, _err = run([CERT, '-f', 'ndjson', '-q',
                           '--max-stream-bytes', '2048',
                           '--max-flows', '8'], capsys)
    assert code == 0
    # 2KB per direction cannot hold the 2.9KB certificate, so the chain is
    # gone -- but the hello still parses and the session is still reported.
    record = json.loads(out)
    assert record['tls']['hostname'] == 'sha384.badssl.com'
    assert not record['tls'].get('certificates')


def test_formats_are_discovered_not_hard_coded():
    """
    An output format whose dependencies are missing should be absent from
    --help rather than present and broken.
    """
    formats = available_formats()
    assert {'ndjson', 'json', 'csv', 'summary'} <= set(formats)
    parser = build_parser()
    action = next(a for a in parser._actions if a.dest == 'format')
    assert set(action.choices) == set(formats)


# --------------------------------------------------------------------------
# the report itself
# --------------------------------------------------------------------------
def test_the_report_does_not_divide_by_zero():
    assert 'Sessions                0' in format_summary(analyse([]))


def test_the_report_names_every_algorithm_it_saw():
    summary = analyse(iter_sessions(STREAMS / "tls12_certificate.pcap"))
    text = format_summary(summary)
    for entry in summary.inventory:
        assert entry['name'][:30] in text


# --------------------------------------------------------------------------
# the process boundary
# --------------------------------------------------------------------------
def test_python_dash_m_pcapscan_runs():
    """`python -m pcapscan` is the documented invocation; it has to resolve."""
    result = subprocess.run(
        [sys.executable, '-m', 'pcapscan', CERT, '-f', 'csv', '-q'],
        cwd=str(ROOT), capture_output=True, text=True,
        env={'PYTHONPATH': str(ROOT), 'PATH': '/usr/bin:/bin'})
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith('ts,time,duration')
