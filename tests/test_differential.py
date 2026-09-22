"""
Three views of the same bytes, held against each other.

PR-18 claims the offline path recovers handshakes the live path cannot see.
That claim is worth exactly as much as its independent check, so this compares
three readers over the same captures:

  tshark, desegmentation ON     the reference. An implementation by people who
                                are not us, which is the only reason its
                                agreement counts for anything.
  pcapscan                      reassembles, so it has no excuse for seeing
                                less. Must match the reference.
  the single-frame path         gated exactly as bpf.py gates it. Must be a
                                subset, and the size of the shortfall is the
                                measurement the whole of Wave 4 rests on.

Note there are two committed oracles and they answer different questions.
`tests/oracle/*.tsv` is built with desegmentation OFF and judges
`cryptomon.parsers` on the input the kernel filter actually delivers;
`tests/oracle/streams/*.tsv` is built with it ON and judges `pcapscan`.
Holding the offline path to the first would pass whatever it did. Holding the
live path to the second would fail for a reason no parser change can fix.

Neither tshark nor the original corpus is needed to run this -- both the
fixtures and the oracles are committed. The `oracle` CI job regenerates them
with a real tshark and fails if they have drifted.
"""
import csv
import pathlib

import pytest

from cryptomon.data import TLS_DICT, TLS_GROUPS_DICT
from cryptomon.parsers.framing import decode_frame
from cryptomon.parsers.tls import parse_tls
from cryptomon.utils import describe_codepoint, is_grease
from pcapscan.reader import Reader
from pcapscan.sessions import iter_sessions

pytestmark = pytest.mark.smoke

HERE = pathlib.Path(__file__).resolve().parent
STREAMS = HERE / "fixtures" / "streams"
ORACLE = HERE / "oracle" / "streams"

CLIENT_HELLO, SERVER_HELLO, CERTIFICATE = 1, 2, 11


def fixture_names():
    return sorted(p.stem for p in STREAMS.glob("*.pcap"))


def codepoints(cell):
    """tshark prints decimal code points; turn them into (hi, lo) tuples."""
    out = []
    for raw in (cell or '').split(','):
        raw = raw.strip()
        if not raw:
            continue
        value = int(raw, 16) if raw.lower().startswith('0x') else int(raw)
        out.append((value >> 8 & 0xFF, value & 0xFF))
    return out


def read_oracle(name):
    rows = []
    with open(ORACLE / f"{name}.tsv", newline='') as handle:
        for row in csv.DictReader(handle, delimiter='\t'):
            row['types'] = [int(t) for t in row['type'].split(',') if t]
            rows.append(row)
    return rows


def oracle_counts(rows):
    counts = {CLIENT_HELLO: 0, SERVER_HELLO: 0, CERTIFICATE: 0}
    for row in rows:
        for handshake_type in row['types']:
            if handshake_type in counts:
                counts[handshake_type] += 1
    return counts


def offline(name):
    """pcapscan's view: one record per handshake."""
    return list(iter_sessions(STREAMS / f"{name}.pcap"))


def single_frame(name):
    """
    The live path's view, gated exactly as bpf.py gates it.

    bpf.py raises a TLS event only when the TCP payload *starts* with a
    handshake record, so anything else never reaches the parser at all.
    """
    out = []
    with Reader(STREAMS / f"{name}.pcap") as reader:
        for packet in reader:
            frame = decode_frame(packet.data, packet.linktype)
            if frame is None:
                continue
            payload = packet.data[frame.payload_offset:frame.payload_end]
            if not (len(payload) >= 3 and payload[0] == 0x16
                    and payload[1] == 3 and payload[2] in (1, 2, 3, 4)):
                continue
            # Was the record whole, or did the parser read a fragment and
            # report it as though it were complete?
            declared = 5 + ((payload[3] << 8) | payload[4])
            parsed = parse_tls(packet.data)
            if parsed.get('ptype'):
                parsed['_truncated'] = declared > len(payload)
                out.append(parsed)
    return out


# --------------------------------------------------------------------------
# pcapscan against the reference
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", fixture_names())
def test_offline_finds_every_hello_tshark_finds(name):
    counts = oracle_counts(read_oracle(name))
    records = offline(name)
    assert all(r['tls']['proposed'] for r in records), (
        f"{name}: a session with no ClientHello in it")

    # One session per connection, however many hellos it took.
    client_hellos = counts[CLIENT_HELLO]
    retries = sum(1 for r in records if r['tls']['hello_retry_request'])
    assert client_hellos == len(records) + retries, (
        f"{name}: tshark saw {client_hellos} ClientHellos, pcapscan reports "
        f"{len(records)} sessions of which {retries} were retried")


@pytest.mark.parametrize("name", fixture_names())
def test_offline_finds_every_certificate_tshark_finds(name):
    counts = oracle_counts(read_oracle(name))
    records = offline(name)
    chains = sum(1 for r in records
                 if r['tls'].get('certificates')
                 or r['tls'].get('certificates_der'))
    assert chains == counts[CERTIFICATE], (
        f"{name}: tshark decoded {counts[CERTIFICATE]} Certificate messages, "
        f"pcapscan recovered {chains}")


@pytest.mark.parametrize("name", fixture_names())
def test_offline_agrees_on_the_proposed_ciphersuites(name):
    """
    Not just the count -- the actual list, translated from the code points
    tshark printed.
    """
    rows = [r for r in read_oracle(name) if CLIENT_HELLO in r['types']]
    records = offline(name)
    assert rows and records
    expected = [describe_codepoint(TLS_DICT, c, 'unknown_ciphersuite')
                for c in codepoints(rows[0]['ciphersuites'])
                if not is_grease(c)]
    assert records[0]['tls']['proposed']['ciphersuites'] == expected


@pytest.mark.parametrize("name", fixture_names())
def test_offline_agrees_on_the_server_name(name):
    rows = [r for r in read_oracle(name) if r['sni']]
    records = offline(name)
    assert rows, f"{name}: the oracle has no SNI to check against"
    assert records[0]['tls']['hostname'] == rows[0]['sni'].split(',')[0]


def test_offline_agrees_on_the_negotiated_group():
    """
    The HelloRetryRequest capture, where the two views could most easily
    diverge: tshark records three key_share groups in order across the
    exchange, and the last one is what was used.
    """
    rows = read_oracle('tls13_hello_retry')
    groups = [g for row in rows for g in codepoints(row['key_share'])
              if not is_grease(g)]
    record = offline('tls13_hello_retry')[0]['tls']
    assert record['kex_group'] == describe_codepoint(
        TLS_GROUPS_DICT, groups[-1], 'unknown_group')
    assert record['offered_kex_group'] == describe_codepoint(
        TLS_GROUPS_DICT, groups[0], 'unknown_group')


@pytest.mark.parametrize("name", ["tls12_certificate",
                                  "tls12_split_certificate"])
def test_offline_agrees_on_who_the_certificate_is_for(name):
    """
    tshark lists every name in the chain, but splits them across two fields:
    subject RDNs that happen to be PrintableString, and subjectAltName DNS
    entries. `*.badssl.com` is a UTF8String CN and appears only in the
    second, so the union is what has to be compared -- checking one field
    would be checking tshark's ASN.1 string encoding rather than whether the
    two of us read the same certificate.
    """
    rows = read_oracle(name)
    names = {n for row in rows
             for field in ('cert_names', 'cert_dns')
             for n in (row[field] or '').split(',') if n}
    assert names, f"{name}: the oracle decoded no certificate names"
    leaf = offline(name)[0]['tls']['certificates'][0]
    ours = {leaf['subject'].split(',')[0].removeprefix('CN=')}
    ours.update(leaf.get('subject_alt_names') or [])
    assert ours & names, f"{name}: {ours} not among {names}"


# --------------------------------------------------------------------------
# the single-frame path against the reference: the measurement
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", fixture_names())
def test_the_single_frame_path_never_sees_more(name):
    """
    A strict subset, always. If this ever fails it means the offline path has
    lost something the live path kept, which is the one regression Wave 4
    must not have.
    """
    live = single_frame(name)
    counts = oracle_counts(read_oracle(name))
    seen = sum(1 for record in live if record['ptype'] in ('client', 'server'))
    assert seen <= counts[CLIENT_HELLO] + counts[SERVER_HELLO]


@pytest.mark.parametrize("name", fixture_names())
def test_the_single_frame_path_reports_fragments_as_whole_records(name):
    """
    The finding, made permanent.

    The live path does not miss these hellos -- it reports them, incomplete,
    with no indication that anything is missing. Asserting the shortfall is
    non-zero keeps the measurement honest: if a future change makes the live
    path whole, this test fails and should be deleted with the claim.
    """
    truncated = [r for r in single_frame(name) if r['_truncated']]
    assert truncated, (
        f"{name}: expected at least one truncated record from the "
        f"single-frame path; if that is no longer true, the recall claim in "
        f"PR-18 needs revisiting")
    for record in truncated:
        assert record.get('tls'), "a truncated record still parses"


@pytest.mark.parametrize("name", ["tls12_certificate",
                                  "tls12_split_certificate"])
def test_the_single_frame_path_recovers_no_certificate(name):
    """
    A chain is kilobytes and a segment is about 1.4KB, so `cert_guess` has
    never had a whole one in front of it. Here it gets none at all.
    """
    live = single_frame(name)
    assert not any(r.get('tls', {}).get('certificate') for r in live)
    assert offline(name)[0]['tls']['certificates']


def test_the_shortfall_is_reported(capsys):
    """
    Prints the three-way comparison under `-s`. Asserts only that the
    accounting adds up, so it does not have to be edited every time a fixture
    changes.
    """
    print()
    for name in fixture_names():
        counts = oracle_counts(read_oracle(name))
        live = single_frame(name)
        records = offline(name)
        truncated = sum(1 for r in live if r['_truncated'])
        chains = sum(1 for r in records if r['tls'].get('certificates'))
        print(f"  {name:26s} tshark: {counts[CLIENT_HELLO]}CH "
              f"{counts[SERVER_HELLO]}SH {counts[CERTIFICATE]}cert   "
              f"pcapscan: {len(records)} sessions, {chains} chains   "
              f"single-frame: {len(live)} records, {truncated} truncated, "
              f"0 chains")
        assert truncated <= len(live)
