#!/usr/bin/env python3
"""
Run the fuzzer for as long as you like.

    ./tests/tools/fuzz.py                    30 seconds, every target
    ./tests/tools/fuzz.py --seconds 600      ten minutes
    ./tests/tools/fuzz.py --target pipeline  whole capture files only
    ./tests/tools/fuzz.py --seed 1234        reproduce a run exactly

`tests/test_fuzz.py` runs the same engine with a budget small enough for the
merge gate. This is where a real campaign goes: the three bugs found so far
came from runs of tens of thousands of cases, which is more than belongs in a
test that has to finish in under a second.

Anything that fails is written to `tests/fuzz-crashers/` as a raw input, one
file per distinct (target, exception, line). Those files are the point --
commit the ones that represent a real defect, and they become regression
fixtures that cost nothing to keep.

Exit status is 1 if anything failed, so this works as a CI step.
"""
import argparse
import collections
import hashlib
import io
import pathlib
import signal
import sys
import time
import traceback
import warnings

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))          # tests/, for fuzzing.py
sys.path.insert(0, str(HERE.parent.parent))   # the repo root

warnings.filterwarnings('ignore')

from fuzzing import capture_files, corpora, mutate, seeded   # noqa: E402

from cryptomon.analysis import analyse                        # noqa: E402
from cryptomon.parsers.framing import (decode_datagram,       # noqa: E402
                                       decode_frame)
from cryptomon.parsers.tls import (parse_hello_message,       # noqa: E402
                                   parse_tls)
from pcapscan.certificates import parse_certificate_message   # noqa: E402
from pcapscan.cleartext import (CleartextHandler,             # noqa: E402
                                PROTECTIONS)
from pcapscan.datagrams import DatagramKey, datagram_key      # noqa: E402
from pcapscan.quic import (CryptoStream, MAX_CRYPTO_BYTES,    # noqa: E402
                           QuicHandler, VERSION_1, initial_keys,
                           iter_crypto_frames, parse_long_header,
                           split_handshake)
from pcapscan.export import write_csv, write_json, write_ndjson  # noqa: E402
from pcapscan.reader import CaptureError, Reader              # noqa: E402
from pcapscan.reassembly import FlowKey, Stream               # noqa: E402
from pcapscan.records import HandshakeStream                  # noqa: E402
from pcapscan.sessions import SessionBuilder, parse_ssh_stream  # noqa: E402

CRASHERS = HERE.parent / "fuzz-crashers"

# One capture should never take this long. A parser that does is a denial of
# service whether or not it eventually returns.
CASE_TIMEOUT_SECONDS = 10

LINKTYPES = (1, 0, 12, 101, 105, 108, 113, 228, 229, 276)


class CaseTimeout(Exception):
    pass


def _on_alarm(_signum, _frame):
    raise CaseTimeout('case exceeded {0}s'.format(CASE_TIMEOUT_SECONDS))


# --------------------------------------------------------------------------
# targets
# --------------------------------------------------------------------------
def t_framing(seeds, rnd):
    raw = mutate(rnd.choice(seeds['frames']), rnd)
    frame = decode_frame(raw, rnd.choice(LINKTYPES))
    if frame is not None:
        assert 0 <= frame.payload_offset <= frame.payload_end <= len(raw), \
            'offsets are not a usable range'
    return raw


def t_tls(seeds, rnd):
    raw = mutate(rnd.choice(seeds['frames']), rnd)
    parsed = parse_tls(raw)
    if parsed:
        assert parsed['ptype'] in ('client', 'server'), 'impossible ptype'
    return raw


def t_hello(seeds, rnd):
    body = mutate(rnd.choice(seeds['hellos']), rnd)
    parse_hello_message(rnd.choice([1, 2]), body)
    return body


def t_records(seeds, rnd):
    blob = mutate(rnd.choice(seeds['streams']), rnd)
    whole = HandshakeStream().feed(blob)
    walker, chunked, offset = HandshakeStream(), [], 0
    while offset < len(blob):
        width = rnd.randrange(1, 257)
        chunked += walker.feed(blob[offset:offset + width])
        offset += width
    assert [(m.msg_type, m.body) for m in whole] == \
           [(m.msg_type, m.body) for m in chunked], \
        'chunking changed the messages'
    return blob


def t_reassembly(seeds, rnd):
    blob = mutate(rnd.choice(seeds['streams']), rnd)
    stream = Stream(FlowKey('10.0.0.1', 1, '10.0.0.2', 443), 2048, 6)
    base = rnd.randrange(1 << 32)
    for offset in range(0, len(blob), 150):
        seq = (base + rnd.choice([offset, offset - 70, offset + 900, 0])) \
            & 0xFFFFFFFF
        stream.add(seq, blob[offset:offset + 150],
                   rnd.choice([0x18, 0x02, 0x11, 0x04]), 0.0)
    assert len(stream.data) <= 2048, 'stream exceeded its cap'
    assert len(stream.pending) <= 6, 'pending table exceeded its cap'
    return blob


def t_certificates(seeds, rnd):
    body = mutate(rnd.choice(seeds['certificates']), rnd)
    for certificate in parse_certificate_message(body):
        assert len(certificate['fingerprint_sha256']) == 64
    return body


def t_ssh(seeds, rnd):
    blob = mutate(rnd.choice(seeds['streams']), rnd)
    parse_ssh_stream(blob)
    return blob


QUIC_KEY = DatagramKey('10.0.0.1', 50000, '10.0.0.2', 443)


def _quic_varint(value):
    if value < 64:
        return bytes([value])
    return bytes([0x40 | (value >> 8), value & 0xFF])


def _quic_seeds():
    """
    One well-formed QUIC v1 Initial and its plaintext, built rather than
    captured.

    The corpus holds hundreds, but none of them are in `tests/fixtures` and a
    fuzz seed has to be in the repository. Building one costs twenty lines and
    uses `pcapscan.quic`'s own key schedule, which tests/test_quic.py checks
    against RFC 9001 Appendix A.
    """
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    extensions = (bytes.fromhex('0000000e000c0000096c6f63616c686f7374')
                  + bytes.fromhex('002b0003020304')
                  + bytes.fromhex('000a00040002001d'))
    body = (bytes.fromhex('0303') + b'\x11' * 32 + b'\x00'
            + bytes.fromhex('0006130113021303') + b'\x01\x00'
            + len(extensions).to_bytes(2, 'big') + extensions)
    hello = b'\x01' + len(body).to_bytes(3, 'big') + body
    plaintext = b'\x06' + _quic_varint(0) + _quic_varint(len(hello)) + hello
    plaintext += b'\x00' * (1162 - len(plaintext))

    dcid = bytes.fromhex('8394c8f03e515708')
    key, iv, hp_key = initial_keys(dcid, VERSION_1, True)
    header = (b'\xc3' + VERSION_1.to_bytes(4, 'big') + bytes([len(dcid)])
              + dcid + b'\x00' + b'\x00'
              + _quic_varint(len(plaintext) + 20))
    aad = header + b'\x00\x00\x00\x00'
    packet = bytearray(aad + AESGCM(key).encrypt(iv, plaintext, aad))
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = encryptor.update(bytes(packet[len(header) + 4:len(header) + 20]))
    packet[0] ^= mask[0] & 0x0F
    for index in range(4):
        packet[len(header) + index] ^= mask[1 + index]
    return bytes(packet), plaintext


QUIC_PACKET, QUIC_PLAINTEXT = _quic_seeds()


def t_quic(seeds, rnd):
    """A whole QUIC datagram, through detection, the walk and the document."""
    raw = mutate(QUIC_PACKET, rnd)
    QuicHandler.detect(raw, QUIC_KEY)
    handler = QuicHandler()
    handler.push(0.0, raw, QUIC_KEY, None)
    handler.push(1.0, raw[:rnd.randrange(len(raw) + 1)],
                 QUIC_KEY.reverse(), None)
    for document in handler.finish():
        assert 'quic' in document, 'a claimed flow produced no quic block'
        assert handler.crypto[True].octets <= MAX_CRYPTO_BYTES, \
            'CRYPTO stream exceeded its cap'
    header = parse_long_header(raw, 0)
    if header is not None:
        assert 0 <= header.start < header.end <= len(raw), \
            'offsets are not a usable range'
    return raw


def t_quic_frames(seeds, rnd):
    """The decrypted side: frame walk, CRYPTO reassembly, message split."""
    plaintext = mutate(QUIC_PLAINTEXT, rnd)
    stream = CryptoStream()
    for offset, data in iter_crypto_frames(plaintext):
        assert offset >= 0, 'a CRYPTO frame at a negative offset'
        stream.add(offset, data)
    assert stream.octets <= MAX_CRYPTO_BYTES, 'CRYPTO stream exceeded its cap'
    split_handshake(stream.assemble())
    return plaintext


def t_cleartext(seeds, rnd):
    """
    Whole mutated frames through decode_datagram and the UDP handler.

    Seeded from `frames` rather than from a datagram corpus because the
    thing being tested starts at the link layer: the offsets decode_datagram
    hands over are as attacker-influenced as the payload they point at, and
    a handler that trusts them is the defect this target exists to find.
    """
    raw = mutate(rnd.choice(seeds['frames']), rnd)
    datagram = decode_datagram(raw, rnd.choice(LINKTYPES))
    if datagram is None:
        return raw
    payload = bytes(raw[datagram.payload_offset:datagram.payload_end])
    key = datagram_key(datagram)
    handler = CleartextHandler()
    if CleartextHandler.detect(payload, key):
        handler.push(0.0, payload, key, datagram)
    for document in handler.finish():
        assert document['cleartext']['protection'] in PROTECTIONS, \
            'a protection verdict outside the published vocabulary'
    return raw


def t_pipeline(seeds, rnd):
    """Reader to exporters, over a whole mutated capture file."""
    blob = mutate(rnd.choice(seeds['files']), rnd)
    builder = SessionBuilder()
    try:
        with Reader(io.BytesIO(blob)) as reader:
            for packet in reader:
                frame = decode_frame(packet.data, packet.linktype)
                if frame is not None:
                    builder.push(packet.timestamp, packet.data, frame)
    except CaptureError:
        return blob                      # a refusal is a correct outcome
    records = list(builder.finish())
    summary = analyse(records)
    write_ndjson(records, io.StringIO())
    write_csv(records, io.StringIO())
    write_json(records, io.StringIO(), summary)
    try:
        from pcapscan.cbom import build
    except ImportError:
        pass
    else:
        build(summary, source='fuzz')
    return blob


TARGETS = {name[2:]: fn for name, fn in sorted(globals().items())
           if name.startswith('t_')}


# --------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    parser.add_argument('--seconds', type=float, default=30.0,
                        help='wall-clock budget (default: %(default)s)')
    parser.add_argument('--cases', type=int, default=None,
                        help='stop after this many cases instead')
    parser.add_argument('--target', action='append', choices=sorted(TARGETS),
                        help='restrict to one target; repeatable')
    parser.add_argument('--seed', default='pcapscan',
                        help='seed, for reproducing a run (default: %(default)s)')
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args(argv)

    seeds = corpora()
    seeds['files'] = capture_files()
    if not seeds['frames']:
        print('fuzz: no fixtures found', file=sys.stderr)
        return 2
    chosen = {name: TARGETS[name] for name in (args.target or TARGETS)}
    if not args.quiet:
        print('fuzz: {0} frames, {1} streams, {2} hellos, {3} certificates, '
              '{4} captures'.format(
                  len(seeds['frames']), len(seeds['streams']),
                  len(seeds['hellos']), len(seeds['certificates']),
                  len(seeds['files'])), file=sys.stderr)
        print('fuzz: targets {0}'.format(', '.join(sorted(chosen))),
              file=sys.stderr)

    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, _on_alarm)

    rnd = seeded(args.seed)
    failures = collections.Counter()
    saved = {}
    started = time.time()
    cases = 0
    names = sorted(chosen)
    while True:
        if args.cases is not None and cases >= args.cases:
            break
        if args.cases is None and time.time() - started >= args.seconds:
            break
        name = rnd.choice(names)
        data = None
        if hasattr(signal, 'SIGALRM'):
            signal.setitimer(signal.ITIMER_REAL, CASE_TIMEOUT_SECONDS)
        try:
            data = chosen[name](seeds, rnd)
        except Exception as exc:                    # noqa: BLE001 -- the point
            frames = traceback.extract_tb(sys.exc_info()[2])
            ours = [f for f in frames
                    if 'pcapscan' in f.filename or 'cryptomon' in f.filename]
            where = (ours[-1] if ours else frames[-1])
            key = (name, type(exc).__name__,
                   '{0}:{1}'.format(pathlib.Path(where.filename).name,
                                    where.lineno), str(exc)[:80])
            failures[key] += 1
            saved.setdefault(key, data)
        finally:
            if hasattr(signal, 'SIGALRM'):
                signal.setitimer(signal.ITIMER_REAL, 0)
        cases += 1

    elapsed = time.time() - started
    print('fuzz: {0} cases in {1:.1f}s ({2:.0f}/s), {3} distinct failure(s)'
          .format(cases, elapsed, cases / elapsed if elapsed else 0,
                  len(failures)))
    if not failures:
        return 0

    CRASHERS.mkdir(exist_ok=True)
    for key, count in failures.most_common():
        target, exception, where, message = key
        print('  {0:6d}x  {1:12s} {2:22s} {3}  {4}'.format(
            count, target, exception, where, message))
        data = saved.get(key)
        if data is None:
            continue
        path = CRASHERS / '{0}_{1}_{2}.bin'.format(
            target, exception, hashlib.sha256(data).hexdigest()[:12])
        path.write_bytes(data)
        print('           saved {0} ({1} bytes)'.format(path, len(data)))
    print('\nRe-run one with: ./tests/tools/fuzz.py --seed {0} --target <name>'
          .format(args.seed))
    return 1


if __name__ == '__main__':
    sys.exit(main())
