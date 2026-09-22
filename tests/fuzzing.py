"""
The mutation engine, shared by the fuzz tests and the standalone runner.

Two deliberate choices.

**Mutation of a real corpus, not random bytes.** A TLS parser rejects random
bytes in its first three comparisons, so a uniform random fuzzer spends
essentially all of its budget on the `looks_like_tls` check and never reaches
the extension walk. Seeding from real handshakes and perturbing them keeps the
input plausible enough to get deep and wrong enough to be interesting. The
first exploratory run made exactly this mistake and reported 20,000 clean
cases in 0.3 seconds, which was not a result about the parsers.

**Corpora are built per target.** `HandshakeStream` takes reassembled TCP
stream bytes, `parse_hello_message` takes a handshake message body, and
`parse_certificate_message` takes a Certificate message body. Feeding any of
them an Ethernet frame is not a shallow test, it is no test -- the same run
reached the certificate parser zero times before the corpora were split.

**No third-party dependency**, which was a judgement call worth recording.
atheris gives coverage-guided exploration and hypothesis gives shrinking to a
minimal failing case, and both are genuinely better at what they do. Neither
is free: atheris needs clang and libFuzzer on every contributor's machine and
every CI runner, and hypothesis is another pin in a project that keeps its
dependency list short on purpose. This engine runs at about ten thousand
cases a second with nothing but the standard library, and it found three real
defects on its first outing. If a fourth class of bug turns up that shrinking
would have caught faster, that is the moment to add hypothesis -- not before.
"""
import glob
import pathlib
import random

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

# Values a length field is most usefully corrupted to: the maximum, zero, and
# a couple that are plausible but wrong. Random bytes rarely land on these
# and they are where the interesting behaviour is.
LENGTH_PATTERNS_2 = (b'\xff\xff', b'\x00\x00', b'\x7f\xff', b'\x00\x01',
                     b'\x40\x00')
LENGTH_PATTERNS_3 = (b'\xff\xff\xff', b'\x00\x00\x00', b'\x0f\xff\xff')
LENGTH_PATTERNS_4 = (b'\xff\xff\xff\xff', b'\x00\x00\x00\x00',
                     b'\xff\xff\xff\x7f')


def mutate(data, rnd, rounds=None):
    """
    Perturb one input. Between one and a dozen edits, biased towards lengths.

    Truncation and growth are in here as well as byte flips: a parser that
    handles a corrupt length correctly can still walk off the end of a buffer
    that simply stops early, and those are different bugs.
    """
    out = bytearray(data)
    for _ in range(rounds or rnd.randint(1, 12)):
        if not out:
            break
        choice = rnd.random()
        index = rnd.randrange(len(out))
        if choice < 0.30:                                   # byte flip
            out[index] = rnd.randrange(256)
        elif choice < 0.45:                                 # 2-byte length
            out[index:index + 2] = rnd.choice(LENGTH_PATTERNS_2)
        elif choice < 0.55:                                 # 3-byte length
            out[index:index + 3] = rnd.choice(LENGTH_PATTERNS_3)
        elif choice < 0.62:                                 # 4-byte length
            out[index:index + 4] = rnd.choice(LENGTH_PATTERNS_4)
        elif choice < 0.75:                                 # truncate
            out = out[:rnd.randrange(len(out) + 1)]
        elif choice < 0.87:                                 # grow
            out += bytes(rnd.randrange(256)
                         for _ in range(rnd.randrange(300)))
        else:                                               # splice a run
            width = rnd.randrange(40)
            out[index:index + width] = bytes(
                rnd.randrange(256) for _ in range(width))
    return bytes(out)


def capture_files():
    """Every committed capture, as raw file bytes."""
    return [pathlib.Path(p).read_bytes()
            for p in sorted(glob.glob(str(FIXTURES / "**" / "*.pcap"),
                                      recursive=True))]


def corpora():
    """
    Real inputs for each target, extracted from the committed fixtures.

    Returns a dict of lists: `frames` (link-layer), `streams` (one direction
    of a reassembled TCP conversation), `hellos` (handshake message bodies)
    and `certificates` (Certificate message bodies). Built by running the
    real pipeline, so the seeds are exactly the shapes production sees.
    """
    # Imported here so that importing this module costs nothing when only
    # mutate() is wanted.
    from cryptomon.parsers.framing import decode_frame
    from pcapscan.reader import Reader
    from pcapscan.reassembly import Reassembler
    from pcapscan.records import HandshakeStream

    out = {'frames': [], 'streams': [], 'hellos': [], 'certificates': []}
    for path in sorted(FIXTURES.glob("**/*.pcap")):
        reassembler = Reassembler()
        with Reader(path) as reader:
            for packet in reader:
                out['frames'].append(packet.data)
                frame = decode_frame(packet.data, packet.linktype)
                if frame is not None:
                    reassembler.push(packet.timestamp, packet.data, frame)
        for stream in reassembler:
            if stream.data:
                out['streams'].append(bytes(stream.data))

    for blob in out['streams']:
        for message in HandshakeStream().feed(blob):
            if message.msg_type in (1, 2):
                out['hellos'].append(message.body)
            elif message.msg_type == 11:
                out['certificates'].append(message.body)
    out['certificates'] += _certificate_variants(out['certificates'])
    return out


def _certificate_variants(messages):
    """
    Re-frame the real chains every way a Certificate message can be framed.

    The fixtures yield two Certificate messages, both TLS 1.2, both two
    certificates long. That is one shape, and the parser has several branches
    -- the TLS 1.3 framing with its request context and per-entry extension
    block, a single-entry chain, an empty one. Mutating one shape leaves the
    others untested however long the campaign runs.

    Built by re-wrapping the certificates that are already there, so this
    stays deterministic: a run with the same --seed is the same run. Keys
    generated on the fly would give more variety and take that away.
    """
    from pcapscan.certificates import iter_der

    variants = []
    for message in messages:
        ders = list(iter_der(message))
        if not ders:
            continue
        for subset in ([ders[0]], ders[-1:], ders, []):
            entries = b''.join(
                len(d).to_bytes(3, 'big') + d for d in subset)
            variants.append(len(entries).to_bytes(3, 'big') + entries)
            # ...and the TLS 1.3 spelling of the same chain.
            entries13 = b''.join(
                len(d).to_bytes(3, 'big') + d + b'\x00\x00' for d in subset)
            variants.append(b'\x00' + len(entries13).to_bytes(3, 'big')
                            + entries13)
    return variants


def seeded(seed):
    """A Random with a named seed, so a failure is reproducible."""
    return random.Random(seed)
