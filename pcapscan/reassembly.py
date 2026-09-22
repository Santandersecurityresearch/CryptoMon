"""
TCP stream reassembly, bounded.

This is the single change that moves the tool from "reports what happened to
fit in one packet" to "reports what happened". The live eBPF path sees one skb
at a time, so it can only parse a handshake that begins at the start of a TCP
payload and ends inside the same segment. Measured against a tshark oracle
over the committed corpus, that is roughly 7-23% of ClientHellos and *no*
certificates at all -- a certificate chain is several kilobytes and never fits
in one segment, so `cert_guess` has never once had a whole one to look at.

What this module does not do, deliberately:

* **It is not a TCP stack.** It does not track windows, does not care about
  ACKs, and never emits anything to the network. It orders bytes.
* **It does not follow a stream past the handshake.** Everything this tool
  wants is in the first few kilobytes of each direction; after that the
  connection is encrypted and buffering it would only cost memory. A
  direction stops accepting data once it reaches `max_stream_bytes`.
* **It does not decide what is interesting.** Port numbers and record magic
  are somebody else's problem, which is why `push()` hands the caller the
  stream and `abandon()` lets it say "not this one". That is what keeps the
  memory ceiling real: a capture full of HTTP drops those flows on their
  first segment rather than buffering 16KB of each.

Memory is bounded by `max_flows * 2 * max_stream_bytes` in the worst case
where every flow is interesting, and in practice by how quickly the caller
abandons the ones that are not.

Sequence numbers wrap at 2**32. Every comparison here goes through
`seq_diff`, which reads the difference as a signed 32-bit quantity, because
`a < b` on raw sequence numbers is wrong for one segment in every four
billion bytes -- about once per 4GB per flow, which a long capture does hit.
"""
import collections
from typing import NamedTuple

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

SEQ_SPACE = 1 << 32

# Defaults. A ClientHello with post-quantum key shares runs to about 2KB; a
# certificate chain with an intermediate is commonly 4-6KB and occasionally
# more. 16KB per direction covers the whole plaintext handshake with room to
# spare, and is the point past which more buffering buys nothing.
DEFAULT_MAX_STREAM_BYTES = 16384
DEFAULT_MAX_FLOWS = 2048
DEFAULT_MAX_PENDING_SEGMENTS = 32


def seq_diff(a, b):
    """`a - b` in TCP sequence space, as a signed value."""
    delta = (a - b) & 0xFFFFFFFF
    return delta - SEQ_SPACE if delta & 0x80000000 else delta


class FlowKey(NamedTuple):
    """One direction of one TCP conversation."""
    src: str
    sport: int
    dst: str
    dport: int

    def reverse(self):
        return FlowKey(self.dst, self.dport, self.src, self.sport)

    def __str__(self):
        return "{0}:{1} -> {2}:{3}".format(*self)


def flow_key(endpoints):
    """Build a FlowKey from a DecodedFrame's endpoints block."""
    src, dst = endpoints['src'], endpoints['dst']
    return FlowKey(src.get('ipv4') or src.get('ipv6'), src['port'],
                   dst.get('ipv4') or dst.get('ipv6'), dst['port'])


class Stream:
    """
    The bytes of one direction, in order, up to a cap.

    `data` holds the contiguous run starting at `base_seq`. Anything arriving
    ahead of the hole waits in `pending` until the hole is filled, or until
    the flow is evicted with the hole still open -- which is the honest
    outcome for a capture that simply does not contain the missing segment.
    """

    __slots__ = ('key', 'data', 'base_seq', 'next_seq', 'pending',
                 'first_seen', 'last_seen', 'syn_seen', 'fin_seen',
                 'rst_seen', 'full', 'abandoned', 'segments', 'retransmits',
                 'overlaps', 'dropped_pending', 'state',
                 'max_bytes', 'max_pending')

    def __init__(self, key, max_bytes=DEFAULT_MAX_STREAM_BYTES,
                 max_pending=DEFAULT_MAX_PENDING_SEGMENTS):
        self.key = key
        self.max_bytes = max_bytes
        self.max_pending = max_pending
        self.data = bytearray()
        self.base_seq = None
        self.next_seq = None
        self.pending = {}
        self.first_seen = None
        self.last_seen = None
        self.syn_seen = False
        self.fin_seen = False
        self.rst_seen = False
        self.full = False
        self.abandoned = False
        self.segments = 0
        self.retransmits = 0
        self.overlaps = 0
        self.dropped_pending = 0
        # Scratch space for whoever consumes the stream -- the record walker
        # keeps its cursor here so that the reassembler need not know it
        # exists.
        self.state = {}

    @property
    def missing_start(self):
        """True when the capture began mid-stream, so byte 0 was never seen."""
        return not self.syn_seen

    def __len__(self):
        return len(self.data)

    def add(self, seq, payload, flags, timestamp):
        """
        Take one segment. Returns the bytes newly appended to `data`.

        Returning only the new bytes is what lets the consumer parse
        incrementally instead of re-walking the whole stream on every packet.
        """
        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp
        if flags & TCP_SYN:
            self.syn_seen = True
            # SYN occupies one sequence number, so the first data byte is
            # seq+1. Getting this wrong shifts the entire stream by one byte,
            # which turns a TLS record header into nonsense.
            if self.base_seq is None:
                self.base_seq = self.next_seq = (seq + 1) & 0xFFFFFFFF
        if flags & TCP_FIN:
            self.fin_seen = True
        if flags & TCP_RST:
            self.rst_seen = True
        if not payload:
            return b''
        self.segments += 1
        if self.base_seq is None:
            # No SYN: the capture started mid-connection, so the first data
            # byte seen is as far back as this stream can ever go.
            self.base_seq = self.next_seq = seq
        if self.full or self.abandoned:
            return b''

        offset = seq_diff(seq, self.next_seq)
        if offset < 0:
            # Overlaps what is already held: a retransmission, or a segment
            # from before the capture started.
            keep = len(payload) + offset
            if keep <= 0:
                self.retransmits += 1
                return b''
            self.overlaps += 1
            payload = payload[-keep:]
            offset = 0
        if offset == 0:
            return self._append(payload)
        # Ahead of the hole. Hold it, replacing any earlier copy of the same
        # sequence number -- a retransmission of a held segment is the same
        # bytes, and keeping both would double-count against the cap.
        if len(self.pending) >= self.max_pending and seq not in self.pending:
            self.dropped_pending += 1
            return b''
        held = self.pending.get(seq)
        if held is None or len(payload) > len(held):
            self.pending[seq] = bytes(payload)
        return b''

    def _append(self, payload):
        room = self.max_bytes - len(self.data)
        if room <= 0:
            self.full = True
            return b''
        take = bytes(payload[:room])
        self.data += take
        self.next_seq = (self.next_seq + len(take)) & 0xFFFFFFFF
        if len(self.data) >= self.max_bytes:
            self.full = True
            self.pending.clear()
        return take + self._drain()

    def _drain(self):
        """Append any held segments that the last append made contiguous."""
        added = bytearray()
        progress = True
        while progress and self.pending and not self.full:
            progress = False
            for seq in sorted(self.pending,
                              key=lambda s: seq_diff(s, self.next_seq)):
                offset = seq_diff(seq, self.next_seq)
                payload = self.pending[seq]
                if offset > 0:
                    break                      # still a hole before this one
                del self.pending[seq]
                keep = len(payload) + offset
                if keep <= 0:
                    continue                   # entirely already held
                chunk = payload[-keep:]
                room = self.max_bytes - len(self.data)
                if room <= 0:
                    self.full = True
                    break
                chunk = chunk[:room]
                self.data += chunk
                added += chunk
                self.next_seq = (self.next_seq + len(chunk)) & 0xFFFFFFFF
                if len(self.data) >= self.max_bytes:
                    self.full = True
                    self.pending.clear()
                progress = True
                break
        return bytes(added)

    def release(self):
        """Give up the buffers. The counters survive; the bytes do not."""
        self.data = bytearray()
        self.pending.clear()
        self.abandoned = True


class Update(NamedTuple):
    """What one segment did to one stream."""
    key: FlowKey
    stream: Stream
    new_bytes: bytes
    restarted: bool = False   # this SYN opened a *new* connection on the tuple


class Reassembler:
    """
    Order the bytes of every TCP flow in a capture, within a memory ceiling.

    Typical use:

        r = Reassembler()
        for packet in Reader(path):
            frame = decode_frame(packet.data, packet.linktype)
            if frame is None:
                continue
            update = r.push(packet.timestamp, packet.data, frame)
            if update and not interesting(update):
                r.abandon(update.key)
    """

    def __init__(self, max_stream_bytes=DEFAULT_MAX_STREAM_BYTES,
                 max_flows=DEFAULT_MAX_FLOWS,
                 max_pending_segments=DEFAULT_MAX_PENDING_SEGMENTS):
        self.max_stream_bytes = max_stream_bytes
        self.max_flows = max_flows
        self.max_pending_segments = max_pending_segments
        self._streams = collections.OrderedDict()
        self.stats = collections.Counter()

    def __len__(self):
        return len(self._streams)

    def __iter__(self):
        return iter(self._streams.values())

    def get(self, key):
        return self._streams.get(key)

    def push(self, timestamp, raw, frame):
        """
        Feed one decoded TCP frame. Returns an Update, or None for a segment
        that carried nothing and changed no state worth reporting.
        """
        key = flow_key(frame.endpoints)
        payload = raw[frame.payload_offset:frame.payload_end]
        stream = self._streams.get(key)
        restarted = False
        if stream is not None and self._reopens(stream, frame):
            # The same four-tuple, a second time. A busy host reuses an
            # ephemeral port within minutes, and analysing several captures
            # together makes it near-certain. Treating the new connection as
            # a continuation of the old one feeds a fresh ClientHello into a
            # stream whose sequence space is somewhere else entirely, and the
            # handshake is simply lost.
            self.stats['tuple_reused'] += 1
            self.close(key)
            stream, restarted = None, True
        if stream is None:
            if not payload and not (frame.flags & TCP_SYN):
                # A bare ACK or FIN for a flow whose data was never captured.
                # Creating a stream for it would fill the table with nothing.
                self.stats['ignored_stateless'] += 1
                return None
            stream = self._new_stream(key)
        else:
            self._streams.move_to_end(key)

        before_full = stream.full
        new_bytes = stream.add(frame.seq, payload, frame.flags, timestamp)
        self.stats['segments'] += 1
        self.stats['payload_bytes'] += len(payload)
        if new_bytes:
            self.stats['reassembled_bytes'] += len(new_bytes)
        if stream.full and not before_full:
            self.stats['streams_full'] += 1
        if frame.flags & TCP_RST:
            self.stats['resets'] += 1
        return Update(key, stream, new_bytes, restarted)

    def _reopens(self, stream, frame):
        """A SYN on a held tuple, carrying a different initial sequence."""
        if not (frame.flags & TCP_SYN) or stream.base_seq is None:
            return False
        # A retransmitted SYN repeats the ISN, so it is not a new connection.
        return seq_diff((frame.seq + 1) & 0xFFFFFFFF, stream.base_seq) != 0

    def _new_stream(self, key):
        while len(self._streams) >= self.max_flows:
            _oldest, evicted = self._streams.popitem(last=False)
            self.stats['evicted'] += 1
            if evicted.pending:
                self.stats['evicted_with_holes'] += 1
            evicted.release()
        stream = Stream(key, self.max_stream_bytes, self.max_pending_segments)
        self._streams[key] = stream
        self.stats['flows'] += 1
        return stream

    def abandon(self, key):
        """
        Stop buffering a flow. Its counters stay; its bytes go.

        The caller uses this the moment it can tell a stream is not carrying
        anything it wants -- which is what keeps a capture full of bulk
        transfer from costing `max_stream_bytes` per flow.
        """
        stream = self._streams.get(key)
        if stream is None:
            return
        if not stream.abandoned:
            self.stats['abandoned'] += 1
        stream.release()

    def close(self, key):
        """Forget a flow entirely, both bytes and table entry."""
        stream = self._streams.pop(key, None)
        if stream is not None:
            stream.release()

    def summary(self):
        """Counters, plus what is still held. Safe to call at any time."""
        out = dict(self.stats)
        out['open_streams'] = len(self._streams)
        out['held_bytes'] = sum(len(s.data) for s in self._streams.values())
        out['pending_segments'] = sum(
            len(s.pending) for s in self._streams.values())
        return out
