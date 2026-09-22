"""
Streaming capture reader: pcap, pcapng, and either gzipped.

Why this exists rather than `scapy.rdpcap`: `rdpcap` reads the whole file into
memory and builds a dissected Packet object for every frame. The captures this
tool is aimed at are not small -- `monitor-NUC-dump1.json` alone is 723MB of
*output* -- and the parsers downstream want raw bytes, not scapy layers. So
this yields one record at a time, holds no more than a frame, and costs a
struct.unpack per packet.

What it handles that a naive reader does not:

* **Both pcap byte orders and both timestamp resolutions.** The magic number
  distinguishes them; a capture written on a big-endian host or with
  nanosecond timestamps otherwise reads as garbage lengths.
* **pcapng with several interfaces.** Each Interface Description Block
  carries its own link type and timestamp resolution, and a packet names the
  interface it came from. Collapsing them onto one link type -- which is what
  reading only the first IDB amounts to -- decodes the second interface's
  frames at the wrong offsets, silently.
* **Sections.** A pcapng file may hold several, each with its own byte order
  and its own interface table. A new Section Header Block resets both.
* **Truncated tails.** A capture cut off mid-record is what an interrupted
  tcpdump leaves behind. That is a normal file, not a corrupt one: iteration
  stops and `Reader.stats['truncated_tail']` records it.

Refusals are deliberate and counted rather than raised, except for a file
whose header is not a capture at all -- that is a caller error worth a
traceback.
"""
import gzip
import io
import struct
from typing import NamedTuple

# --- pcap ----------------------------------------------------------------
PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MAGIC_NSEC = 0xA1B23C4D          # ...4D3CB2A1 on disk, little-endian
PCAP_FILE_HDR_LEN = 24
PCAP_REC_HDR_LEN = 16

# --- pcapng --------------------------------------------------------------
BLOCK_SECTION_HEADER = 0x0A0D0D0A
BLOCK_INTERFACE_DESC = 0x00000001
BLOCK_PACKET_OBSOLETE = 0x00000002
BLOCK_SIMPLE_PACKET = 0x00000003
BLOCK_ENHANCED_PACKET = 0x00000006
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
OPT_IF_TSRESOL = 9
OPT_END = 0

GZIP_MAGIC = b'\x1f\x8b'

# A caplen larger than this is a corrupt or hostile length field, not a
# frame. The largest snaplen in practice is 262144 (libpcap's own default
# ceiling); jumbo frames are 9KB.
MAX_CAPTURE_LEN = 1 << 20

# A capture may legitimately describe many interfaces, but not this many.
MAX_INTERFACES = 1024


class CaptureError(ValueError):
    """The file is not a capture this reader understands."""


class Packet(NamedTuple):
    """One captured frame, with what is needed to decode it."""
    index: int          # 1-based, matching how tshark numbers frames
    timestamp: float    # seconds since the epoch
    linktype: int       # of the interface this frame arrived on
    caplen: int         # bytes actually stored
    origlen: int        # bytes on the wire; > caplen means snaplen truncation
    data: bytes


class _Interface(NamedTuple):
    linktype: int
    tsresol: float      # seconds per timestamp tick


def _open_maybe_gzip(source):
    """
    Open a capture, transparently decompressing gzip.

    Sniffed from the magic bytes, not the extension: a `.pcap` written by
    `tcpdump -z gzip` is gzipped, and a `.gz` that is not is a file someone
    renamed. The magic is the fact.

    `peek` is preferred over read-then-seek so that a pipe -- `zcat foo.gz |
    python -m pcapscan -` -- works as well as a file does.
    """
    stream = source if hasattr(source, 'read') else open(source, 'rb')
    if hasattr(stream, 'peek'):
        head = stream.peek(2)[:2]
    else:
        head = stream.read(2)
        try:
            stream.seek(-len(head), io.SEEK_CUR)
        except (OSError, ValueError) as exc:
            raise CaptureError(
                "capture stream must be seekable or buffered") from exc
    if head == GZIP_MAGIC:
        return gzip.GzipFile(fileobj=stream, mode='rb')
    return stream


def _tsresol(value):
    """Decode the if_tsresol option byte into seconds per tick."""
    if value & 0x80:
        return 1.0 / float(1 << (value & 0x7F))
    return 10.0 ** -value


class Reader:
    """
    Iterate the frames of a capture.

    Use it as a context manager, or call `close()`. Iterating yields Packet
    records in file order; `stats` accumulates what was refused and why, so a
    run that quietly dropped frames does not look like a run that saw none.
    """

    def __init__(self, path):
        self.path = path
        self._fh = _open_maybe_gzip(path)
        self._index = 0
        self.stats = {
            'packets': 0,
            'bytes': 0,
            'truncated_tail': 0,
            'oversize_refused': 0,
            'unknown_blocks': 0,
            'sections': 0,
        }
        magic = self._fh.read(4)
        if len(magic) < 4:
            self.close()
            raise CaptureError("file is too short to be a capture")
        self._interfaces = []
        if magic == struct.pack('>I', BLOCK_SECTION_HEADER):
            self._format = 'pcapng'
            self._endian = None          # set from the byte-order magic
            self._pending_shb = True
        elif magic in (struct.pack('<I', PCAP_MAGIC_USEC),
                       struct.pack('>I', PCAP_MAGIC_USEC),
                       struct.pack('<I', PCAP_MAGIC_NSEC),
                       struct.pack('>I', PCAP_MAGIC_NSEC)):
            self._format = 'pcap'
            self._read_pcap_header(magic)
        else:
            self.close()
            raise CaptureError(
                "unrecognised capture magic {0!r}; expected pcap or "
                "pcapng".format(magic))

    # -- lifecycle --------------------------------------------------------
    def close(self):
        fh, self._fh = getattr(self, '_fh', None), None
        if fh is not None:
            fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __iter__(self):
        if self._format == 'pcap':
            return self._iter_pcap()
        return self._iter_pcapng()

    # -- pcap -------------------------------------------------------------
    def _read_pcap_header(self, magic):
        little = magic in (struct.pack('<I', PCAP_MAGIC_USEC),
                           struct.pack('<I', PCAP_MAGIC_NSEC))
        self._endian = '<' if little else '>'
        value = struct.unpack(self._endian + 'I', magic)[0]
        # Nanosecond captures are otherwise identical, so the only difference
        # is the divisor -- but using 1e6 on one makes every timestamp 1000x
        # too large, which reads as a plausible date in the far future.
        self._tick = 1e-9 if value == PCAP_MAGIC_NSEC else 1e-6
        rest = self._fh.read(PCAP_FILE_HDR_LEN - 4)
        if len(rest) < PCAP_FILE_HDR_LEN - 4:
            raise CaptureError("truncated pcap file header")
        _vmaj, _vmin, _tz, _sig, snaplen, network = struct.unpack(
            self._endian + 'HHiIII', rest)
        self.snaplen = snaplen
        self._interfaces = [_Interface(network, self._tick)]

    def _iter_pcap(self):
        endian = self._endian
        linktype = self._interfaces[0].linktype
        tick = self._tick
        while True:
            header = self._fh.read(PCAP_REC_HDR_LEN)
            if len(header) < PCAP_REC_HDR_LEN:
                if header:
                    self.stats['truncated_tail'] += 1
                return
            ts_sec, ts_frac, caplen, origlen = struct.unpack(
                endian + 'IIII', header)
            if caplen > MAX_CAPTURE_LEN:
                self.stats['oversize_refused'] += 1
                return           # the stream is no longer trustworthy
            data = self._fh.read(caplen)
            if len(data) < caplen:
                self.stats['truncated_tail'] += 1
                return
            self._index += 1
            self.stats['packets'] += 1
            self.stats['bytes'] += caplen
            yield Packet(self._index, ts_sec + ts_frac * tick, linktype,
                         caplen, origlen, data)

    # -- pcapng -----------------------------------------------------------
    def _iter_pcapng(self):
        # The first four bytes were consumed in __init__ to identify the
        # format; the section header block is read from its length field on.
        block_type = BLOCK_SECTION_HEADER
        while True:
            if block_type is None:
                raw_type = self._fh.read(4)
                if len(raw_type) < 4:
                    if raw_type:
                        self.stats['truncated_tail'] += 1
                    return
                block_type = struct.unpack(self._endian + 'I', raw_type)[0]

            if block_type == BLOCK_SECTION_HEADER:
                if not self._read_section_header():
                    return
                block_type = None
                continue

            body = self._read_block_body(block_type)
            if body is None:
                return
            if block_type == BLOCK_INTERFACE_DESC:
                self._add_interface(body)
            elif block_type in (BLOCK_ENHANCED_PACKET, BLOCK_SIMPLE_PACKET,
                                BLOCK_PACKET_OBSOLETE):
                packet = self._decode_packet_block(block_type, body)
                if packet is not None:
                    yield packet
            else:
                # Name resolution, statistics, decryption secrets, custom
                # blocks: skipped by design, counted so that is visible.
                self.stats['unknown_blocks'] += 1
            block_type = None

    def _read_section_header(self):
        """Read an SHB from its length field on. Returns False at EOF."""
        head = self._fh.read(8)          # total_length + byte-order magic
        if len(head) < 8:
            self.stats['truncated_tail'] += 1
            return False
        # The byte-order magic is what says how to read total_length, so it
        # has to be identified first, from its own bytes.
        if head[4:8] == struct.pack('>I', PCAPNG_BYTE_ORDER_MAGIC):
            self._endian = '>'
        elif head[4:8] == struct.pack('<I', PCAPNG_BYTE_ORDER_MAGIC):
            self._endian = '<'
        else:
            raise CaptureError("pcapng section header has no byte-order magic")
        total_length = struct.unpack(self._endian + 'I', head[:4])[0]
        if total_length < 28 or total_length > MAX_CAPTURE_LEN:
            raise CaptureError(
                "implausible pcapng section header length {0}".format(
                    total_length))
        rest = self._fh.read(total_length - 12)   # already read 4+4+4
        if len(rest) < total_length - 12:
            self.stats['truncated_tail'] += 1
            return False
        # A new section starts a new interface table. Carrying the old one
        # over would decode the new section's frames with the previous
        # section's link types.
        self._interfaces = []
        self.stats['sections'] += 1
        return True

    def _read_block_body(self, block_type):
        """Body of a block whose type has been read. None at EOF."""
        raw_len = self._fh.read(4)
        if len(raw_len) < 4:
            self.stats['truncated_tail'] += 1
            return None
        total_length = struct.unpack(self._endian + 'I', raw_len)[0]
        if total_length < 12 or total_length > MAX_CAPTURE_LEN:
            self.stats['oversize_refused'] += 1
            return None
        body = self._fh.read(total_length - 12)
        trailer = self._fh.read(4)
        if len(body) < total_length - 12 or len(trailer) < 4:
            self.stats['truncated_tail'] += 1
            return None
        return body

    def _add_interface(self, body):
        if len(body) < 8:
            return
        linktype, _reserved, _snaplen = struct.unpack(
            self._endian + 'HHI', body[:8])
        tsresol = 1e-6
        for code, value in self._iter_options(body[8:]):
            if code == OPT_IF_TSRESOL and value:
                tsresol = _tsresol(value[0])
        if len(self._interfaces) < MAX_INTERFACES:
            self._interfaces.append(_Interface(linktype, tsresol))

    def _iter_options(self, raw):
        """Walk a pcapng option list: code(2) length(2) value, padded to 4."""
        offset = 0
        while offset + 4 <= len(raw):
            code, length = struct.unpack(self._endian + 'HH', raw[offset:offset + 4])
            offset += 4
            if code == OPT_END:
                return
            value = raw[offset:offset + length]
            if len(value) < length:
                return
            yield code, value
            offset += (length + 3) & ~3

    def _decode_packet_block(self, block_type, body):
        if block_type == BLOCK_SIMPLE_PACKET:
            if len(body) < 4:
                return None
            origlen = struct.unpack(self._endian + 'I', body[:4])[0]
            data = body[4:4 + min(origlen, MAX_CAPTURE_LEN)]
            interface_id, timestamp = 0, 0.0
        else:
            if block_type == BLOCK_ENHANCED_PACKET:
                if len(body) < 20:
                    return None
                interface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack(
                    self._endian + 'IIIII', body[:20])
                payload = body[20:]
            else:                       # obsolete Packet Block
                if len(body) < 20:
                    return None
                interface_id, _drops, ts_hi, ts_lo, caplen, origlen = \
                    struct.unpack(self._endian + 'HHIIII', body[:20])
                payload = body[20:]
            if caplen > MAX_CAPTURE_LEN:
                self.stats['oversize_refused'] += 1
                return None
            data = payload[:caplen]
            if len(data) < caplen:
                self.stats['truncated_tail'] += 1
                return None
            ticks = (ts_hi << 32) | ts_lo
            timestamp = None            # resolved below, needs the interface

        if interface_id < len(self._interfaces):
            iface = self._interfaces[interface_id]
        elif self._interfaces:
            # A packet naming an interface the section never described. Its
            # link type is a guess either way; say so rather than drop it.
            self.stats['unknown_blocks'] += 1
            iface = self._interfaces[0]
        else:
            self.stats['unknown_blocks'] += 1
            return None

        if block_type != BLOCK_SIMPLE_PACKET:
            timestamp = ticks * iface.tsresol
        self._index += 1
        self.stats['packets'] += 1
        self.stats['bytes'] += len(data)
        return Packet(self._index, timestamp, iface.linktype, len(data),
                      origlen, data)


def read_packets(path):
    """
    Yield every Packet in a capture. Convenience wrapper around Reader.

    Use Reader directly when the refusal counters matter; this closes the file
    when the generator is exhausted or garbage-collected, so the counters go
    with it.
    """
    with Reader(path) as reader:
        yield from reader
