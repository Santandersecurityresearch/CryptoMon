"""
Unwrapping mirrored traffic: GRE, ERSPAN, VXLAN, GENEVE and IP-in-IP.

**Why this exists.** Every measurement in this repository was taken from a
capture made *on an endpoint*. That is not how anyone monitors a corporate
network. They configure a SPAN, RSPAN or ERSPAN session on a switch, or hang
a TAP off a link, and the mirrored traffic arrives somewhere else --
encapsulated. The common encapsulation is ERSPAN, which wraps the whole
original Ethernet frame in GRE inside IP. To `decode_frame` that frame is IP
protocol 47, which is neither TCP nor UDP, so it returned None and the packet
was dropped with no cryptography recorded. Pointing this tool at an
enterprise's actual monitoring infrastructure produced a report of nothing at
all.

**Why it is a separate stage rather than a branch inside `decode_frame`.**
Unwrapping a tunnel does not produce a transport header; it produces *another
whole frame*, which then needs the entire link-layer -> network -> transport
walk run over it again. Putting that recursion inside `decode_frame` would
hand every one of its callers -- the live eBPF adapter included -- a
recursion they never asked for, and would make the recursion depth an
attacker-controlled parameter in the middle of the hottest function in the
project. So this runs *before* framing and hands framing a frame:

    decoded = decode_packet(raw, linktype)      # tunnels resolved
    decoded.frame                               # a DecodedFrame, or None
    decoded.datagram                            # a DecodedDatagram, or None
    decoded.raw                                 # what those offsets index

The stage also generalises, which is the other half of the argument for it:
VXLAN, GENEVE, plain GRE and IP-in-IP are a few lines each here rather than
four more branches in the framing hot path.

**The network walk is borrowed, not copied.** `framing.walk_network` already
resolves the link layer, skips stacked VLAN tags, reads the IPv4 header
length from IHL, walks the IPv6 extension chain and refuses non-initial
fragments. Every defect that walk has ever had produced *plausible wrong
offsets* rather than an error, and a second copy of it here would be a second
place to reintroduce them. The leading underscore says "not part of the
interface"; this module is nevertheless asking for exactly the interface it
provides, and the PR that added this file asks for it to be made public.

**Nothing here is validated against the corpus.** There are zero packets of
IP protocol 47 in all 160,221 frames of `CryptomonData/**`,
`tests/fixtures/**` and `sandbox/*.pcap`, and no VXLAN or GENEVE either. The
fixtures under `tests/fixtures/tunnels/` are built to the RFCs by
`tests/test_tunnels.py` and committed; they are not evidence about real
switches, and this comment is here so that nobody later mistakes them for it.
"""
from typing import NamedTuple

from cryptomon.parsers.framing import (ETHERTYPE_IPV4, ETHERTYPE_IPV6,
                                       LINKTYPE_ETHERNET, LINKTYPE_IPV4,
                                       LINKTYPE_IPV6, LINKTYPE_RAW,
                                       payload_end, walk_network,
                                       decode_datagram, decode_frame)
from cryptomon.utils import PARSE_STATS, lst2int

# --- what a tunnel is carried in ------------------------------------------
IP_PROTO_IPIP = 4          # IPv4 in IPv4, RFC 2003
IP_PROTO_GRE = 47          # RFC 2784, and everything built on it
IP_PROTO_IPV6 = 41         # IPv6 in IPv4 ("6in4"), RFC 4213

# --- GRE, RFC 2784 with the RFC 2890 extensions ---------------------------
# The header is four bytes plus whichever optional fields the flag bits in
# the first two bytes claim are present. Getting the flags wrong does not
# fail -- it shifts the inner frame by four, eight or twelve bytes and
# decodes plausible nonsense, which is the failure mode this whole file
# exists to avoid.
GRE_MIN_HDR_LEN = 4
GRE_FLAG_CHECKSUM = 0x8000     # + checksum(2) and reserved1(2)
GRE_FLAG_ROUTING = 0x4000      # RFC 1701, withdrawn by RFC 2784
GRE_FLAG_KEY = 0x2000          # + key(4), RFC 2890
GRE_FLAG_SEQUENCE = 0x1000     # + sequence(4), RFC 2890
GRE_FLAG_ACK = 0x0080          # PPTP only (RFC 2637), version 1
GRE_VERSION_MASK = 0x0007

# GRE protocol types. The first two are ERSPAN; the rest are ethertypes used
# for what GRE carries directly.
GRE_PROTO_ERSPAN_I_II = 0x88BE
GRE_PROTO_ERSPAN_III = 0x22EB
GRE_PROTO_TEB = 0x6558         # Transparent Ethernet Bridging: inner Ethernet

# --- ERSPAN, draft-foschiano-erspan ---------------------------------------
# Type I has no header at all: the inner Ethernet frame starts immediately
# after GRE. It is told apart from Type II *only* by the GRE sequence flag
# being clear. This is the trap in the whole format -- a parser that assumes
# a header is always present consumes eight bytes of the real Ethernet frame
# and then reads a destination MAC that is half payload, an ethertype that is
# not one, and, more often than it should, decodes anyway.
ERSPAN2_HDR_LEN = 8
ERSPAN3_HDR_LEN = 12
ERSPAN3_SUBHDR_LEN = 8         # platform-specific; present when O is set
ERSPAN_VER_TYPE_II = 1
ERSPAN_VER_TYPE_III = 2
ERSPAN3_FT_IP = 2              # Type III's frame type: 0 Ethernet, 2 bare IP

# --- UDP-carried tunnels ---------------------------------------------------
# These are the only two places a port is allowed to mean anything in this
# project, and even here it only decides whether to *look*: the header is
# then validated and the inner frame has to decode before the outer datagram
# is given up. `pcapscan/protocols.py` settled the general rule -- 13 TLS
# flows in this corpus are on ports nothing watches -- and the rule holds
# here too, because a VXLAN packet is also a perfectly good UDP datagram and
# a detector that unwrapped on the port alone would take DNS traffic that
# happened to be addressed to 4789 away from the UDP router.
VXLAN_PORT = 4789              # IANA
VXLAN_PORT_LINUX = 8472        # what Linux's vxlan driver defaulted to first
GENEVE_PORT = 6081             # IANA, RFC 8926
UDP_TUNNEL_PORTS = {VXLAN_PORT: 'vxlan', VXLAN_PORT_LINUX: 'vxlan',
                    GENEVE_PORT: 'geneve'}

VXLAN_HDR_LEN = 8
VXLAN_FLAG_VNI = 0x08          # "I" -- the VNI field is valid
GENEVE_HDR_LEN = 8             # before options; opt_len counts 4-byte words

# Ethertypes a tunnel may name for what it carries, and the link type that
# describes the result. Mapping to LINKTYPE_IPV4/IPV6 rather than synthesising
# an Ethernet header means framing reads the real bytes, not bytes this
# module invented.
_INNER_BY_ETHERTYPE = {
    ETHERTYPE_IPV4: LINKTYPE_IPV4,
    ETHERTYPE_IPV6: LINKTYPE_IPV6,
    GRE_PROTO_TEB: LINKTYPE_ETHERNET,
}

# How many tunnel headers may be peeled off one packet.
#
# Nesting is legitimate: ERSPAN carrying VLAN-tagged traffic, VXLAN inside
# GRE, the mirror of a link that was itself carrying a tunnel. Three or four
# deep covers every real topology anyone has described.
#
# What the cap defends against is the other case. The inner frame is entirely
# attacker-chosen, and an IPv4-in-IPv4 header costs twenty bytes, so a single
# 1500-byte frame can nest seventy-five of them and a jumbo frame four
# hundred. Without a cap the work per packet is bounded only by how much the
# attacker felt like nesting, over a file this tool is asked to read in bulk
# -- and every layer of it is also a fresh chance for an offset bug. The
# unwrap loop is iterative rather than recursive, so this is a bound on work
# rather than on stack, but unbounded work on attacker input is the whole
# denial of service. A packet still tunnelled at the cap is refused entirely
# and counted, rather than half-unwrapped and handed on as if it were whole.
MAX_TUNNEL_DEPTH = 4


class Layer(NamedTuple):
    """One tunnel header that was peeled off, and what it said."""
    kind: str          # erspan1/2/3, gre, vxlan, geneve or ipip
    truncated: bool    # the switch marked the frame as cut short
    detail: dict       # session id, VLAN, VNI -- whatever it carried


class Unwrapped(NamedTuple):
    """An inner frame, and the tunnel headers that were wrapped around it."""
    raw: bytes         # the inner frame, exactly as the mirrored port saw it
    linktype: int      # what `raw` is: Ethernet, or bare IPv4/IPv6
    layers: tuple      # outermost first
    truncated: bool    # any layer said the frame was cut short


class Decoded(NamedTuple):
    """
    A packet resolved through however many tunnels it arrived in.

    `frame` and `datagram` are what `decode_frame` and `decode_datagram`
    returned for `raw`; exactly one of them is set. `tunnel` is None for the
    overwhelming majority of packets, which are not tunnelled at all.
    """
    raw: bytes
    frame: object      # DecodedFrame, or None
    datagram: object   # DecodedDatagram, or None
    tunnel: object     # Unwrapped, or None


def _count(stats, name):
    """
    Record a refusal or a recognised layer.

    Refusals go somewhere by default rather than nowhere: a run that dropped
    every tunnelled frame must not look like a run that saw none, which is
    what `cryptomon.utils.PARSE_STATS` is for. A caller with its own counter
    -- `SessionBuilder.stats`, which is what `--stats` prints -- passes it in
    and gets the same names under its own roof.
    """
    if stats is None:
        stats = PARSE_STATS
    stats[name] += 1


def _erspan_common(word):
    """
    The first ERSPAN header word, which Type II and Type III share.

        Ver(4) VLAN(12) COS(3) En/BSO(2) T(1) SessionID(10)

    The two types put different meanings on bits 19-20 -- Type II's
    encapsulation type, Type III's bad/short/oversized code -- but every
    other field, the truncation bit included, sits in the same place in both.
    """
    return {
        'version': (word >> 28) & 0x0F,
        'vlan': (word >> 16) & 0x0FFF,
        'cos': (word >> 13) & 0x07,
        'en_bso': (word >> 11) & 0x03,
        'truncated': bool((word >> 10) & 0x01),
        'session_id': word & 0x03FF,
    }


def _peel_erspan(raw, start, end, sequence, kind_hint, stats):
    """
    Resolve an ERSPAN header to (offset of the inner frame, Layer, linktype).

    `kind_hint` is what the GRE protocol type said: 'erspan12' for 0x88BE,
    which is Type I or Type II, or 'erspan3' for 0x22EB. `sequence` is the
    GRE sequence number, or None when the flag was clear -- and for 0x88BE
    that None is not a detail, it is the whole type discriminator.
    """
    if kind_hint == 'erspan12' and sequence is None:
        # Type I. There is no header, so there is nothing to validate and
        # nothing to skip -- the bytes here are already the mirrored frame.
        return start, Layer('erspan1', False, {}), LINKTYPE_ETHERNET

    if kind_hint == 'erspan12':
        if end - start < ERSPAN2_HDR_LEN:
            _count(stats, 'tunnel_refused_erspan_short')
            return None
        fields = _erspan_common(lst2int(raw[start:start + 4]))
        if fields['version'] != ERSPAN_VER_TYPE_II:
            # The sequence flag said Type II and the version nibble disagrees.
            # Trusting the flag here would eat eight bytes of somebody's
            # destination MAC; refusing costs one frame and says so.
            _count(stats, 'tunnel_refused_erspan_version')
            return None
        second = lst2int(raw[start + 4:start + 8])
        detail = {'vlan': fields['vlan'], 'cos': fields['cos'],
                  'encap': fields['en_bso'],
                  'session_id': fields['session_id'],
                  'index': second & 0x000FFFFF,
                  'sequence': sequence}
        # Type II has no frame-type field: what it mirrors is always a frame.
        return (start + ERSPAN2_HDR_LEN,
                Layer('erspan2', fields['truncated'], detail),
                LINKTYPE_ETHERNET)

    if end - start < ERSPAN3_HDR_LEN:
        _count(stats, 'tunnel_refused_erspan_short')
        return None
    fields = _erspan_common(lst2int(raw[start:start + 4]))
    if fields['version'] != ERSPAN_VER_TYPE_III:
        _count(stats, 'tunnel_refused_erspan_version')
        return None
    third = lst2int(raw[start + 8:start + 12])
    # The O bit is the last bit of the third word and says an 8-byte
    # platform-specific sub-header follows. It is the second variable-length
    # decision in this format and the second chance to shift the inner frame.
    length = ERSPAN3_HDR_LEN + (ERSPAN3_SUBHDR_LEN if third & 0x01 else 0)
    if end - start < length:
        _count(stats, 'tunnel_refused_erspan_short')
        return None
    # Frame type. Type III can mirror a bare IP packet rather than a frame,
    # and says which in five bits of the third word -- 0 for Ethernet, 2 for
    # IP. Anything else is a value nobody defined, and is read as Ethernet
    # because that is what every mirror session in the field produces; the
    # value is kept in `detail` so it is visible rather than assumed away.
    # LINKTYPE_RAW takes the family from the IP version nibble, so an FT that
    # lies produces a refusal from framing rather than a wrong decode.
    frame_type = (third >> 10) & 0x1F
    detail = {'vlan': fields['vlan'], 'cos': fields['cos'],
              'bso': fields['en_bso'], 'session_id': fields['session_id'],
              'timestamp': lst2int(raw[start + 4:start + 8]),
              'sgt': (third >> 16) & 0xFFFF,
              'frame_type': frame_type,
              'hardware_id': (third >> 4) & 0x3F,
              'granularity': (third >> 1) & 0x03,
              'subheader': bool(third & 0x01),
              'sequence': sequence}
    return (start + length, Layer('erspan3', fields['truncated'], detail),
            LINKTYPE_RAW if frame_type == ERSPAN3_FT_IP else LINKTYPE_ETHERNET)


def _peel_gre(raw, linktype, stats):
    """
    Peel one GRE header, ERSPAN included. (inner, linktype, Layer) or None.

    The GRE header is variable-length and the variability is in optional
    fields announced by flag bits, so its length is computed from the packet
    rather than known. Each of those computations is checked against what is
    actually left in the buffer before it is used as an offset.
    """
    walked = walk_network(raw, linktype, IP_PROTO_GRE)
    if walked is None:
        return None
    _src, _dst, gre_offset, ip_total_len, ip_offset, _ver, _family = walked
    end = payload_end(raw, ip_offset, ip_total_len, gre_offset)
    if end - gre_offset < GRE_MIN_HDR_LEN:
        _count(stats, 'tunnel_refused_gre_short')
        return None

    flags = lst2int(raw[gre_offset:gre_offset + 2])
    protocol = lst2int(raw[gre_offset + 2:gre_offset + 4])
    if flags & GRE_VERSION_MASK:
        # Version 1 is PPTP (RFC 2637), whose header has an acknowledgement
        # field and whose payload is PPP, not a frame. Nothing else is
        # defined. Either way this is not a mirror session.
        _count(stats, 'tunnel_refused_gre_version')
        return None
    if flags & GRE_FLAG_ROUTING:
        # RFC 1701 source routing: a variable-length list of routing entries
        # terminated by a zero-length one, withdrawn by RFC 2784 and not
        # implemented by anything still shipping. Walking a list that no
        # sender produces, on bytes an attacker chose, to find an offset, is
        # a bad trade -- so it is refused and counted instead of guessed.
        _count(stats, 'tunnel_refused_gre_routing')
        return None

    header_len = GRE_MIN_HDR_LEN
    if flags & GRE_FLAG_CHECKSUM:
        header_len += 4        # checksum(2) + reserved1(2), always together
    if flags & GRE_FLAG_KEY:
        header_len += 4
    sequence_at = gre_offset + header_len
    if flags & GRE_FLAG_SEQUENCE:
        header_len += 4
    if end - gre_offset < header_len:
        # The frame ends inside the optional fields its own flags claimed.
        # `decode_frame` carries a scar from exactly this shape of bug: a
        # frame ending inside its own TCP header gave payload_offset past
        # payload_end, and arithmetic on that is a negative length. Check the
        # computed length against the buffer before it becomes an offset.
        _count(stats, 'tunnel_refused_gre_truncated_header')
        return None
    start = gre_offset + header_len

    # The mirror session's own frame counter, when it sent one. Kept because
    # it is the only evidence a capture carries about whether the SPAN itself
    # dropped frames: a gap in it is traffic the switch chose not to send,
    # which is missing data of exactly the kind this project has twice paid
    # for leaving unlabelled. Counting the gaps needs per-session state and
    # so belongs to a later PR; recording the number costs nothing now.
    sequence = (lst2int(raw[sequence_at:sequence_at + 4])
                if flags & GRE_FLAG_SEQUENCE else None)

    if protocol in (GRE_PROTO_ERSPAN_I_II, GRE_PROTO_ERSPAN_III):
        peeled = _peel_erspan(
            raw, start, end, sequence,
            'erspan12' if protocol == GRE_PROTO_ERSPAN_I_II else 'erspan3',
            stats)
        if peeled is None:
            return None
        start, layer, inner_linktype = peeled
    else:
        inner_linktype = _INNER_BY_ETHERTYPE.get(protocol)
        if inner_linktype is None:
            # GRE carrying something that is not a frame this tool can read
            # -- PPP, MPLS, IS-IS. Refusing is the honest outcome.
            _count(stats, 'tunnel_refused_gre_protocol')
            return None
        layer = Layer('gre', False, {'protocol': protocol,
                                     'sequence': sequence})

    if start >= end:
        _count(stats, 'tunnel_refused_empty')
        return None
    return raw[start:end], inner_linktype, layer


def _peel_udp(raw, linktype, stats):
    """
    Peel one VXLAN or GENEVE header. (inner, linktype, Layer) or None.

    Both sit on a well-known UDP port, so `decode_datagram` does the whole
    network walk -- VLAN tags, IPv4 options, the IPv6 chain, the non-initial
    fragment refusal -- and hands over a payload slice that is already
    bounded by the smaller of the IP and UDP lengths.
    """
    datagram = decode_datagram(raw, linktype)
    if datagram is None:
        return None
    dport = datagram.endpoints['dst']['port']
    sport = datagram.endpoints['src']['port']
    kind = UDP_TUNNEL_PORTS.get(dport) or UDP_TUNNEL_PORTS.get(sport)
    if kind is None:
        return None
    start, end = datagram.payload_offset, datagram.payload_end

    if kind == 'vxlan':
        if end - start < VXLAN_HDR_LEN:
            _count(stats, 'tunnel_refused_vxlan_short')
            return None
        if not raw[start] & VXLAN_FLAG_VNI:
            # RFC 7348 requires the I bit; a receiver must drop the packet
            # without it. Its absence on this port is the cheapest evidence
            # that the payload is something else entirely.
            _count(stats, 'tunnel_refused_vxlan_flags')
            return None
        detail = {'vni': lst2int(raw[start + 4:start + 7])}
        start += VXLAN_HDR_LEN
        inner_linktype = LINKTYPE_ETHERNET
    else:
        if end - start < GENEVE_HDR_LEN:
            _count(stats, 'tunnel_refused_geneve_short')
            return None
        first = raw[start]
        if first >> 6:
            _count(stats, 'tunnel_refused_geneve_version')
            return None
        # Option length is in four-byte words and is the whole variable part
        # of this header, so it is the one number worth checking twice.
        header_len = GENEVE_HDR_LEN + (first & 0x3F) * 4
        if end - start < header_len:
            _count(stats, 'tunnel_refused_geneve_options')
            return None
        protocol = lst2int(raw[start + 2:start + 4])
        inner_linktype = _INNER_BY_ETHERTYPE.get(protocol)
        if inner_linktype is None:
            _count(stats, 'tunnel_refused_geneve_protocol')
            return None
        detail = {'vni': lst2int(raw[start + 4:start + 7]),
                  'protocol': protocol,
                  'options': (first & 0x3F) * 4}
        start += header_len

    if start >= end:
        _count(stats, 'tunnel_refused_empty')
        return None
    return raw[start:end], inner_linktype, Layer(kind, False, detail)


def _peel_ipip(raw, linktype, stats):
    """
    Peel one IP-in-IP header. (inner, linktype, Layer) or None.

    RFC 2003 and the 6in4 of RFC 4213: the payload of the outer IP header is
    another IP header, with no shim between them at all. Cheap here, and the
    same code path a GRE-less mirror or a tunnelled VPN link arrives on.
    """
    for protocol, inner_linktype in ((IP_PROTO_IPIP, LINKTYPE_IPV4),
                                     (IP_PROTO_IPV6, LINKTYPE_IPV6)):
        walked = walk_network(raw, linktype, protocol)
        if walked is None:
            continue
        _src, _dst, start, ip_total_len, ip_offset, _ver, _fam = walked
        end = payload_end(raw, ip_offset, ip_total_len, start)
        if start >= end:
            _count(stats, 'tunnel_refused_empty')
            return None
        return (raw[start:end], inner_linktype,
                Layer('ipip', False, {'protocol': protocol}))
    return None


def _peel(raw, linktype, stats):
    """One tunnel header, whichever kind it is, or None if this is not one."""
    for peel in (_peel_gre, _peel_udp, _peel_ipip):
        peeled = peel(raw, linktype, stats)
        if peeled is not None:
            return peeled
    return None


def unwrap(raw, linktype=LINKTYPE_ETHERNET, max_depth=MAX_TUNNEL_DEPTH,
           stats=None):
    """
    Strip every tunnel header off a packet. An `Unwrapped`, or None.

    None means "this is not a tunnel", which is the answer for essentially
    every packet, and is not an error. A packet that is *still* a tunnel once
    `max_depth` headers have come off is refused outright rather than handed
    on half-unwrapped: what would be returned is a tunnel header, not the
    frame, and the caller has no way to tell the difference.

    Never raises. It is offered attacker-chosen bytes for every packet a
    capture holds that the framing could not read.
    """
    view = memoryview(raw) if isinstance(raw, (bytes, bytearray)) else raw
    layers = []
    for _ in range(max_depth):
        peeled = _peel(view, linktype, stats)
        if peeled is None:
            break
        view, linktype, layer = peeled
        layers.append(layer)
    else:
        # The whole budget was spent and there is still a tunnel underneath.
        # Probed with the counters suppressed, because this second look is
        # this function's own bookkeeping and would otherwise double-count
        # whatever the peel refused.
        if _peel(view, linktype, None) is not None:
            _count(stats, 'tunnel_depth_exceeded')
            return None
    if not layers:
        return None
    return Unwrapped(bytes(view), linktype, tuple(layers),
                     any(layer.truncated for layer in layers))


def decode_packet(raw, linktype=LINKTYPE_ETHERNET, stats=None):
    """
    Decode one packet, through however many tunnels it arrived in.

    The entry point the capture readers call in place of `decode_frame` /
    `decode_datagram`. Returns a `Decoded`, or None when nothing readable is
    in there -- the caller's `frames_undecodable` case, unchanged.

    The order matters and is not the obvious one. TCP first and UDP second,
    because that is the shape of the corpus: 125,708 TCP frames to 30,531
    datagrams, and a tunnel is neither. But a VXLAN or GENEVE packet *is* a
    valid UDP datagram, so "decode first, unwrap only if both refuse" would
    hand the outer datagram straight to the UDP router and never look
    inside. Those two are therefore looked into before being accepted --
    gated on the destination port, which costs one dict lookup per datagram,
    and undone if the inner frame does not decode, so a misidentified port
    loses nothing.
    """
    frame = decode_frame(raw, linktype)
    if frame is not None:
        return Decoded(raw, frame, None, None)

    datagram = decode_datagram(raw, linktype)
    if datagram is not None:
        ports = (datagram.endpoints['dst']['port'],
                 datagram.endpoints['src']['port'])
        if not any(port in UDP_TUNNEL_PORTS for port in ports):
            return Decoded(raw, None, datagram, None)

    tunnel = unwrap(raw, linktype, stats=stats)
    if tunnel is not None:
        inner_frame = decode_frame(tunnel.raw, tunnel.linktype)
        inner_datagram = (None if inner_frame is not None
                          else decode_datagram(tunnel.raw, tunnel.linktype))
        if inner_frame is not None or inner_datagram is not None:
            _count(stats, 'tunnel_frames')
            for layer in tunnel.layers:
                _count(stats, 'tunnel_' + layer.kind)
            if tunnel.truncated:
                # The switch told us it cut this frame short. That is
                # *labelled* missing data, and it is worth more than the
                # frame: this project has been bitten twice by the unlabelled
                # kind -- truncated ClientHellos parsed as whole, and
                # tshark's desegmenter giving up in silence -- and both times
                # the cost was a wrong answer that looked right. Counting it
                # here is the minimum; see the PR for carrying it onto the
                # session document, which needs a change in sessions.py.
                _count(stats, 'tunnel_truncated')
            return Decoded(tunnel.raw, inner_frame, inner_datagram, tunnel)
        # A tunnel whose inner frame is not something framing can read. Worth
        # its own counter: it separates "we cannot follow this tunnel" from
        # "this was never a tunnel", and those want different fixes.
        _count(stats, 'tunnel_inner_undecodable')

    if datagram is not None:
        # A tunnel port carrying something that was not a tunnel, or was one
        # this could not follow. It is still a UDP datagram and the router is
        # still entitled to it.
        return Decoded(raw, None, datagram, None)
    return None


__all__ = ['Decoded', 'Layer', 'MAX_TUNNEL_DEPTH', 'Unwrapped',
           'UDP_TUNNEL_PORTS', 'decode_packet', 'unwrap']
