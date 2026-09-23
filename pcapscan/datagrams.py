"""
Delivering UDP datagrams to the protocols carried over them.

The counterpart of `pcapscan/reassembly.py`, and deliberately much smaller,
because the two transports need opposite things. TCP hands a parser a byte
stream that has to be rebuilt from segments that may arrive twice, out of
order, or not at all. UDP hands it a datagram, whole, exactly as the sender
wrote it. There is nothing to reassemble and nothing to order, so this module
does neither -- it keys flows, picks a handler, and passes bytes through.

Anything that *does* need ordering over UDP carries it in its own header:
QUIC has packet numbers, DTLS has epoch and sequence, IKEv2 has message IDs.
Recovering that is the protocol's job, and pushing it down here would mean
inventing a stream abstraction that three protocols would each have to
misuse. So `push` delivers one datagram and the handler decides what to do
with it.

**Why this exists at all.** Nineteen per cent of this project's capture
corpus -- 30,530 of 159,929 packets -- is UDP, and until this module every
one of them was dropped by `decode_frame`'s `return None`, with no counter
and no mention in the stats. A monitor whose purpose is to report what
cryptography is in use was blind to the transport that now carries a large
share of the web's TLS handshakes. Of those, 11,722 packets are QUIC on port
443 and 738 of them carry a long header, which is where the ClientHello is.

**Handlers are discovered, not registered.** `HANDLER_MODULES` names the
modules this package may carry; each is imported if it is there and skipped
if it is not, the same way `pcapscan/cli.py` discovers the `cbom` format.
That keeps this file from needing an edit every time a protocol is added,
and it means a checkout holding only one of them works -- which is what lets
several people write several protocols at once without editing one shared
list and colliding in it.

**Detection is by content, not by port.** `pcapscan/protocols.py` already
established why for TCP: a port is a convention the traffic is free to
ignore, and this corpus contains 13 TLS flows on ports nothing watches. A
handler's `ports` set is a hint used to order the candidates, never to
decide. The first handler whose `detect` accepts the flow's first datagram
owns the flow.
"""
import collections
import importlib
from typing import NamedTuple

# The modules this package may carry, in the order their detectors are
# offered a datagram. Ordering matters only for the rare payload two
# protocols would both accept: the more specific magic goes first.
HANDLER_MODULES = ('quic', 'dtls', 'ikev2', 'cleartext')

# Flows tracked at once, matching `pcapscan/reassembly.py`'s default. A
# capture of a busy network is mostly DNS and mDNS, so this fills faster
# than the TCP table does and the eviction below is not theoretical.
MAX_FLOWS = 2048

# Per flow. A handler that has not recognised anything within this many
# datagrams is not going to, and a flow that has been recognised does not
# need the tail to describe what it negotiated -- a handshake is at the
# front. Both caps exist so that one long-lived flow cannot grow without
# bound in a process that may be parsing an attacker's capture.
MAX_DATAGRAMS = 64
MAX_BYTES = 65536


class DatagramKey(NamedTuple):
    """
    A UDP flow, keyed the way `reassembly.FlowKey` keys a TCP one.

    Direction is preserved rather than normalised: which end sent the first
    datagram is what tells a handler whether it is looking at a client's
    Initial or a server's reply, and normalising the tuple would throw that
    away. `reverse()` is how a handler reaches the other direction.
    """
    src: str
    sport: int
    dst: str
    dport: int

    def reverse(self):
        return DatagramKey(self.dst, self.dport, self.src, self.sport)


def datagram_key(datagram):
    """The four-tuple of a DecodedDatagram, in the order it was sent."""
    src, dst = datagram.endpoints['src'], datagram.endpoints['dst']
    return DatagramKey(src.get('ipv4') or src.get('ipv6'), src['port'],
                       dst.get('ipv4') or dst.get('ipv6'), dst['port'])


def handlers(modules=HANDLER_MODULES):
    """
    The handler classes this checkout actually has.

    A module that is absent is skipped rather than raising, so a tree
    carrying only one protocol works and a release can ship a subset. A
    module that is present but broken is *not* skipped -- an ImportError
    raised from inside it would be silently swallowed by a bare try, and a
    handler that quietly stops running is worse than one that refuses to
    load. Only the module's own absence is tolerated.
    """
    found = []
    for name in modules:
        full = 'pcapscan.' + name
        try:
            module = importlib.import_module(full)
        except ImportError as exc:
            # `No module named 'pcapscan.quic'` is absence. Anything else --
            # including an ImportError raised by the module's own imports --
            # is a defect, and is re-raised.
            if getattr(exc, 'name', None) != full:
                raise
            continue
        handler = getattr(module, 'HANDLER', None)
        if handler is not None:
            found.append(handler)
    return found


class Flow:
    """One UDP flow, and whichever handler claimed it."""

    __slots__ = ('key', 'handler', 'datagrams', 'octets', 'first_ts',
                 'last_ts', 'undetected', 'full')

    def __init__(self, key):
        self.key = key
        self.handler = None
        self.datagrams = 0
        self.octets = 0
        self.first_ts = None
        self.last_ts = None
        self.undetected = False
        self.full = False


class DatagramRouter:
    """
    Keys UDP flows, picks a handler for each, and collects their documents.

    Mirrors `SessionBuilder`'s shape -- `push()` per packet, `finish()` at
    the end -- so the CLI drives both the same way.
    """

    def __init__(self, handler_classes=None, max_flows=MAX_FLOWS,
                 max_datagrams=MAX_DATAGRAMS, max_bytes=MAX_BYTES):
        self.handlers = (handlers() if handler_classes is None
                         else list(handler_classes))
        self.max_flows = max_flows
        self.max_datagrams = max_datagrams
        self.max_bytes = max_bytes
        self.flows = collections.OrderedDict()
        self.done = []
        self.stats = collections.Counter()

    def push(self, timestamp, raw, datagram):
        """Deliver one datagram. `raw` is the whole frame."""
        payload = bytes(raw[datagram.payload_offset:datagram.payload_end])
        self.stats['datagrams'] += 1
        self.stats['payload_bytes'] += len(payload)
        if not payload:
            self.stats['empty'] += 1
            return

        key = datagram_key(datagram)
        flow = self.flows.get(key)
        if flow is None:
            # A reply arrives on the reversed tuple and belongs to the same
            # conversation. Without this a QUIC exchange is two flows and
            # the server's half has no ClientHello to be a reply to.
            flow = self.flows.get(key.reverse())
        if flow is None:
            flow = self._open(key)
        else:
            self.flows.move_to_end(flow.key)

        if flow.undetected or flow.full:
            return

        flow.datagrams += 1
        flow.octets += len(payload)
        flow.last_ts = timestamp
        if flow.first_ts is None:
            flow.first_ts = timestamp

        if flow.handler is None:
            chosen = self._detect(payload, key)
            if chosen is None:
                if flow.datagrams >= self.max_datagrams:
                    flow.undetected = True
                    self.stats['flows_unrecognised'] += 1
                return
            flow.handler = chosen()
            self.stats['flows_' + chosen.name] += 1

        try:
            flow.handler.push(timestamp, payload, key, datagram)
        except Exception:                   # noqa: BLE001
            # Guarded for the same reason `_detect` is, and it was not at
            # first: a handler is fed attacker-chosen bytes on every packet,
            # and one raising here ended the whole capture -- for every other
            # protocol too, since they share this loop. A protocol that
            # cannot read a datagram should cost that datagram, not the file.
            self.stats['push_error_' + flow.handler.name] += 1
        if (flow.datagrams >= self.max_datagrams
                or flow.octets >= self.max_bytes):
            flow.full = True
            self.stats['flows_capped'] += 1

    def _detect(self, payload, key):
        """
        The first handler that recognises this payload, or None.

        Handlers whose advertised ports match the flow are offered it first.
        That is an ordering hint and nothing more: a handler still has to
        recognise the bytes, so a protocol on an unexpected port is still
        found and a decoy on an expected one is still refused.
        """
        ports = (key.sport, key.dport)
        ordered = sorted(
            self.handlers,
            key=lambda h: 0 if set(ports) & set(getattr(h, 'ports', ())) else 1)
        for handler in ordered:
            try:
                if handler.detect(payload, key):
                    return handler
            except Exception:               # noqa: BLE001
                # A detector is fed attacker-chosen bytes on every packet.
                # One that raises must not take the capture down with it or
                # stop the remaining detectors being offered the datagram.
                self.stats['detect_error_' + handler.name] += 1
        return None

    def _open(self, key):
        flow = Flow(key)
        self.flows[key] = flow
        self.stats['flows'] += 1
        while len(self.flows) > self.max_flows:
            _evicted, old = self.flows.popitem(last=False)
            self.stats['evicted'] += 1
            self._retire(old)
        return flow

    def _retire(self, flow):
        if flow.handler is not None:
            self.done.append(flow)
            return
        # Every flow no handler claimed, not only the ones that ran all the
        # way to MAX_DATAGRAMS. `flows_unrecognised` alone counted the
        # latter, so a two-datagram exchange was counted nowhere and the
        # per-handler counters plus the unrecognised count did not sum to
        # `flows` -- 1,071 of 1,164 corpus flows fell in the gap. A stats
        # line whose parts do not add up is worse than no stats line, and
        # "what is on this network that we cannot name" is exactly the
        # number this one is for.
        if not flow.undetected:
            self.stats['flows_undetected'] += 1

    def finish(self):
        """Every recognised flow, as documents, oldest first."""
        for flow in self.flows.values():
            self._retire(flow)
        self.flows.clear()
        for flow in sorted(self.done, key=lambda f: f.first_ts or 0.0):
            try:
                documents = list(flow.handler.finish() or ())
            except Exception:               # noqa: BLE001
                # Guarded for the same reason `push` and `_detect` are, and
                # it matters more here than in either: `finish` is where the
                # expensive parsing happens -- reassembled CRYPTO bytes split
                # into handshake messages, a hello parsed, a certificate
                # chain walked -- all over input somebody else chose. An
                # unguarded raise here does not cost one datagram, it
                # propagates out of SessionBuilder.finish() and past the
                # CLI's `except (OSError, CaptureError)`, so the whole
                # capture ends in a traceback with no report at all.
                self.stats['finish_error_' + flow.handler.name] += 1
                continue
            for document in documents:
                document.setdefault('ptype', 'session')
                document.setdefault('ts', flow.first_ts)
                document.setdefault(
                    'duration',
                    round((flow.last_ts or 0.0) - (flow.first_ts or 0.0), 6))
                document.setdefault('eth', _eth(flow.key))
                yield document
        self.done = []

    def __len__(self):
        return len(self.flows)


def _eth(key):
    """The 'eth' block, from the flow key rather than the frame."""
    def side(address, port):
        family = 'ipv6' if ':' in str(address) else 'ipv4'
        return {family: address, 'port': port}
    return {'src': side(key.src, key.sport), 'dst': side(key.dst, key.dport)}


__all__ = ['DatagramKey', 'DatagramRouter', 'Flow', 'datagram_key',
           'handlers', 'HANDLER_MODULES', 'MAX_FLOWS', 'MAX_DATAGRAMS',
           'MAX_BYTES']
