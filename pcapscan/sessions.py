"""
One record per handshake, not one per packet.

The live tool emits a document per parsed frame, which means a ClientHello and
the ServerHello answering it are two unrelated rows joined by nothing. That is
enough to count what clients *offer*, and not enough to say what was *used* --
and those are different questions. The corpus makes the gap concrete: clients
in it offer X25519Kyber768Draft00 constantly, and a server refusing it with a
HelloRetryRequest looks, row by row, exactly like a server accepting it.

A session record carries both halves:

    tls.proposed   what the client asked for
    tls.selected   what the server chose
    tls.ciphersuite / tls.kex_group / tls.hostname   the selected values, at
                   the paths the existing documents already use, so queries
                   and stored data keep working

**Resumption has to be labelled or the key-exchange statistics are wrong.** A
resumed session performs no key exchange at all; counting it as one is
counting an event that did not happen. Roughly a third of connections in the
corpus resume. Two signals, one per protocol version:

  * TLS 1.3 -- the server echoes pre_shared_key (extension 41) in its
    ServerHello. Unambiguous: that *is* the acceptance.
  * TLS 1.2 -- an abbreviated handshake sends no Certificate. Reliable in
    practice, and marked `inferred` in the record so a reader knows which of
    the two it got.

SSH is handled here too, because the live path handles it and an offline tool
that silently ignored it would be a step backwards. Only what the KEXINIT
carries; host key sizes and the PQ markers are PR-33.
"""
import collections

from cryptomon.data import SSH_SECTIONS, TLS_GROUPS_DICT
from cryptomon.parsers.framing import decode_frame
from cryptomon.parsers.tls import parse_hello_message
from cryptomon.ssh_enrichment import describe_ssh_session
from cryptomon.utils import describe_codepoint, lst2int, printable_text
from pcapscan.reader import Reader
from pcapscan.reassembly import Reassembler
from pcapscan.protocols import DEFAULT_HEAD_BYTES, LIKELY, detect
from pcapscan.records import (HS_CERTIFICATE, HS_CLIENT_HELLO,
                              HS_SERVER_HELLO, HS_SERVER_KEY_EXCHANGE,
                              HandshakeStream)

EXT_PRE_SHARED_KEY = 41
EXT_SESSION_TICKET = 35
EXT_EARLY_DATA = 42
EXT_ALPN = 16

# ServerKeyExchange curve types (RFC 8422). Only named_curve is used in
# practice; explicit_prime and explicit_char2 were deprecated for good reason.
EC_CURVE_TYPE_NAMED = 3

SSH_BANNER = b'SSH-'
SSH_MSG_KEXINIT = 20
SSH_COOKIE_LEN = 16
MAX_SSH_BANNER = 255            # RFC 4253 section 4.2
MAX_SSH_NAMELIST = 4096


def _certificate_parser():
    """
    The certificate parser, if this installation has one.

    It lives in pcapscan.certificates and needs `cryptography`, which is an
    optional dependency: reading algorithm negotiation out of a capture does
    not require parsing X.509, and plenty of deployments will not want the
    extra install. Absent it, the chain is kept as raw DER and whoever reads
    the record can do as they like with it.
    """
    try:
        from pcapscan.certificates import parse_certificate_message
    except ImportError:
        return None
    return parse_certificate_message


class Session:
    """
    One connection's handshake, assembled from both directions.

    Built incrementally as messages arrive, so a capture that ends mid
    handshake still yields what it saw. `complete` says whether both hellos
    were present.
    """

    def __init__(self, key, start_ts):
        self.key = key                   # client -> server
        self.start_ts = start_ts
        self.end_ts = start_ts
        self.protocol = None             # 'tls' or 'ssh'
        self.client_hellos = []
        self.server_hellos = []
        self.certificate_messages = []
        self.alerts = []
        self.ssh = {}
        self.banners = {}
        self.encrypted_after_hello = False
        self.server_key_exchange = None
        self.messages = collections.Counter()

    # -- accumulation -----------------------------------------------------
    def note(self, timestamp):
        self.end_ts = max(self.end_ts, timestamp)

    def add_message(self, from_client, message):
        self.protocol = 'tls'
        self.messages[message.name] += 1
        if message.msg_type == HS_CLIENT_HELLO:
            parsed = parse_hello_message(message.msg_type, message.body)
            if parsed:
                self.client_hellos.append(parsed['tls'])
        elif message.msg_type == HS_SERVER_HELLO:
            parsed = parse_hello_message(message.msg_type, message.body)
            if parsed:
                self.server_hellos.append(parsed['tls'])
        elif message.msg_type == HS_CERTIFICATE and not from_client:
            self.certificate_messages.append(message.body)
        elif message.msg_type == HS_SERVER_KEY_EXCHANGE and not from_client:
            self.server_key_exchange = message.body

    # -- derived ----------------------------------------------------------
    @property
    def complete(self):
        return bool(self.client_hellos and self.server_hellos)

    @property
    def hello_retry(self):
        """
        The server refused the client's key share and asked for another.

        Two ClientHellos on one connection is what that looks like on the
        wire, and it is the single most interesting thing a post-quantum
        monitor can observe: an offer that was turned down.
        """
        return len(self.client_hellos) > 1

    @property
    def proposed(self):
        """The client's first offer -- what it was willing to use."""
        return self.client_hellos[0] if self.client_hellos else {}

    @property
    def negotiated(self):
        """The server's last word -- after any HelloRetryRequest."""
        return self.server_hellos[-1] if self.server_hellos else {}

    def key_exchange_group(self):
        """
        The group actually used, from wherever the version in play puts it.

        TLS 1.3 names it in the ServerHello's key_share extension. TLS 1.2
        does not name it in the ServerHello at all -- it is in the
        ServerKeyExchange message, which the single-frame path never had in
        front of it. Reading only the ServerHello reports no group for every
        TLS 1.2 connection, and TLS 1.2 is exactly where classical-only key
        exchange still lives.
        """
        from_hello = self.negotiated.get('kex_group')
        if from_hello:
            return from_hello
        body = self.server_key_exchange
        if not body:
            return None
        suite = self.negotiated.get('ciphersuite') or ''
        if 'ECDHE' in suite or 'ECDH_' in suite:
            if len(body) >= 3 and body[0] == EC_CURVE_TYPE_NAMED:
                return describe_codepoint(TLS_GROUPS_DICT, tuple(body[1:3]),
                                          'unknown_group')
            return 'explicit EC parameters'
        if 'DHE' in suite or 'DH_' in suite:
            # Finite-field Diffie-Hellman names no group; the prime is sent
            # inline, so its size is the only thing identifying the strength.
            # The corpus contains a 512-bit server, which is the whole point
            # of recording this rather than leaving it blank.
            if len(body) >= 2:
                prime_len = lst2int(body[0:2])
                if 0 < prime_len <= len(body) - 2:
                    return 'ffdhe{0}'.format(prime_len * 8)
            return 'finite field DH'
        return None

    def resumption(self):
        """
        ('resumed', 'fresh' or 'unknown', how it was decided).

        Kept as a pair rather than a bool because the two versions give
        evidence of different strength, and a statistic built on this should
        be able to say which it rests on.
        """
        selected = self.negotiated
        if not selected:
            return 'unknown', 'no server hello'
        if EXT_PRE_SHARED_KEY in (selected.get('extensions') or []):
            return 'resumed', 'server selected pre_shared_key'
        versions = selected.get('tls_versions')
        is_13 = (versions == 'TLSv1.3'
                 or (isinstance(versions, list) and 'TLSv1.3' in versions))
        if is_13:
            return 'fresh', 'TLS 1.3 without pre_shared_key'
        if self.certificate_messages:
            return 'fresh', 'certificate sent'
        if self.encrypted_after_hello:
            return 'resumed', 'inferred: abbreviated handshake, no certificate'
        return 'unknown', 'handshake incomplete in the capture'

    # -- output -----------------------------------------------------------
    def document(self, certificate_parser=None):
        """
        One record, shaped so existing consumers keep working.

        `tls.ciphersuite`, `tls.kex_group` and `tls.hostname` stay where the
        live tool has always put them; everything new hangs off `proposed`,
        `selected` and `certificates`.
        """
        if self.protocol == 'ssh':
            return self._ssh_document()
        proposed, selected = self.proposed, self.negotiated
        state, evidence = self.resumption()
        tls = {
            'hostname': proposed.get('hostname'),
            # Sits directly under `hostname` on purpose: when a server
            # accepts ECH the name above is the public outer one, not the
            # destination. 36.9% of corpus clients already offer it. A
            # hostname that quietly stops being the hostname is the same
            # class of defect as the truncated ClientHellos -- unlabelled
            # missing data -- so the qualifier travels with the value.
            'ech': proposed.get('ech'),
            # The client and server fingerprints, lifted out of proposed/
            # selected so that a consumer does not have to know which half
            # of the handshake produced them.
            'ja4': proposed.get('ja4'),
            'ja4s': selected.get('ja4s'),
            'ciphersuite': selected.get('ciphersuite'),
            'kex_group': self.key_exchange_group(),
            'tls_versions': selected.get('tls_versions')
                            or proposed.get('tls_versions'),
            'proposed': proposed,
            'selected': selected,
            'resumption': state,
            'resumption_evidence': evidence,
            'hello_retry_request': self.hello_retry,
            'messages': dict(self.messages),
        }
        if self.hello_retry:
            # What was asked for first, and what the server forced instead.
            # Keeping only the final exchange would erase the refusal.
            tls['offered_kex_group'] = self.client_hellos[0].get('kex_group')
            tls['retry_kex_group'] = self.client_hellos[-1].get('kex_group')
        if self.alerts:
            tls['alerts'] = [{'level': alert.level,
                              'description': alert.description,
                              'from_client': from_client}
                             for from_client, alert in self.alerts]
        if self.certificate_messages:
            parser = certificate_parser or _certificate_parser()
            if parser is None:
                tls['certificates_der'] = [bytes(m) for m
                                           in self.certificate_messages]
            else:
                chain = []
                for message in self.certificate_messages:
                    chain.extend(parser(message))
                tls['certificates'] = chain
        elif self.encrypted_after_hello and state == 'fresh':
            # A TLS 1.3 certificate is inside the encrypted flight. Saying
            # "not readable" and saying "not sent" are different claims, and
            # a post-quantum readiness report that conflated them would
            # undercount the certificates in use.
            tls['certificates_unreadable'] = True
        return {
            'ptype': 'session',
            'eth': {'src': {_family(self.key.src): self.key.src,
                            'port': self.key.sport},
                    'dst': {_family(self.key.dst): self.key.dst,
                            'port': self.key.dport}},
            'ts': self.start_ts,
            'duration': round(self.end_ts - self.start_ts, 6),
            'tls': tls,
        }

    def _ssh_document(self):
        return {
            'ptype': 'session',
            'eth': {'src': {_family(self.key.src): self.key.src,
                            'port': self.key.sport},
                    'dst': {_family(self.key.dst): self.key.dst,
                            'port': self.key.dport}},
            'ts': self.start_ts,
            'duration': round(self.end_ts - self.start_ts, 6),
            'ssh': dict(self.ssh, banners=self.banners),
        }


def _family(address):
    return 'ipv6' if ':' in str(address) else 'ipv4'


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------
def parse_ssh_stream(data):
    """
    Banner and KEXINIT algorithm lists from one direction of an SSH stream.

    The live parser reads these from a single frame; over a reassembled
    stream the banner and the KEXINIT are simply at known offsets from the
    start, with no framing to guess at.
    """
    out = {}
    newline = data.find(b'\r\n', 0, MAX_SSH_BANNER + 2)
    if newline < 0:
        return out
    out['banner'] = printable_text(
        data[:newline].decode('ascii', 'replace'), 'nonprintable_ssh')
    offset = newline + 2
    if offset + 6 + SSH_COOKIE_LEN > len(data):
        return out
    packet_len = lst2int(data[offset:offset + 4])
    if not 0 < packet_len <= len(data) - offset - 4:
        return out                       # the packet has not all arrived
    if data[offset + 5] != SSH_MSG_KEXINIT:
        return out
    end = offset + 4 + packet_len
    offset += 6 + SSH_COOKIE_LEN         # length, padding, code, cookie
    for section in SSH_SECTIONS:
        if offset + 4 > end:
            break
        length = lst2int(data[offset:offset + 4])
        offset += 4
        if length > MAX_SSH_NAMELIST or offset + length > end:
            break
        out[section] = [
            printable_text(name, 'nonprintable_ssh')
            for name in data[offset:offset + length].decode(
                'ascii', 'replace').split(',')]
        offset += length
    return out


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------
class SessionBuilder:
    """
    Reader -> reassembly -> records -> parser -> one record per handshake.

    Holds one Session per connection, keyed on the client's direction so that
    both halves land in the same place. A connection is finished when it
    closes, when its handshake becomes unreadable, or when the capture ends.
    """

    def __init__(self, reassembler=None, certificate_parser=None):
        # `reassembler or Reassembler()` would discard the caller's instance:
        # Reassembler defines __len__, so an empty one is falsy. This is the
        # same shape of bug as the `self.mongodb = False` sentinel that made
        # the TinyDB branch unreachable -- a truthiness test standing in for
        # an identity test.
        self.reassembler = Reassembler() if reassembler is None else reassembler
        self.certificate_parser = certificate_parser
        self.sessions = {}
        self.stats = collections.Counter()
        self._finished = []

    def push(self, timestamp, raw, frame):
        update = self.reassembler.push(timestamp, raw, frame)
        if update is None:
            return
        stream, key = update.stream, update.key
        if not stream.data:
            return
        if 'kind' not in stream.state:
            head = bytes(stream.data[:DEFAULT_HEAD_BYTES])
            kind = self._classify(head, key.dport)
            if kind is None:
                # Undecided is not the same as "not ours". The three-byte
                # sniff this replaces could always answer from the first
                # segment; a detector that checks a declared length against
                # the bytes present cannot, and abandoning on a one-byte
                # first segment would drop real TLS flows.
                if len(head) < DEFAULT_HEAD_BYTES and not stream.full:
                    return
                self.reassembler.abandon(key)
                self.stats['flows_not_tls_or_ssh'] += 1
                return
            stream.state['kind'] = kind
            # Waiting for enough bytes to classify means some have already
            # arrived, and the record walker is fed `new_bytes` -- so hand it
            # everything held rather than only this segment's share, or the
            # start of the handshake is lost exactly when the flow was
            # slowest to identify.
            stream.state['pending_head'] = bytes(stream.data)
        kind = stream.state['kind']
        # The client is whoever sent the first byte of this connection; when
        # only one direction was captured, the lower-numbered well-known port
        # is the server. Pairing on the wrong direction puts the ClientHello
        # in the server slot and every 'selected' value becomes a proposal.
        session_key, from_client = self._orient(key)
        session = self.sessions.get(session_key)
        if update.restarted and session is not None and session.protocol:
            # The tuple has been reused. Whatever was collected under it
            # belongs to the connection that has just ended, not to this one.
            self._finished.append(session)
            self.stats['sessions_closed_by_reuse'] += 1
            session = None
        if session is None:
            session = self.sessions[session_key] = Session(session_key,
                                                           timestamp)
            self.stats['sessions'] += 1
        session.note(timestamp)

        if kind == 'ssh':
            session.protocol = 'ssh'
            if stream.state.get('ssh_done'):
                return
            blob = bytes(stream.data)
            parsed = parse_ssh_stream(blob)
            if parsed:
                side = 'client' if from_client else 'server'
                session.banners[side] = parsed.pop('banner', None)
                for name, value in parsed.items():
                    session.ssh.setdefault(name, value)
                # The host key type and size are the point of reading SSH at
                # all -- "RSA" says nothing about quantum exposure and
                # "RSA-2048" says everything -- and only the server sends
                # one, in a KEX reply that follows the KEXINIT and is
                # normally in a later segment.
                #
                # This is why the gate below is no longer `bool(parsed)`.
                # The old comment here said re-reading the stream "can only
                # find the same thing again", which was true while the
                # KEXINIT lists were all anyone wanted and became false the
                # moment they were not. The server side is not finished
                # until a host key parses.
                enriched = describe_ssh_session(
                    session.banners[side], parsed,
                    None if from_client else blob)
                for name, value in enriched.items():
                    # Skipping empty values matters: describe_ssh_session
                    # always returns its full key set, so a plain setdefault
                    # from the client side would pin host_key_* to None and
                    # the server's real values could never land.
                    if value not in (None, '', {}, [], False):
                        session.ssh[name] = session.ssh.get(name) or value
                stream.state['ssh_done'] = bool(
                    from_client or enriched.get('host_key_size'))
            return

        if 'hs' not in stream.state:
            stream.state['hs'] = HandshakeStream()
        walker = stream.state['hs']
        held = stream.state.pop('pending_head', None)
        for message in walker.feed(update.new_bytes if held is None else held):
            session.add_message(from_client, message)
        # Alerts accumulate on the walker; take the ones not yet copied
        # across. Both directions send them, and both belong to the session.
        seen = stream.state.get('alerts_taken', 0)
        # Which side sent it, kept rather than dropped. Without it the
        # record cannot distinguish "a middlebox refused our key share" from
        # "we refused their parameters" -- and that ambiguity is what makes
        # a handshake_failure correlated with a post-quantum offer a lead
        # rather than a finding. `from_client` is already in scope here and
        # was being discarded one line later.
        session.alerts.extend((from_client, alert)
                              for alert in walker.alerts[seen:])
        stream.state['alerts_taken'] = len(walker.alerts)
        if walker.encrypted:
            session.encrypted_after_hello = True
        if not walker.usable and not stream.abandoned:
            self.reassembler.abandon(key)
            if walker.malformed:
                self.stats['streams_malformed'] += 1

    def _classify(self, head, server_port=None):
        """
        What this stream carries, decided from its bytes.

        The three-byte sniff this replaces could not tell TLS from anything
        else whose first byte happened to land in 20-23, and filed HTTP,
        LDAP, SMB2 and DCE/RPC together as "not TLS or SSH". `detect` names
        them, so the counter below records what the traffic *was* rather
        than only what it was not.

        The port is passed but never decides: `detect` uses it to break a
        `220 ` greeting tie between SMTP and FTP and to mark a port the
        kernel filter does not watch. Letting it select a protocol would
        rebuild the assumption this module exists to remove.
        """
        found = detect(head, server_port)
        if found is None or found.confidence < LIKELY:
            return None
        if found.protocol in ('tls', 'ssh'):
            return found.protocol
        self.stats['flows_' + found.protocol] += 1
        return None

    def _orient(self, key):
        """Return (client->server key, is this stream the client's?)."""
        if key in self.sessions:
            return key, True
        reverse = key.reverse()
        if reverse in self.sessions:
            return reverse, False
        # New connection. The client is the side with the higher port, which
        # is right for every well-known service and is what tshark assumes
        # when it has no SYN either.
        if key.sport < key.dport:
            return reverse, False
        return key, True

    def finish(self):
        """Every session seen, as documents, oldest first."""
        everything = self._finished + list(self.sessions.values())
        for session in sorted(everything, key=lambda s: (s.start_ts, s.key)):
            if session.protocol is None:
                self.stats['sessions_without_handshake'] += 1
                continue
            if session.protocol == 'tls' and not session.client_hellos:
                self.stats['sessions_without_client_hello'] += 1
                continue
            self.stats['sessions_emitted'] += 1
            yield session.document(self.certificate_parser)


def iter_sessions(path, reassembler=None, certificate_parser=None,
                  builder=None):
    """
    Every handshake in a capture, as documents.

    The whole offline pipeline in one call. Streaming in, but not out: a
    session is only complete once its connection is, so the records arrive at
    the end. Memory is bounded by the reassembler's ceiling plus one small
    record per connection.
    """
    if builder is None:
        builder = SessionBuilder(reassembler, certificate_parser)
    with Reader(path) as reader:
        for packet in reader:
            frame = decode_frame(packet.data, packet.linktype)
            if frame is None:
                builder.stats['frames_undecodable'] += 1
                continue
            builder.stats['frames'] += 1
            builder.push(packet.timestamp, packet.data, frame)
        builder.stats.update({'capture_' + k: v
                              for k, v in reader.stats.items()})
    yield from builder.finish()
