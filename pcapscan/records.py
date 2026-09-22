"""
TLS record and handshake-message framing over a reassembled byte stream.

Between "the bytes of this direction, in order" and "this is what the client
proposed" sit two layers of framing that the single-frame parser skipped over
because, in the cases it could see, they happened to line up:

* **Records.** A TLS record is at most 16KB, so a large ClientHello or a
  certificate chain is split across several. Conversely one record can hold
  several handshake messages, and a segment can begin with a record that is
  not a handshake at all. That last case is measurable: about 7% of the
  handshake frames in the committed corpus carry a ChangeCipherSpec record
  ahead of the handshake, and the kernel filter -- which tests only the first
  three bytes of the payload -- never forwards them.

* **Messages.** A handshake message has its own 4-byte header and its own
  length, independent of the records carrying it. A ServerHello and the
  Certificate that follows are commonly in one record; a Certificate on its
  own routinely spans four or five.

Walking both is what turns 7-23% ClientHello recall into all of them, and
zero certificates into every certificate sent in the clear.

The one thing plaintext walking cannot reach: in TLS 1.3 everything after
ServerHello -- EncryptedExtensions, Certificate, CertificateVerify, Finished
-- is inside records marked as application data and encrypted under the
handshake keys. Those certificates are not recoverable from a capture without
the keys, and no amount of reassembly changes that. `HandshakeStream.encrypted`
says when a stream has reached that point, so the difference between "no
certificate was sent" and "the certificate is not readable" stays visible.
"""
from typing import NamedTuple

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23
CONTENT_TYPES = (CONTENT_CHANGE_CIPHER_SPEC, CONTENT_ALERT,
                 CONTENT_HANDSHAKE, CONTENT_APPLICATION_DATA)

RECORD_HDR_LEN = 5
MESSAGE_HDR_LEN = 4

# Handshake message types worth naming here. The rest pass through as numbers.
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CERTIFICATE_VERIFY = 15
HS_CLIENT_KEY_EXCHANGE = 16
HS_FINISHED = 20

HS_NAMES = {
    HS_CLIENT_HELLO: 'client_hello',
    HS_SERVER_HELLO: 'server_hello',
    HS_NEW_SESSION_TICKET: 'new_session_ticket',
    8: 'encrypted_extensions',
    HS_CERTIFICATE: 'certificate',
    HS_SERVER_KEY_EXCHANGE: 'server_key_exchange',
    HS_CERTIFICATE_REQUEST: 'certificate_request',
    HS_SERVER_HELLO_DONE: 'server_hello_done',
    HS_CERTIFICATE_VERIFY: 'certificate_verify',
    HS_CLIENT_KEY_EXCHANGE: 'client_key_exchange',
    HS_FINISHED: 'finished',
}

# A record may be 2**14 plus expansion; the spec's ceiling is 2**14 + 2048.
MAX_RECORD_LEN = (1 << 14) + 2048
# A handshake message length field is three bytes, so it can claim 16MB. The
# stream it arrives on is capped far below that, but the claim is what drives
# the wait, so it is capped here too.
MAX_MESSAGE_LEN = 1 << 18


class Message(NamedTuple):
    """One complete handshake message, header stripped."""
    msg_type: int
    body: bytes

    @property
    def name(self):
        return HS_NAMES.get(self.msg_type, 'type_{0}'.format(self.msg_type))


class Alert(NamedTuple):
    level: int
    description: int


def plausible_handshake(body):
    """
    Could this record body be the start of a plaintext handshake message?

    Needed only after a ChangeCipherSpec, to tell TLS 1.2 -- where CCS really
    does mean the next handshake record is encrypted -- from TLS 1.3, where
    the CCS is a no-op sent purely so that middleboxes see a familiar packet
    sequence (RFC 8446 D.4), and the handshake carries on in the clear.

    An encrypted Finished record is ciphertext, so the first byte lands in
    HS_NAMES about 4% of the time and the three length bytes then have to
    come out below MAX_MESSAGE_LEN as well -- under one in a thousand
    together. A false positive costs one message that parse_handshake
    rejects; a false negative costs the second ClientHello of every
    HelloRetryRequest exchange, which is exactly where the interesting key
    shares are.
    """
    if len(body) < MESSAGE_HDR_LEN:
        return False
    if body[0] not in HS_NAMES:
        return False
    length = (body[1] << 16) | (body[2] << 8) | body[3]
    return length <= MAX_MESSAGE_LEN


def looks_like_tls(data):
    """
    Could these leading stream bytes be the start of a TLS record?

    Used to drop a flow before buffering it. Deliberately loose -- it tests
    the record header only -- because the cost of a false positive is 16KB
    and the cost of a false negative is a missed handshake.
    """
    if len(data) < 3:
        return len(data) == 0 or data[0] in CONTENT_TYPES
    return data[0] in CONTENT_TYPES and data[1] == 3 and data[2] <= 4


class HandshakeStream:
    """
    Turns a growing one-directional byte stream into handshake messages.

    Fed the *new* bytes each time a segment lands, it keeps whatever is left
    over and resumes from there, so the cost is linear in the stream rather
    than quadratic in the number of segments.
    """

    def __init__(self, max_message_len=MAX_MESSAGE_LEN):
        self.max_message_len = max_message_len
        self._buf = bytearray()          # stream bytes not yet made into records
        self._hs = bytearray()           # handshake record bodies, concatenated
        self.records = 0
        self.encrypted = False           # application data seen: stop looking
        self.cipher_changed = False      # ChangeCipherSpec seen
        self.compat_ccs = False          # ...and plaintext handshake after it
        self.alerts = []
        self.malformed = False
        self.record_versions = []
        self.bytes_seen = 0

    @property
    def usable(self):
        """False once the stream cannot yield anything further."""
        return not (self.encrypted or self.malformed)

    def feed(self, data):
        """Take newly reassembled bytes. Returns the messages now complete."""
        if not data or not self.usable:
            return []
        self._buf += data
        self.bytes_seen += len(data)
        self._walk_records()
        return self._split_messages()

    def _walk_records(self):
        offset = 0
        buf = self._buf
        while offset + RECORD_HDR_LEN <= len(buf):
            content_type = buf[offset]
            major, minor = buf[offset + 1], buf[offset + 2]
            length = (buf[offset + 3] << 8) | buf[offset + 4]
            if (content_type not in CONTENT_TYPES or major != 3
                    or minor > 4 or length > MAX_RECORD_LEN):
                # Not a TLS record. Either the stream is not TLS or it has
                # gone out of step, and guessing where it resynchronises
                # would invent handshakes that were never sent.
                self.malformed = True
                break
            end = offset + RECORD_HDR_LEN + length
            if end > len(buf):
                break                    # wait for the rest of the record
            body = bytes(buf[offset + RECORD_HDR_LEN:end])
            self.records += 1
            self.record_versions.append((major, minor))
            if content_type == CONTENT_HANDSHAKE:
                if self.cipher_changed and not plausible_handshake(body):
                    # TLS 1.2: after ChangeCipherSpec the handshake records
                    # are encrypted under the negotiated keys even though the
                    # content type still says 22. Parsing them yields
                    # plausible-looking nonsense, which is worse than
                    # stopping. TLS 1.3 sends a dummy CCS mid-handshake and
                    # carries on in the clear, so the body decides, not the
                    # CCS alone.
                    self.encrypted = True
                    offset = end
                    break
                if self.cipher_changed:
                    self.compat_ccs = True
                self._hs += body
            elif content_type == CONTENT_CHANGE_CIPHER_SPEC:
                self.cipher_changed = True
            elif content_type == CONTENT_ALERT:
                if len(body) >= 2:
                    self.alerts.append(Alert(body[0], body[1]))
            else:                        # application data
                self.encrypted = True
                offset = end
                break
            offset = end
        if offset:
            del self._buf[:offset]

    def _split_messages(self):
        out = []
        hs = self._hs
        offset = 0
        while offset + MESSAGE_HDR_LEN <= len(hs):
            msg_type = hs[offset]
            length = ((hs[offset + 1] << 16) | (hs[offset + 2] << 8)
                      | hs[offset + 3])
            if length > self.max_message_len:
                self.malformed = True
                break
            end = offset + MESSAGE_HDR_LEN + length
            if end > len(hs):
                break                    # message continues in a later record
            out.append(Message(msg_type, bytes(hs[offset + MESSAGE_HDR_LEN:end])))
            offset = end
        if offset:
            del self._hs[:offset]
        return out

    @property
    def pending_bytes(self):
        """Bytes held waiting for the rest of a record or a message."""
        return len(self._buf) + len(self._hs)
