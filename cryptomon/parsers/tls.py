"""
TLS handshake parsing.

Pure functions: bytes in, dict out. No ctypes, no bcc, no I/O -- which is what
lets the suite exercise them with no BPF compile and no socket, and what the
offline pcap reader will consume unchanged.

The byte arithmetic below was moved here verbatim from CryptoMon.tls_parse_crypto;
only the skb unwrapping and the header walk changed. The test suite is the proof.
"""
from cryptomon.data import TLS_DICT, TLS_GROUPS_DICT
from cryptomon.parsers.framing import decode_ipv4_tcp
from cryptomon.utils import (PARSE_STATS, cert_guess, describe_codepoint,
                             describe_codepoints, get_tls_version, is_grease,
                             lst2int, lst2str, parse_sigalgs, printable_text)


# A TLS record is a 5-byte header -- type, version(2), length(2) -- followed
# by `length` bytes of body. Nothing parsed below may read past that, or past
# the captured frame, whichever comes first.
TLS_RECORD_HDR_LEN = 5

# The handshake message header, up to and including the session id length
# byte: type(1) length(3) version(2) random(32) session_id_len(1).
HANDSHAKE_HDR_LEN = 39

# The same prefix measured from the start of the enclosing record, which is
# how a single-frame parse reaches it.
HANDSHAKE_PREFIX_LEN = TLS_RECORD_HDR_LEN + HANDSHAKE_HDR_LEN   # 44

CLIENT_HELLO = 1
SERVER_HELLO = 2

# Extension code points this parser acts on. Collected verbatim into
# tls['extensions'] as well, because which extensions were *offered* is what
# distinguishes a resumed session from a fresh key exchange -- and an
# unrecognised one still matters to whoever reads the output later.
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ENCRYPT_THEN_MAC = 22
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

# Caps on packet-driven loops. A real hello carries on the order of ten
# extensions and a few dozen list entries; these exist so that a crafted or
# corrupt length field costs a bounded amount of work.
MAX_EXTENSIONS = 64
MAX_LIST_ITEMS = 512


def _clamp_items(byte_length, limit, offset, item_size=2):
    """
    How many fixed-size items can actually be read from `offset`.

    Takes the smallest of what the packet claims, what is left inside the
    record, and MAX_LIST_ITEMS. The claimed length is attacker-controlled and
    was previously trusted outright, so a 0xffff in a two-byte length field
    drove tens of thousands of out-of-range reads whose empty slices then
    entered the output as real values.
    """
    claimed = byte_length // item_size
    available = max(0, (limit - offset)) // item_size
    return min(claimed, available, MAX_LIST_ITEMS)


def parse_handshake(buf, hs_start, limit):
    """
    Parse a ClientHello or ServerHello whose type byte sits at `hs_start`.

    Returns {'ptype': ..., 'tls': {...}}, or {} when the message is not a
    hello or is truncated. `limit` is the first byte the walk may not touch:
    the end of the message, of the enclosing record, or of the captured bytes,
    whichever comes first.

    Splitting this out of parse_tls() is what lets a reassembled stream be
    parsed at all. On the wire a hello is not the start of a frame -- it is a
    handshake message, possibly split across several TLS records, possibly
    sharing a record with the messages around it. The byte arithmetic is
    unchanged; it is rebased from the start of the record onto the start of
    the message, which is the only offset that exists in both worlds.

    Bounding the walk by the end of the *message* rather than the end of the
    record is also strictly tighter. A record holding ServerHello followed by
    Certificate previously let the ServerHello extension walk run on into the
    certificate bytes.
    """
    data = {}
    supported_groups = []
    supported_sigalgs = []
    supported_tls_versions = []
    extensions_seen = []

    if hs_start + HANDSHAKE_HDR_LEN > limit:
        PARSE_STATS['truncated'] += 1
        return {}
    msg_type = buf[hs_start]
    if msg_type not in (CLIENT_HELLO, SERVER_HELLO):
        # A Certificate, NewSessionTicket or Finished message. Not an error
        # -- the caller dispatches on type -- and not something this function
        # can say anything about.
        return {}

    sess_id_len = buf[hs_start + 38]
    data['tls'] = {}
    data['tls']['tls_versions'] = get_tls_version(buf[hs_start + 4: hs_start + 6])
    offset = hs_start + HANDSHAKE_HDR_LEN + sess_id_len
    if offset > limit:
        PARSE_STATS['truncated'] += 1
        return {}
    if msg_type == SERVER_HELLO:
        data['ptype'] = 'server'
        negotiated_suite = tuple(buf[offset:offset+2])
        data['tls']['ciphersuite'] = describe_codepoint(
            TLS_DICT, negotiated_suite, 'unknown_ciphersuite')
        ext_offset = offset + 5  # SKIP negotiated suite (2 bytes), TLS section length (2 bytes) and compression method (1 byte)
        ext_section_len = min(ext_offset + lst2int(buf[offset+3:offset+5]), limit)
        seen_extensions = 0
        while ext_offset + 4 <= ext_section_len:
            seen_extensions += 1
            if seen_extensions > MAX_EXTENSIONS:
                PARSE_STATS['extension_cap_hit'] += 1
                break
            ext_type = lst2int(buf[ext_offset:ext_offset+2])
            ext_len = lst2int(buf[ext_offset+2:ext_offset+4])
            extensions_seen.append(ext_type)
            if ext_type == EXT_KEY_SHARE:  # key section
                kex_group = tuple(buf[ext_offset+4:ext_offset+6])
                data['tls']['kex_group'] = describe_codepoint(
                    TLS_GROUPS_DICT, kex_group, 'unknown_group')
            if ext_type == EXT_SUPPORTED_VERSIONS:
                vers_offset = ext_offset + 2
                # Two byte length for server HELO... (1 for client HELO)
                vers_ext_len = lst2int(buf[vers_offset:vers_offset+2])
                vers_offset += 2
                for i in range(0, _clamp_items(vers_ext_len, ext_section_len,
                                               vers_offset) * 2, 2):
                    supported_tls_versions.append(buf[vers_offset+i:vers_offset+i+2])
                # supported_versions carries GREASE too (RFC 8701). This
                # code was unreachable until the extension walk bound was
                # fixed, so the padding surfaced as a bogus 'ERR' version.
                data['tls']['tls_versions'] = [
                    get_tls_version(x) for x in supported_tls_versions
                    if not is_grease(x)]
            ext_offset += ext_len + 4
    if msg_type == CLIENT_HELLO:
        data['ptype'] = 'client'
        len_ciphersuite_list = lst2int(buf[offset:offset+2])
        csuite_offset = offset + 2
        # Clamp to the record: the length field is attacker-controlled.
        csuite_end = min(csuite_offset + len_ciphersuite_list, limit)
        proposed_suites = buf[csuite_offset:csuite_end]
        ciphersuites = list(zip(proposed_suites[::2], proposed_suites[1::2]))
        data['tls']['ciphersuites'] = describe_codepoints(
            TLS_DICT, ciphersuites, 'unknown_ciphersuite')
        ext_offset = csuite_end
        ext_offset = ext_offset + 1 + lst2int(buf[ext_offset:ext_offset+1])  # compression method len, 1 byte
        ext_offset += 2  # extension length bytes
        # `while ext_offset < tls_len - 1` compared an absolute frame offset
        # against a record-relative length, so the walk stopped tls_offset + 6
        # bytes early and silently dropped whatever extensions sat at the end
        # of the hello -- supported_groups on 15 of 68 corpus ClientHellos,
        # sig_hash_alg on 13. `limit` is the real end of the message.
        seen_extensions = 0
        while ext_offset + 4 <= limit:
            seen_extensions += 1
            if seen_extensions > MAX_EXTENSIONS:
                PARSE_STATS['extension_cap_hit'] += 1
                break
            ext_type = lst2int(buf[ext_offset:ext_offset+2])
            ext_len = lst2int(buf[ext_offset+2:ext_offset+4])
            extensions_seen.append(ext_type)
            if ext_type == EXT_SUPPORTED_VERSIONS:
                vers_offset = ext_offset + 4
                if vers_offset >= limit:
                    break
                vers_ext_len = buf[vers_offset]  # just one byte...
                vers_offset += 1
                for i in range(0, _clamp_items(vers_ext_len, limit,
                                               vers_offset) * 2, 2):
                    supported_tls_versions.append(buf[vers_offset+i:vers_offset+i+2])
                # supported_versions carries GREASE too (RFC 8701). This
                # code was unreachable until the extension walk bound was
                # fixed, so the padding surfaced as a bogus 'ERR' version.
                data['tls']['tls_versions'] = [
                    get_tls_version(x) for x in supported_tls_versions
                    if not is_grease(x)]
            if ext_type == EXT_SERVER_NAME:  # '0000' indicating server_name
                name_offset = ext_offset + 7 # shift 7 bytes to find length of hostname
                len_hostname = lst2int(buf[name_offset:name_offset+2]) # get length of hostname
                name_offset += 2  # skip over the length bytes we just enumerated
                # Clamp: a hostname length of 0xffff would otherwise pull in
                # everything after it, whatever that happened to be.
                name_end = min(name_offset + len_hostname, limit)
                # Printable ASCII only: the bytes are the sender's choice,
                # and every consumer of this field -- CSV, JSON, the report
                # page, a log line -- assumes a hostname.
                data['tls']['hostname'] = printable_text(
                    lst2str(buf[name_offset:name_end]), 'nonprintable_sni')
            if ext_type == EXT_SUPPORTED_GROUPS:  # supported ECC groups
                group_offset = ext_offset + 4
                group_list_len = lst2int(buf[group_offset:group_offset + 2])
                group_offset += 2
                for i in range(0, _clamp_items(group_list_len, limit,
                                               group_offset) * 2, 2):
                    supported_groups.append(tuple(buf[group_offset+i:group_offset+i+2]))
                data['tls']['groups'] = describe_codepoints(
                    TLS_GROUPS_DICT, supported_groups, 'unknown_group')
            if ext_type == EXT_SIGNATURE_ALGORITHMS:
                sigalg_offset = ext_offset + 4
                sigalt_list_len = lst2int(buf[sigalg_offset:sigalg_offset + 2])
                sigalg_offset += 2
                for i in range(0, _clamp_items(sigalt_list_len, limit,
                                               sigalg_offset) * 2, 2):
                    supported_sigalgs.append(tuple(buf[sigalg_offset+i:sigalg_offset+i+2]))
                data['tls']['sigalgs'] = parse_sigalgs(supported_sigalgs)
            if ext_type == EXT_KEY_SHARE:  # key share extension
                # The client offers a *list* of key shares, and Chrome and
                # Edge put a GREASE entry first (RFC 8701). Taking entry
                # zero therefore recorded the padding as the negotiated
                # group on every Chromium ClientHello; walk to the first
                # real group instead.
                shares_len = lst2int(buf[ext_offset+4:ext_offset+6])
                share_offset = ext_offset + 6
                share_end = min(share_offset + shares_len, limit)
                kex_group = None
                seen_shares = 0
                while share_offset + 4 <= share_end:
                    seen_shares += 1
                    if seen_shares > MAX_LIST_ITEMS:
                        PARSE_STATS['keyshare_cap_hit'] += 1
                        break
                    group = tuple(buf[share_offset:share_offset+2])
                    key_len = lst2int(buf[share_offset+2:share_offset+4])
                    if not is_grease(group):
                        kex_group = group
                        break
                    PARSE_STATS['grease_filtered'] += 1
                    # A zero key_len would otherwise leave share_offset
                    # advancing by 4 forever inside a crafted extension; the
                    # cap above bounds it either way.
                    share_offset += 4 + key_len
                if kex_group is not None:
                    data['tls']['kex_group'] = describe_codepoint(
                        TLS_GROUPS_DICT, kex_group, 'unknown_group')
            ext_offset += ext_len + 4
        # Encrypt-then-MAC is a property of the hello, not of whichever
        # extension happened to be walked last. The old `if/else` inside the
        # loop reassigned it on every iteration, so it reported the identity
        # of the final extension: False for all but a handful of helos, and
        # True only when extension 22 came last by luck.
        data['tls']['EtM'] = EXT_ENCRYPT_THEN_MAC in extensions_seen
    if 'ptype' not in data:
        return {}
    # Which extensions were present, in wire order and including ones this
    # parser does not act on. Session pairing needs pre_shared_key (41) to
    # tell a resumption from a fresh key exchange, and nothing else in the
    # output records it.
    data['tls']['extensions'] = extensions_seen
    return data


def parse_hello_message(msg_type, body):
    """
    Parse a hello from a reassembled handshake *message* body.

    `body` excludes the 4-byte handshake header, which is how every record
    walker hands a message over. The header is rebuilt rather than worked
    around, so that exactly one copy of the offset arithmetic exists.
    """
    buf = bytes([msg_type]) + len(body).to_bytes(3, 'big') + bytes(body)
    return parse_handshake(buf, 0, len(buf))


def parse_tls(raw, magic=1):
    """
    Parse one TLS handshake frame. Returns {} if it is not a hello.

    The single-frame path: whatever the kernel filter forwarded, parsed as a
    record starting at the first byte of the TCP payload. Everything it
    cannot see -- a hello split across segments, a hello behind a
    ChangeCipherSpec record, a certificate chain -- belongs to the offline
    reader, which reassembles first and then calls parse_handshake directly.
    """
    frame = decode_ipv4_tcp(raw)
    if frame is None:
        # Not IPv4/TCP, or too short to walk. Dropping is the honest outcome:
        # the alternative is reading whatever bytes happen to sit at the
        # offsets a plain frame would have used.
        PARSE_STATS['unsupported_framing'] += 1
        return {}
    tls_offset = frame.payload_offset

    # Establish the parseable region once. `limit` is the end of the TLS
    # record or the end of the captured bytes, whichever comes first, and
    # every read below is checked against it.
    if tls_offset + TLS_RECORD_HDR_LEN > len(raw):
        PARSE_STATS['truncated'] += 1
        return {}
    tls_len = lst2int(raw[tls_offset + 3: tls_offset + 5])
    limit = min(tls_offset + TLS_RECORD_HDR_LEN + tls_len, len(raw))

    parsed = parse_handshake(raw, tls_offset + TLS_RECORD_HDR_LEN, limit)
    if not parsed:
        return {}
    data = {'eth': frame.endpoints}
    data.update(parsed)

    # next, attempt to get a cert if present...
    cert = {}
    try:
        cert = cert_guess(raw)
    except Exception:
        # Counted, not printed: this runs per packet at line rate, so the
        # counter is the surface. Read it with cryptomon.utils.PARSE_STATS.
        PARSE_STATS['cert_error'] += 1
    if cert:
        data['tls']['certificate'] = cert
    return data
