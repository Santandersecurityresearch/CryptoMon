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
                             lst2int, lst2str, parse_sigalgs)


# A TLS record is a 5-byte header -- type, version(2), length(2) -- followed
# by `length` bytes of body. Nothing parsed below may read past that, or past
# the captured frame, whichever comes first.
TLS_RECORD_HDR_LEN = 5

# The handshake header before the session id: type(1) length(3) version(2)
# random(32), then the session id length byte at +43.
HANDSHAKE_PREFIX_LEN = 44

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


def parse_tls(raw, magic=1):
    """Parse one TLS handshake frame. Returns {} if it is not a hello."""
    data = {}
    supported_groups = []
    supported_sigalgs = []
    supported_tls_versions = []

    frame = decode_ipv4_tcp(raw)
    if frame is None:
        # Not IPv4/TCP, or too short to walk. Dropping is the honest outcome:
        # the alternative is reading whatever bytes happen to sit at the
        # offsets a plain frame would have used.
        PARSE_STATS['unsupported_framing'] += 1
        return {}
    data['eth'] = frame.endpoints
    tls_offset = frame.payload_offset

    # Establish the parseable region once. `limit` is the end of the TLS
    # record or the end of the captured bytes, whichever comes first, and
    # every read below is checked against it.
    if tls_offset + TLS_RECORD_HDR_LEN > len(raw):
        PARSE_STATS['truncated'] += 1
        return {}
    tls_len = lst2int(raw[tls_offset + 3: tls_offset + 5])
    limit = min(tls_offset + TLS_RECORD_HDR_LEN + tls_len, len(raw))

    if tls_offset + HANDSHAKE_PREFIX_LEN > limit:
        PARSE_STATS['truncated'] += 1
        return {}
    sess_id_len = raw[tls_offset + 43]
    data['tls'] = {}
    data['tls']['tls_versions'] = get_tls_version(raw[tls_offset + 9: tls_offset + 11])
    offset = tls_offset + HANDSHAKE_PREFIX_LEN + sess_id_len
    if offset > limit:
        PARSE_STATS['truncated'] += 1
        return {}
    if raw[tls_offset + 5] == 2:  # server helo
        data['ptype'] = 'server'
        negotiated_suite = tuple(raw[offset:offset+2])
        data['tls']['ciphersuite'] = describe_codepoint(
            TLS_DICT, negotiated_suite, 'unknown_ciphersuite')
        ext_offset = offset + 5  # SKIP negotiated suite (2 bytes), TLS section length (2 bytes) and compression method (1 byte)
        ext_section_len = min(ext_offset + lst2int(raw[offset+3:offset+5]), limit)
        seen_extensions = 0
        while ext_offset + 4 <= ext_section_len:
            seen_extensions += 1
            if seen_extensions > MAX_EXTENSIONS:
                PARSE_STATS['extension_cap_hit'] += 1
                break
            ext_type = lst2int(raw[ext_offset:ext_offset+2])
            ext_len = lst2int(raw[ext_offset+2:ext_offset+4])
            if ext_type == 51:  # key section
                kex_group = tuple(raw[ext_offset+4:ext_offset+6])
                data['tls']['kex_group'] = describe_codepoint(
                    TLS_GROUPS_DICT, kex_group, 'unknown_group')
            if ext_type == 43:  # supported TLS versions
                vers_offset = ext_offset + 2
                # Two byte length for server HELO... (1 for client HELO)
                vers_ext_len = lst2int(raw[vers_offset:vers_offset+2])
                vers_offset += 2
                for i in range(0, _clamp_items(vers_ext_len, ext_section_len,
                                               vers_offset) * 2, 2):
                    supported_tls_versions.append(raw[vers_offset+i:vers_offset+i+2])
                # supported_versions carries GREASE too (RFC 8701). This
                # code was unreachable until the extension walk bound was
                # fixed, so the padding surfaced as a bogus 'ERR' version.
                data['tls']['tls_versions'] = [
                    get_tls_version(x) for x in supported_tls_versions
                    if not is_grease(x)]
            ext_offset += ext_len + 4
    if raw[tls_offset + 5] == 1:  # client helo
        data['ptype'] = 'client'
        len_ciphersuite_list = lst2int(raw[offset:offset+2])
        csuite_offset = offset + 2
        # Clamp to the record: the length field is attacker-controlled.
        csuite_end = min(csuite_offset + len_ciphersuite_list, limit)
        proposed_suites = raw[csuite_offset:csuite_end]
        ciphersuites = list(zip(proposed_suites[::2], proposed_suites[1::2]))
        data['tls']['ciphersuites'] = describe_codepoints(
            TLS_DICT, ciphersuites, 'unknown_ciphersuite')
        ext_offset = csuite_end
        ext_offset = ext_offset + 1 + lst2int(raw[ext_offset:ext_offset+1])  # compression method len, 1 byte
        ext_offset += 2  # extension length bytes
        # `while ext_offset < tls_len - 1` compared an absolute frame offset
        # against a record-relative length, so the walk stopped tls_offset + 6
        # bytes early and silently dropped whatever extensions sat at the end
        # of the hello -- supported_groups on 15 of 68 corpus ClientHellos,
        # sig_hash_alg on 13. `limit` is the real end of the record.
        seen_extensions = 0
        while ext_offset + 4 <= limit:
            seen_extensions += 1
            if seen_extensions > MAX_EXTENSIONS:
                PARSE_STATS['extension_cap_hit'] += 1
                break
            ext_type = lst2int(raw[ext_offset:ext_offset+2])
            ext_len = lst2int(raw[ext_offset+2:ext_offset+4])
            if ext_type == 22:  # EtM is enabled
                data['tls']['EtM'] = True
            else:
                data['tls']['EtM'] = False
            if ext_type == 43:  # supported TLS versions
                vers_offset = ext_offset + 4
                if vers_offset >= limit:
                    break
                vers_ext_len = raw[vers_offset]  # just one byte...
                vers_offset += 1
                for i in range(0, _clamp_items(vers_ext_len, limit,
                                               vers_offset) * 2, 2):
                    supported_tls_versions.append(raw[vers_offset+i:vers_offset+i+2])
                # supported_versions carries GREASE too (RFC 8701). This
                # code was unreachable until the extension walk bound was
                # fixed, so the padding surfaced as a bogus 'ERR' version.
                data['tls']['tls_versions'] = [
                    get_tls_version(x) for x in supported_tls_versions
                    if not is_grease(x)]
            if ext_type == 0:  # check if '0000' indicating server_name TLS parameter
                name_offset = ext_offset + 7 # shift 7 bytes to find length of hostname
                len_hostname = lst2int(raw[name_offset:name_offset+2]) # get length of hostname
                name_offset += 2  # skip over the length bytes we just enumerated
                # Clamp: a hostname length of 0xffff would otherwise pull in
                # everything after it, whatever that happened to be.
                name_end = min(name_offset + len_hostname, limit)
                data['tls']['hostname'] = lst2str(raw[name_offset:name_end])
            if ext_type == 10:  # supported ECC groups
                group_offset = ext_offset + 4
                group_list_len = lst2int(raw[group_offset:group_offset + 2])
                group_offset += 2
                for i in range(0, _clamp_items(group_list_len, limit,
                                               group_offset) * 2, 2):
                    supported_groups.append(tuple(raw[group_offset+i:group_offset+i+2]))
                data['tls']['groups'] = describe_codepoints(
                    TLS_GROUPS_DICT, supported_groups, 'unknown_group')
            if ext_type == 13: # supported Signature Algorithms
                sigalg_offset = ext_offset + 4
                sigalt_list_len = lst2int(raw[sigalg_offset:sigalg_offset + 2])
                sigalg_offset += 2
                for i in range(0, _clamp_items(sigalt_list_len, limit,
                                               sigalg_offset) * 2, 2):
                    supported_sigalgs.append(tuple(raw[sigalg_offset+i:sigalg_offset+i+2]))
                data['tls']['sigalgs'] = parse_sigalgs(supported_sigalgs)
            if ext_type == 51: # key share extension
                # The client offers a *list* of key shares, and Chrome and
                # Edge put a GREASE entry first (RFC 8701). Taking entry
                # zero therefore recorded the padding as the negotiated
                # group on every Chromium ClientHello; walk to the first
                # real group instead.
                shares_len = lst2int(raw[ext_offset+4:ext_offset+6])
                share_offset = ext_offset + 6
                share_end = min(share_offset + shares_len, limit)
                kex_group = None
                seen_shares = 0
                while share_offset + 4 <= share_end:
                    seen_shares += 1
                    if seen_shares > MAX_LIST_ITEMS:
                        PARSE_STATS['keyshare_cap_hit'] += 1
                        break
                    group = tuple(raw[share_offset:share_offset+2])
                    key_len = lst2int(raw[share_offset+2:share_offset+4])
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
    # next, attempt to get a cert if present...
    if "ptype" not in data.keys():
        # this means that it wasn't a hello packet, so drop
        return {}
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
