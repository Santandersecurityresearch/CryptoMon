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


def parse_tls(raw, magic=1):
    """Parse one TLS handshake frame. Returns {} if it is not a hello."""
    data = {}
    supported_groups = []
    supported_sigalgs = []
    supported_tls_versions = []

    data['eth'], tls_offset = decode_ipv4_tcp(raw)
    sess_id_len = raw[tls_offset+43]
    data['tls'] = {}
    data['tls']['tls_versions'] = get_tls_version(raw[tls_offset + 9: tls_offset + 11])
    tls_len = lst2int(raw[tls_offset + 3: tls_offset + 5])
    # the 44 in the next line is the various declarations of TLS type plus a 32-byte random value.
    offset = tls_offset + 44 + sess_id_len
    if raw[tls_offset + 5] == 2:  # server helo
        data['ptype'] = 'server'
        negotiated_suite = tuple(raw[offset:offset+2])
        data['tls']['ciphersuite'] = describe_codepoint(
            TLS_DICT, negotiated_suite, 'unknown_ciphersuite')
        ext_offset = offset + 5  # SKIP negotiated suite (2 bytes), TLS section length (2 bytes) and compression method (1 byte)
        ext_section_len = ext_offset + lst2int(raw[offset+3:offset+5])
        while ext_offset < ext_section_len:
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
                for i in range(0, vers_ext_len, 2):
                    supported_tls_versions.append(raw[vers_offset+i:vers_offset+i+2])
                data['tls']['tls_versions'] = [get_tls_version(x) for x in supported_tls_versions]
            ext_offset += ext_len + 4
    if raw[tls_offset + 5] == 1:  # client helo
        data['ptype'] = 'client'
        len_ciphersuite_list = lst2int(raw[offset:offset+2])
        csuite_offset = offset + 2
        proposed_suites = raw[csuite_offset:csuite_offset + len_ciphersuite_list]
        ciphersuites = list(zip(proposed_suites[::2], proposed_suites[1::2]))
        data['tls']['ciphersuites'] = describe_codepoints(
            TLS_DICT, ciphersuites, 'unknown_ciphersuite')
        ext_offset = csuite_offset + len_ciphersuite_list
        ext_offset = ext_offset + 1 + lst2int(raw[ext_offset:ext_offset+1])  # compression method len, 1 byte
        ext_offset += 2  # extension length bytes
        while ext_offset < tls_len-1:
            ext_type = lst2int(raw[ext_offset:ext_offset+2])
            ext_len = lst2int(raw[ext_offset+2:ext_offset+4])
            if ext_type == 22:  # EtM is enabled
                data['tls']['EtM'] = True
            else:
                data['tls']['EtM'] = False
            if ext_type == 43:  # supported TLS versions
                vers_offset = ext_offset + 4
                vers_ext_len = raw[vers_offset:vers_offset+1][0]  # just one byte...
                vers_offset += 1
                for i in range(0, vers_ext_len, 2):
                    supported_tls_versions.append(raw[vers_offset+i:vers_offset+i+2])
                data['tls']['tls_versions'] = [get_tls_version(x) for x in supported_tls_versions]
            if ext_type == 0:  # check if '0000' indicating server_name TLS parameter
                name_offset = ext_offset + 7 # shift 7 bytes to find length of hostname
                len_hostname = lst2int(raw[name_offset:name_offset+2]) # get length of hostname
                name_offset += 2  # skip over the length bytes we just enumerated
                data['tls']['hostname'] = lst2str(raw[name_offset:name_offset+len_hostname])
            if ext_type == 10:  # supported ECC groups
                group_offset = ext_offset + 4
                group_list_len = lst2int(raw[group_offset:group_offset + 2])
                group_offset += 2
                for i in range(0, group_list_len, 2):
                    supported_groups.append(tuple(raw[group_offset+i:group_offset+i+2]))
                data['tls']['groups'] = describe_codepoints(
                    TLS_GROUPS_DICT, supported_groups, 'unknown_group')
            if ext_type == 13: # supported Signature Algorithms
                sigalg_offset = ext_offset + 4
                sigalt_list_len = lst2int(raw[sigalg_offset:sigalg_offset + 2])
                sigalg_offset += 2
                for i in range(0, sigalt_list_len, 2):
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
                share_end = share_offset + shares_len
                kex_group = None
                while share_offset + 4 <= share_end:
                    group = tuple(raw[share_offset:share_offset+2])
                    key_len = lst2int(raw[share_offset+2:share_offset+4])
                    if not is_grease(group):
                        kex_group = group
                        break
                    PARSE_STATS['grease_filtered'] += 1
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
