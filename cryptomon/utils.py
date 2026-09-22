import collections
import ipaddress
import sys

try:
    import jc
except ImportError:  # only cert_guess() needs it; see cert_guess() below
    jc = None

from cryptomon.data import TLS_HASH_ALGS, TLS_SIGALG_DICT, TLS_SIGN_ALGS


# Per-run parse counters. A run that parses nothing should not look like a run
# that saw nothing, so every value we fail to recognise is counted here rather
# than discarded. These live at module scope rather than on CryptoMon so that
# the parsers stay callable without an instance -- the property the test
# harness depends on.
PARSE_STATS = collections.Counter()

_warned = set()


def reset_parse_stats():
    """Zero the parse counters, e.g. at the start of a run or a test."""
    PARSE_STATS.clear()


def is_grease(value):
    """
    True if a two-byte code point is a GREASE value (RFC 8701).

    GREASE is the sixteen values 0x0a0a, 0x1a1a ... 0xfafa -- both bytes equal,
    low nibble 0xa. Clients sprinkle them through their ciphersuite, group,
    signature-algorithm, version and extension lists so that middleboxes stay
    tolerant of values they do not know. They are not algorithms, and counting
    them as such skews every per-algorithm statistic.
    """
    try:
        high, low = value
        return high == low and (high & 0x0f) == 0x0a
    except (TypeError, ValueError):
        # Unpacking succeeds for any 2-element iterable, including a 2-char
        # string, so the bitwise test has to be inside the guard too.
        return False


def describe_codepoint(table, value, stat=None):
    """
    Name a two-byte code point. Never raises.

    Unknown values keep their code point in the label rather than collapsing
    into one bucket, so that an unrecognised suite can still be identified
    afterwards, and are counted under `stat`.
    """
    try:
        return table[value]
    except (KeyError, TypeError):
        pass
    if is_grease(value):
        # A peer should not *select* a GREASE value; if one does, say so.
        PARSE_STATS['grease_unexpected'] += 1
        return 'GREASE'
    if stat:
        PARSE_STATS[stat] += 1
    try:
        return 'Unknown (0x{:02x}{:02x})'.format(value[0], value[1])
    except (TypeError, IndexError):
        return 'Unknown'


def describe_codepoints(table, values, stat=None):
    """Name a list of code points, dropping GREASE padding as it goes."""
    out = []
    for value in values:
        if is_grease(value):
            PARSE_STATS['grease_filtered'] += 1
            continue
        out.append(describe_codepoint(table, value, stat))
    return out


def lst2int(in_lst):
    lenlst = len(in_lst)
    if lenlst > 8:
        return 0
    out_int = 0
    lenlst -= 1
    for i in range(len(in_lst)):
        out_int += (in_lst[i] << (8*(lenlst-i)))
    return out_int


def parse_sigalgs(sigalg_list):
    out_list = []
    for i in sigalg_list:
        if is_grease(i):
            PARSE_STATS['grease_filtered'] += 1
            continue
        if i in TLS_SIGALG_DICT:
            out_list.append(TLS_SIGALG_DICT[i])
            continue
        # Otherwise compose the legacy TLS 1.2 hash/signature pair. Both halves
        # are attacker-supplied, so neither lookup may be a bare subscript: a
        # KeyError here escapes the parser entirely and loses the handshake.
        hash_alg = TLS_HASH_ALGS.get(i[0])
        sign_alg = TLS_SIGN_ALGS.get(i[1])
        if hash_alg and sign_alg:
            out_list.append(hash_alg + " " + sign_alg)
        else:
            PARSE_STATS['unknown_sigalg'] += 1
            out_list.append('Unknown (0x{:02x}{:02x})'.format(i[0], i[1]))
    return out_list


def help():
    print("execute: {0} <net_interface>".format(sys.argv[0]))
    print("e.g.: {0} eno1\n".format(sys.argv[0]))
    sys.exit(1)


def get_tls_version(in_lst):
    if in_lst[0] != 3:
        return "ERR"
    match in_lst[1]:
        case 1:
            return "TLSv1.0"
        case 2:
            return "TLSv1.1"
        case 3:
            return "TLSv1.2"
        case 4:
            return "TLSv1.3"
    return ''.join('{:02x}'.format(x) for x in in_lst)


def lst2str(in_lst):
    return ''.join([chr(x) for x in in_lst])


def decimal_to_human(input_value):
    try:
        decimal_ip = int(input_value)
        if decimal_ip <= 0xFFFFFFFF:
            ip_string = str(ipaddress.IPv4Address(decimal_ip))
        else:
            ip_string = str(ipaddress.IPv6Address(decimal_ip))
        return ip_string
    except ValueError:
        return "Invalid input"


def cert_guess(in_array):
    match = 0
    for i in range(len(in_array)):
        if in_array[i] == 0x0b:
            # look for a SEQUENCE 0x30, 0x82
            # as certificates are looong, and then
            # what should be the first 0x30 after that.
            if in_array[i+10] == 0x30 and \
               in_array[i+11] == 0x82 and \
               in_array[i+14] == 0x30:
                match = i
                break  # break out and try the cert
    output = {}
    if match == 0:
        return output  # no certificato
    if jc is None:
        PARSE_STATS['cert_no_parser'] += 1
        if 'jc' not in _warned:      # once per run, not once per packet
            _warned.add('jc')
            print("[!] jc is not installed, so certificates cannot be parsed. "
                  "Install it with `pip install jc`.", file=sys.stderr)
        return output
    try:
        cert_len = lst2int(in_array[match+7:match+10])
        cert_begin = match + 10
        if in_array[cert_begin] != 0x30:  # something is wrong
            return output
        cert_list = in_array[cert_begin:cert_begin+cert_len]
        # print(''.join('{:02x}'.format(x) for x in cert_list))
        # cert_data = x509.load_der_x509_certificate(bytes(cert_list))
        output = jc.parse('x509_cert', bytes(cert_list))
        PARSE_STATS['cert_parsed'] += 1
    except Exception:
        # Counted rather than printed: cert_guess runs on every packet, and a
        # chain split across TCP segments is the common case, not an anomaly.
        PARSE_STATS['cert_malformed'] += 1
    return output
