import ipaddress
import sys

from cryptomon.data import TLS_HASH_ALGS, TLS_SIGALG_DICT, TLS_SIGN_ALGS


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
        if i not in TLS_SIGALG_DICT.keys():
            out_list.append(TLS_HASH_ALGS[i[0]] + " " + TLS_SIGN_ALGS[i[1]])
        else:
            out_list.append(TLS_SIGALG_DICT[i])
    return out_list


def help():
    print("execute: {0} <net_interface>".format(sys.argv[0]))
    print("e.g.: {0} eno1\n".format(sys.argv[0]))
    exit(1)


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
    return "ERR"


def lst2str(in_lst):
    return ''.join([chr(x) for x in in_lst])


def decimal_to_human(input_value):
    try:
        if isinstance(input_value, tuple):  # Check if input_value is a tuple which means this is an IPv6 address
            ip_string = str(ipaddress.IPv6Address(input_value))
        else:  # Assume IPv4
            decimal_ip = int(input_value)
            ip_string = str(ipaddress.IPv4Address(decimal_ip))
        return ip_string
    except ValueError:
        return "Invalid input"
