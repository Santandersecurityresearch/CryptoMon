import ipaddress
import sys
import jc

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
    return ''.join('{:02x}'.format(x) for x in in_lst)


def lst2str(in_lst):
    return ''.join([chr(x) for x in in_lst])


def decimal_to_human(input_value):
    try:
        decimal_ip = int(input_value)
        ip_string = str(ipaddress.IPv4Address(decimal_ip))
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
    try:
        cert_len = lst2int(in_array[match+7:match+10])
        cert_begin = match + 10
        if in_array[cert_begin] != 0x30:  # something is wrong
            return output
        cert_list = in_array[cert_begin:cert_begin+cert_len]
        # print(''.join('{:02x}'.format(x) for x in cert_list))
        # cert_data = x509.load_der_x509_certificate(bytes(cert_list))
        output = jc.parse('x509_cert', bytes(cert_list))
    except:
        print("oops")
        pass
    print("SUCCESS!")
    return output
