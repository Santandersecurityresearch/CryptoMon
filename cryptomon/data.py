# 

import csv
import os

TLS_DICT = {}


def get_tls_from_csv(csv_file):
    with open(csv_file, 'r') as file:
        csv_reader = csv.DictReader(file)
        data = [row for row in csv_reader]
    csuite_dict = {}
    for i in range(len(data)):
        value = data[i]['Value'].split(',')
        csuite_dict[tuple([int(x, 0) for x in value])] = data[i]['Description']
    return csuite_dict


cwd = os.getcwd() + '/'
TLS_DICT = get_tls_from_csv(cwd+'cryptomon/tls_ciphersuites.csv')


# TLSv1.3 Support Gropups (ext sec 10)
TLS_GROUPS_DICT = {(0x00, 0x17): "secp256r1", (0x00, 0x18): "secp384r1", (0x00, 0x19): "secp521r1", 
                   (0x00, 0x1D): "x25519", (0x00, 0x1E): "x448",
                   (0x01, 0x00): "ffdhe2048", (0x01, 0x01): "ffdhe3072", (0x01, 0x02): "ffdhe4096", 
                   (0x01, 0x03): "ffdhe6144", (0x01, 0x04): "ffdhe8192"}


# TLSv1.3 Signature Algorithms (ext sec 13)
TLS_SIGALG_DICT = {(0x02, 0x01): "rsa_pkcs1_sha1",
                   (0x02, 0x03): "ecdsa_sha1",
                   (0x04, 0x01): "rsa_pkcs1_sha256",
                   (0x04, 0x03): "ecdsa_secp256r1_sha256",
                   (0x04, 0x20): "rsa_pkcs1_sha256_legacy",
                   (0x05, 0x01): "rsa_pkcs1_sha384",
                   (0x05, 0x03): "ecdsa_secp384r1_sha384",
                   (0x05, 0x20): "rsa_pkcs1_sha384_legacy",
                   (0x06, 0x01): "rsa_pkcs1_sha512",
                   (0x06, 0x03): "ecdsa_secp521r1_sha512",
                   (0x06, 0x20): "rsa_pkcs1_sha512_legacy",
                   (0x07, 0x04): "eccsi_sha256",
                   (0x07, 0x05): "iso_ibs1",
                   (0x07, 0x06): "iso_ibs2",
                   (0x07, 0x07): "iso_chinese_ibs",
                   (0x07, 0x08): "sm2sig_sm3",
                   (0x07, 0x09): "gostr34102012_256a",
                   (0x07, 0x0A): "gostr34102012_256b",
                   (0x07, 0x0B): "gostr34102012_256c",
                   (0x07, 0x0C): "gostr34102012_256d",
                   (0x07, 0x0D): "gostr34102012_512a",
                   (0x07, 0x0E): "gostr34102012_512b",
                   (0x07, 0x0F): "gostr34102012_512c",
                   (0x08, 0x04): "rsa_pss_rsae_sha256",
                   (0x08, 0x05): "rsa_pss_rsae_sha384",
                   (0x08, 0x06): "rsa_pss_rsae_sha512",
                   (0x08, 0x07): "ed25519",
                   (0x08, 0x08): "ed448",
                   (0x08, 0x09): "rsa_pss_pss_sha256",
                   (0x08, 0x0A): "rsa_pss_pss_sha384",
                   (0x08, 0x0B): "rsa_pss_pss_sha512",
                   (0x08, 0x1A): "ecdsa_brainpoolP256r1tls13_sha256",
                   (0x08, 0x1B): "ecdsa_brainpoolP384r1tls13_sha384",
                   (0x08, 0x1C): "ecdsa_brainpoolP512r1tls13_sha512"}


TLS_HASH_ALGS = {1: "MD5", 2: "SHA1", 3: "SHA224", 4: "SHA256",
                 5: "SHA384", 6: "SHA512"}


TLS_SIGN_ALGS = {1: "RSA", 2: "DSA", 3: "ECDSA", 7: "ed25519", 8: "ed448",
                 64: "gostr34102012_256", 65: "gostr34102012_512"}


SSH_SECTIONS = ['KEXalgs', 'ServerHostKeyAlgos', "EncryptionAlgosClient2Server",
                "EncryptionAlgosServer2Client", "MACalgosClient2Server",
                "MACalgosServer2Client"]
