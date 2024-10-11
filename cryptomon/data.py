import csv
import os

TLS_DICT = {}


def get_tls_from_csv(csv_file):
    """
    Reads a CSV file containing TLS data and returns a dictionary of cipher suites.

    Args:
        csv_file (str): The path to the CSV file.

    Returns:
        dict: A dictionary where the keys are tuples of integers representing cipher suites,
              and the values are the corresponding descriptions.

    """
    try:
        with open(csv_file, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            data = [row for row in csv_reader]
    except FileNotFoundError:
        print(f"Error: The file {csv_file} was not found.")
        return {}
    except Exception as e:
        print(f"Error: {e}")
        return {}
    csuite_dict = {}
    for i in range(len(data)):
        value = data[i]['Value'].split(',')
        csuite_dict[tuple([int(x, 0) for x in value])] = data[i]['Description']
    return csuite_dict


cwd = os.getcwd() + '/'
TLS_DICT = get_tls_from_csv(cwd+'cryptomon/tls_ciphersuites.csv')


# TLSv1.3 Support Gropups (ext sec 10)
TLS_GROUPS_DICT = {(0x00, 0x01): "sect163k1",
                   (0x00, 0x02): "sect163r1",
                   (0x00, 0x03): "sect163r2",
                   (0x00, 0x04): "sect193r1",
                   (0x00, 0x05): "sect193r2",
                   (0x00, 0x06): "sect233k1",
                   (0x00, 0x07): "sect233r1",
                   (0x00, 0x08): "sect239k1",
                   (0x00, 0x09): "sect283k1",
                   (0x00, 0x0A): "sect283r1",
                   (0x00, 0x0B): "sect409k1",
                   (0x00, 0x0C): "sect409r1",
                   (0x00, 0x0D): "sect571k1",
                   (0x00, 0x0E): "sect571r1",
                   (0x00, 0x0F): "secp160k1",
                   (0x00, 0x10): "secp160r1",
                   (0x00, 0x11): "secp160r2",
                   (0x00, 0x12): "secp192k1",
                   (0x00, 0x13): "secp192r1",
                   (0x00, 0x14): "secp224k1",
                   (0x00, 0x15): "secp224r1",
                   (0x00, 0x16): "secp256k1",
                   (0x00, 0x17): "secp256r1",
                   (0x00, 0x18): "secp384r1",
                   (0x00, 0x19): "secp521r1",
                   (0x00, 0x1A): "brainpoolP256r1",
                   (0x00, 0x1B): "brainpoolP384r1",
                   (0x00, 0x1C): "brainpoolP512r1",
                   (0x00, 0x1D): "x25519",
                   (0x00, 0x1E): "x448",
                   (0x00, 0x1F): "brainpoolP256r1tls13",
                   (0x00, 0x20): "brainpoolP384r1tls13",
                   (0x00, 0x21): "brainpoolP512r1tls13",
                   (0x00, 0x22): "GC256A",
                   (0x00, 0x23): "GC256B",
                   (0x00, 0x24): "GC256C",
                   (0x00, 0x25): "GC256D",
                   (0x00, 0x26): "GC512A",
                   (0x00, 0x27): "GC512B",
                   (0x00, 0x28): "GC512C",
                   (0x00, 0x29): "curveSM2",
                   (0x01, 0x00): "ffdhe2048",
                   (0x01, 0x01): "ffdhe3072",
                   (0x01, 0x02): "ffdhe4096",
                   (0x01, 0x03): "ffdhe6144",
                   (0x01, 0x04): "ffdhe8192",
                   (0x63, 0x99): "X25519Kyber768Draft00",
                   (0x63, 0x9A): "SecP256r1Kyber768Draft00",
                   (0xFF, 0x01): "arbitrary_explicit_prime_curves",
                   (0xFF, 0x02): "arbitrary_explicit_char2_curves"}


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
