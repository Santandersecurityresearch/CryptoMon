[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

# CryptoMon

Network Cryptography Monitor - using eBPF, written in python.

**NB - This code is pre-production and is intended for demonstration purposes.**

This is an demonstration service that allows the interception and analysis of over-the-wire TLS cryptography. 

Cryptomon looks for port 443 traffic, and if found, looks for the 'hello' packets from the client and server. It parses the packet data and then stores it in a MongoDB database that can later be analysed.

The advantage of using network monitoring alongside the [CodeQL Source Code analysis](https://github.blog/2023-12-05-addressing-post-quantum-cryptography-with-codeql/) we have worked on previously, is that static analysis of code tells you what could be running, whilst over-the-wire monitoring tells you what is actually being negotiated. 

## Setup

This setup is designed to operate under Ubuntu 22.04 "jammy". 

Firstly, `git clone` this repository. The `ubuntu-setup.sh` script will install all the necessary files. 

If you wish to run this service all the time in the background, then you should look at running the `create-service.sh` script that creates a systemd service that continually monitors network traffic in the background. 

You will also need to make sure that mongodb is installed and running. Once this is done, you should connect to the instance with `mongosh` and run the following: 

```python
db.createCollection('cryptomon')
db.createUser({user: "cryptomonUser", pwd: passwordPrompt(), roles: [{ role: "readWrite", db: "cryptomon" }]})
```

This creates the `cryptomon` collection that the monitor will use to store information, as well as a read/write user for that database - this will prompt you to create a password.

Once this is done you may export these: 

```bash
export DB_URL="mongodb://cryptomonUser:<password>@<uri>:27017/cryptomon?retryWrites=true&w=majority"
export DB_NAME="cryptomon"
```

**OR** if you are using MongoDB Atlas or some other cloud service:

```bash
export DB_URL="mongodb+srv://<Connection URL>/cryptomon?retryWrites=true&w=majority"
export DB_NAME="cryptomon"
```

The `fapi/config/__init__.py` should pick these settings up. If, for whatever reason, these environment variables are not picked up, you can edit that file manually.

## Usage

Once everything is installed you can run the monitor and FastAPI with:

```bash
sudo python3 ./cryptomon.py -i <iface> &
python3 ./api.py
```

Where `<iface>` should be replaecd with the network interface to be monitored (`enp0s1` by default.)

If you have installed `cryptomon` as a service, then you do not need to run the first line. To check the monitor is working you can run `db.cryptomon.count({})` from `mongosh` to see if the record count is increasing. 

## FastAPI 

To access the FastAPI documentation go to `http://0.0.0.0:8000/docs` to find the documentation for the backend API.

## Example Data

### TLS Capture

A TLS client capture example:

```json
{
"_id": "6682cd75393bb4e863fc0c65",
"eth": {
    "src": {
    "ipv4": "192.168.64.5"
    },
    "dst": {
    "ipv4": "3.210.189.242"
    }
},
"tls": {
    "tls_versions": [
    "TLSv1.3",
    "TLSv1.2"
    ],
    "ciphersuites": [
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
    ],
    "EtM": false,
    "hostname": "ping.chartbeat.net",
    "groups": [
    "x25519",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "ffdhe2048",
    "ffdhe3072"
    ],
    "kex_group": "x25519",
    "sigalgs": [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "ecdsa_sha1",
    "rsa_pkcs1_sha1"
    ]
},
"ptype": "client",
"ts": 1719848309.166212
}
```

A TLS server hello capture example:

```json
{
"_id": "6682cd75393bb4e863fc0c66",
"eth": {
    "src": {
    "ipv4": "3.210.189.242"
    },
    "dst": {
    "ipv4": "192.168.64.5"
    }
},
"tls": {
    "tls_versions": "TLSv1.2",
    "ciphersuite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
},
"ptype": "server",
"ts": 1719848309.26233
}
```

Here is a sample server response with a certificate that was successfully parsed:

```json
[
    {
    "_id": "6687c791fc10affe7c563d01",
    "eth": {
      "src": {
        "ipv4": "52.72.184.67",
        "port": 443
      },
      "dst": {
        "ipv4": "192.168.64.5",
        "port": 38498
      }
    },
    "tls": {
      "tls_versions": "TLSv1.2",
      "ciphersuite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "certificate": [
        {
          "tbs_certificate": {
            "version": "v3",
            "serial_number": "03:11:2c:04:f0:46:dd:bd:89:fd:61:85:c1:70:cf:50:c6:04",
            "signature": {
              "algorithm": "sha256_rsa",
              "parameters": null
            },
            "issuer": {
              "country_name": "US",
              "organization_name": "Let's Encrypt",
              "common_name": "R3"
            },
            "validity": {
              "not_before": 1716956913,
              "not_after": 1724732912,
              "not_before_iso": "2024-05-29T04:28:33+00:00",
              "not_after_iso": "2024-08-27T04:28:32+00:00"
            },
            "subject": {
              "common_name": "compass.mongodb.com"
            },
            "subject_public_key_info": {
              "algorithm": {
                "algorithm": "rsa",
                "parameters": null
              },
              "public_key": {
                "modulus": "dc:4e:4b:6e:75:04:72:97:73:77:73:08:27:94:7f:ca:b5:2d:51:1a:bd:39:97:94:eb:a7:a5:94:c4:e2:4a:1c:5d:1b:01:6c:7e:d3:b0:4c:4f:7f:06:a5:84:6f:20:34:b3:d7:a2:d3:10:cf:29:f9:00:b6:14:76:02:85:0f:41:00:48:82:12:59:7e:51:50:43:8f:c2:41:e1:8f:4d:6c:66:02:2b:d2:cb:49:75:04:1d:0d:4b:6b:0c:f3:1a:65:d2:48:26:0e:a3:ca:d3:47:3b:1f:92:c3:e4:c7:b1:05:09:fc:b7:fd:a6:82:a2:97:41:67:b8:cb:89:91:3a:55:f9:26:61:37:2a:50:dd:13:44:50:51:54:13:5f:d5:cd:9e:b9:2d:3e:dc:f7:60:a0:53:ef:ee:a2:ef:ba:0e:93:24:2e:da:a3:c3:ff:13:3f:e2:67:1a:b6:8f:23:ce:67:00:d7:d3:cb:d7:b1:47:2c:a1:05:6f:d7:b8:9e:d3:00:cb:92:84:13:ea:5a:a8:63:89:aa:28:db:78:96:8e:cc:99:07:60:f7:f2:f0:95:88:3f:a0:ce:56:8c:b3:6e:1a:65:8f:69:10:a2:38:3e:02:ef:fd:eb:59:51:2a:d9:24:34:b0:d1:05:9d:96:31:46:f0:a6:fe:42:f2:62:36:15",
                "public_exponent": 65537
              }
            },
            "issuer_unique_id": null,
            "subject_unique_id": null,
            "extensions": [
              {
                "extn_id": "key_usage",
                "critical": true,
                "extn_value": [
                  "digital_signature",
                  "key_encipherment"
                ]
              },
              {
                "extn_id": "extended_key_usage",
                "critical": false,
                "extn_value": [
                  "server_auth",
                  "client_auth"
                ]
              },
              {
                "extn_id": "basic_constraints",
                "critical": true,
                "extn_value": {
                  "ca": false,
                  "path_len_constraint": null
                }
              },
              {
                "extn_id": "key_identifier",
                "critical": false,
                "extn_value": "51:9b:a2:cc:5b:eb:9e:40:b4:5e:a8:28:11:61:09:53:7e:90:6b:cb"
              },
              {
                "extn_id": "authority_key_identifier",
                "critical": false,
                "extn_value": {
                  "key_identifier": "14:2e:b3:17:b7:58:56:cb:ae:50:09:40:e6:1f:af:9d:8b:14:c2:c6",
                  "authority_cert_issuer": null,
                  "authority_cert_serial_number": null
                }
              },
              {
                "extn_id": "authority_information_access",
                "critical": false,
                "extn_value": [
                  {
                    "access_method": "ocsp",
                    "access_location": "http://r3.o.lencr.org"
                  },
                  {
                    "access_method": "ca_issuers",
                    "access_location": "http://r3.i.lencr.org/"
                  }
                ]
              },
              {
                "extn_id": "subject_alt_name",
                "critical": false,
                "extn_value": [
                  "compass.mongodb.com"
                ]
              },
              {
                "extn_id": "certificate_policies",
                "critical": false,
                "extn_value": [
                  {
                    "policy_identifier": "2.23.140.1.2.1",
                    "policy_qualifiers": null
                  }
                ]
              },
              {
                "extn_id": "signed_certificate_timestamp_list",
                "critical": false,
                "extn_value": "00:ef:00:75:00:48:b0:e3:6b:da:a6:47:34:0f:e5:6a:02:fa:9d:30:eb:1c:52:01:cb:56:dd:2c:81:d9:bb:bf:ab:39:d8:84:73:00:00:01:8f:c2:d2:50:8e:00:00:04:03:00:46:30:44:02:20:32:d5:e7:01:85:ca:28:af:85:8c:8d:b6:a0:54:c3:a0:a3:37:a5:f7:b9:b6:d2:57:ea:41:3e:96:40:1b:61:10:02:20:30:d7:2c:e2:7f:f9:88:21:20:24:d7:40:eb:cf:ab:28:9b:1d:d7:35:39:cd:63:74:8a:df:0c:e1:4c:a3:30:33:00:76:00:ee:cd:d0:64:d5:db:1a:ce:c5:5c:b7:9d:b4:cd:13:a2:32:87:46:7c:bc:ec:de:c3:51:48:59:46:71:1f:b5:9b:00:00:01:8f:c2:d2:50:90:00:00:04:03:00:47:30:45:02:20:33:20:f7:35:ea:79:55:0a:40:db:8f:9b:b8:4d:df:77:cb:bb:d9:4b:23:06:13:11:a8:13:ec:58:3a:60:0d:b2:02:21:00:eb:51:a7:0d:41:ac:ff:25:d6:ba:20:ee:29:2e:14:ea:93:e9:b3:4a:2d:43:20:54:9d:ae:b6:c7:34:ac:1c:be"
              }
            ],
            "serial_number_str": "267180169707331565834655439909840030320132"
          },
          "signature_algorithm": {
            "algorithm": "sha256_rsa",
            "parameters": null
          },
          "signature_value": "3b:69:19:7a:c0:3e:41:64:1b:34:bb:3e:eb:2d:05:ef:01:df:5a:23:f0:14:1f:c0:1c:0c:b3:2b:06:e7:d3:f9:c4:b1:8d:21:28:e3:ee:3c:73:b1:47:b0:1f:a4:e4:53:ed:55:0c:3a:41:7f:38:c8:7e:9a:5b:c4:fa:4a:0a:cd:b0:83:d0:5e:64:40:ae:4c:3a:1d:90:bb:4c:f3:af:e8:7e:b2:f9:68:11:b4:23:2f:b2:85:72:55:d0:ea:69:25:20:b0:72:c4:c3:f5:00:77:54:a6:46:f5:5e:7b:4d:21:34:43:c8:9e:c6:4b:88:4e:c3:64:9e:29:5d:0c:34:f5:db:38:f1:59:79:87:e7:a7:48:fc:14:d5:fd:d5:70:c9:8c:e9:55:5e:c8:76:95:49:fa:a6:c9:d2:4b:c5:8d:f6:93:9d:1e:0e:28:c6:d4:dd:7a:ce:f4:f8:5e:87:81:1c:aa:0f:f0:13:6a:c2:8c:67:35:c9:c4:14:37:ac:d1:70:ed:79:07:fb:b9:0b:c5:3e:b8:7a:3f:85:2f:80:eb:66:62:46:da:68:89:df:20:81:aa:2f:6d:6a:e3:00:3d:ef:de:73:b0:33:b2:e4:9b:a0:51:a1:ac:ca:30:60:fd:b2:b5:28:d2:08:fc:97:ee:f9:9b:19:5d:8e:53:09:b6:14"
        }
      ]
    },
    "ptype": "server",
    "ts": 1720174481.875246
  },
]
```

### SSH Capture

Sample SSH Server capture:

```json
{
"_id": "66840491591561a355709042",
"ptype": "server",
"eth": {
    "src": {
    "ipv4": "20.0.104.77"
    },
    "dst": {
    "ipv4": "192.168.64.5"
    }
},
"ssh": {
    "KEXalgs": [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "sntrup761x25519-sha512@openssh.com",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
    "kex-strict-s-v00@openssh.com"
    ],
    "ServerHostKeyAlgos": [
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
    "ssh-ed25519"
    ],
    "EncryptionAlgosClient2Server": [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com"
    ],
    "EncryptionAlgosServer2Client": [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com"
    ],
    "MACalgosClient2Server": [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1"
    ],
    "MACalgosServer2Client": [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1"
    ]
},
"ts": 1719927953.541072
}
```

A sample SSH Client capture:

```json
{
"_id": "66840492591561a355709043",
"ptype": "client",
"eth": {
    "src": {
    "ipv4": "192.168.64.5"
    },
    "dst": {
    "ipv4": "20.0.104.77"
    }
},
"ssh": {
    "KEXalgs": [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "sntrup761x25519-sha512@openssh.com",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
    "ext-info-c",
    "kex-strict-c-v00@openssh.com"
    ],
    "ServerHostKeyAlgos": [
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256"
    ],
    "EncryptionAlgosClient2Server": [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com"
    ],
    "EncryptionAlgosServer2Client": [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com"
    ],
    "MACalgosClient2Server": [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com"
    ]
},
"ts": 1719927954.565768
}
```
