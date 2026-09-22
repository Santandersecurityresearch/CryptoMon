"""
SSH enrichment: banners, host key sizes, post-quantum markers.

**Every byte in this file was constructed here.** There is no SSH traffic in
the committed fixtures and none in the corpus, so nothing below was measured
on captured traffic and nothing below should be read as evidence about real
deployments. The packets are built from RFC 4253 (sections 4.2, 5, 6, 6.6),
RFC 4419 section 5 and RFC 5656 section 3.1, which is also the only thing
they prove: that this parser agrees with those documents.

The host key sizes are the reason for the file. A key size read wrong is
worse than a key size not read at all -- "RSA-2056" is a number nobody can
act on -- so the mpint cases below are deliberately the awkward ones.
"""
import json
import random

import pytest

from cryptomon.analysis import CLASSICAL, HYBRID, UNKNOWN
from cryptomon.data import SSH_SECTIONS
from cryptomon.ssh_enrichment import (MAX_BANNER_LEN, MAX_PACKETS,
                                      classify_kex_algorithms,
                                      describe_ssh_session, mpint_bits,
                                      parse_banner, parse_host_key,
                                      parse_kex_reply)
from cryptomon.utils import PARSE_STATS, reset_parse_stats

pytestmark = pytest.mark.smoke


# --------------------------------------------------------------------------
# building SSH by hand
# --------------------------------------------------------------------------
def ssh_string(value):
    """RFC 4253 section 5: uint32 length, then the bytes."""
    return len(value).to_bytes(4, 'big') + value


def mpint(value):
    """
    RFC 4253 section 5: two's complement big-endian, shortest form.

    `(bit_length + 8) // 8` is ceil(bits/8) plus one byte whenever the top
    bit of that byte would be set -- which is exactly when a positive number
    needs the leading zero that makes parsing it a trap.
    """
    if value == 0:
        return ssh_string(b'')
    return ssh_string(value.to_bytes((value.bit_length() + 8) // 8, 'big'))


def odd_prime_like(bits):
    """An integer of exactly `bits` bits. Not prime, and it does not need
    to be: only its length is ever read."""
    return (1 << (bits - 1)) | 1


def rsa_blob(bits, exponent=65537, key_type=b'ssh-rsa'):
    return (ssh_string(key_type) + mpint(exponent)
            + mpint(odd_prime_like(bits)))


def dss_blob(bits=1024):
    return (ssh_string(b'ssh-dss') + mpint(odd_prime_like(bits))
            + mpint(odd_prime_like(160)) + mpint(odd_prime_like(bits - 1))
            + mpint(odd_prime_like(bits - 1)))


def ed25519_blob():
    return ssh_string(b'ssh-ed25519') + ssh_string(bytes(32))


def ecdsa_blob(curve=b'nistp256', point_len=65, name=None):
    return (ssh_string(name or b'ecdsa-sha2-' + curve) + ssh_string(curve)
            + ssh_string(b'\x04' + bytes(point_len - 1)))


def cert_blob(inner):
    """
    An OpenSSH host certificate wrapping a key: type, nonce, then the base
    key's own fields.
    """
    type_end = 4 + int.from_bytes(inner[:4], 'big')
    key_type = inner[4:type_end]
    return (ssh_string(key_type + b'-cert-v01@openssh.com')
            + ssh_string(bytes(32)) + inner[type_end:])


def ssh_packet(payload):
    """
    RFC 4253 section 6 framing: the packet is a multiple of 8 bytes and the
    padding is at least 4.
    """
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    body = bytes([padding]) + payload + bytes(padding)
    return len(body).to_bytes(4, 'big') + body


def ecdh_reply(blob):
    """SSH_MSG_KEX_ECDH_REPLY: K_S, Q_S, signature (RFC 5656 section 4)."""
    return ssh_packet(bytes([31]) + ssh_string(blob)
                      + ssh_string(b'\x04' + bytes(64))
                      + ssh_string(b'signature'))


def gex_group():
    """
    SSH_MSG_KEX_DH_GEX_GROUP, which is *also* message 31 (RFC 4419 section
    5) and carries `mpint p, mpint g` -- no host key anywhere in it.
    """
    return ssh_packet(bytes([31]) + mpint(odd_prime_like(2048)) + mpint(2))


def gex_reply(blob):
    """SSH_MSG_KEX_DH_GEX_REPLY: K_S, f, signature."""
    return ssh_packet(bytes([33]) + ssh_string(blob)
                      + mpint(odd_prime_like(2047))
                      + ssh_string(b'signature'))


KEX_LISTS = [b'curve25519-sha256,sntrup761x25519-sha512@openssh.com',
             b'rsa-sha2-512,ssh-ed25519',
             b'chacha20-poly1305@openssh.com',
             b'chacha20-poly1305@openssh.com',
             b'hmac-sha2-256', b'hmac-sha2-256',
             b'none', b'none', b'', b'']


def kexinit(lists=None):
    payload = bytes([20]) + bytes(16)
    for entry in (lists or KEX_LISTS):
        payload += ssh_string(entry)
    return ssh_packet(payload + b'\x00' + bytes(4))


def server_stream(blob, banner=b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5'):
    """A whole server-to-client stream up to NEWKEYS."""
    return (banner + b'\r\n' + kexinit() + ecdh_reply(blob)
            + ssh_packet(bytes([21])))


# --------------------------------------------------------------------------
# banners
# --------------------------------------------------------------------------
def test_an_openssh_banner_splits_into_software_version_and_comment():
    """
    The banner is the only thing in an SSH handshake that says which
    implementation is speaking. Keeping it as one opaque string means the
    answer to "which hosts still run OpenSSH 7.x" is a substring search
    someone has to invent; splitting it once, here, means it is a field.
    """
    parsed = parse_banner(b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5')
    assert parsed == {'banner': 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5',
                      'protocol_version': '2.0',
                      'software': 'OpenSSH',
                      'software_version': '9.6p1',
                      'comment': 'Ubuntu-3ubuntu13.5'}


@pytest.mark.parametrize("banner,software,version", [
    (b'SSH-2.0-dropbear_2022.83', 'dropbear', '2022.83'),
    (b'SSH-2.0-libssh_0.10.6', 'libssh', '0.10.6'),
    # libssh has also shipped a minus sign here, which RFC 4253 forbids in
    # softwareversion. Tolerated on input: refusing to name the software
    # would lose more than accepting a non-conformant separator does.
    (b'SSH-2.0-libssh-0.7.0', 'libssh', '0.7.0'),
    (b'SSH-1.99-OpenSSH_4.3', 'OpenSSH', '4.3'),
    (b'SSH-2.0-OpenSSH_for_Windows_9.5', 'OpenSSH_for_Windows', '9.5'),
])
def test_implementations_other_than_openssh_split_too(banner, software,
                                                      version):
    parsed = parse_banner(banner)
    assert (parsed['software'], parsed['software_version']) == (software,
                                                                version)


def test_a_banner_with_no_comment_has_no_comment():
    """
    The comment is optional (RFC 4253 section 4.2). An empty string and
    "there was no comment" are different statements, and only one of them is
    true here.
    """
    parsed = parse_banner(b'SSH-2.0-dropbear_2022.83')
    assert parsed['comment'] is None


def test_a_banner_with_no_version_keeps_the_whole_name():
    """Inventing a version split for `SSH-2.0-Go` would be a guess."""
    parsed = parse_banner(b'SSH-2.0-Go')
    assert parsed['software'] == 'Go'
    assert parsed['software_version'] is None


def test_an_over_long_banner_is_cut_to_the_rfcs_limit():
    """
    RFC 4253 caps the identification line at 255 bytes. A peer that sends
    more is sending something else, and carrying it whole would put an
    unbounded attacker-chosen string into every downstream consumer -- a CSV
    cell, a JSON document, a log line.
    """
    reset_parse_stats()
    parsed = parse_banner(b'SSH-2.0-OpenSSH_9.6 ' + b'A' * 4096)
    assert len(parsed['banner']) == MAX_BANNER_LEN
    assert PARSE_STATS['ssh_banner_too_long'] == 1


def test_control_characters_in_a_banner_are_escaped_not_passed_through():
    """
    The bytes are the peer's choice. A banner carrying an ANSI escape is
    terminal injection the moment anyone cats the output, and a NUL in it is
    a truncation waiting for whoever compares two of them. Escaped rather
    than stripped, so the anomaly stays visible and reversible.
    """
    reset_parse_stats()
    parsed = parse_banner(b'SSH-2.0-OpenSSH_9.6\x1b[31m\x00')
    assert '\x1b' not in parsed['banner']
    assert '\x00' not in parsed['banner']
    assert '\\x1b' in parsed['banner']
    assert PARSE_STATS['nonprintable_ssh'] == 1


def test_something_that_is_not_a_banner_is_refused_and_counted():
    """
    Port 22 carries whatever anyone sends to it. A refusal keeps the line
    for whoever reads the output -- it is evidence -- while naming nothing
    it could not read.
    """
    reset_parse_stats()
    parsed = parse_banner(b'HTTP/1.1 200 OK')
    assert parsed['banner'] == 'HTTP/1.1 200 OK'
    assert parsed['protocol_version'] is None
    assert parsed['software'] is None
    assert PARSE_STATS['ssh_banner_malformed'] == 1


def test_a_banner_is_read_from_a_whole_stream():
    """The caller holds a reassembled stream, not a tidy line."""
    parsed = parse_banner(server_stream(ed25519_blob()))
    assert parsed['software'] == 'OpenSSH'


# --------------------------------------------------------------------------
# mpints: the off-by-eight
# --------------------------------------------------------------------------
def test_a_leading_zero_mpint_is_not_eight_bits_longer():
    """
    The trap this module exists to avoid. An RSA modulus has its top bit set
    by construction, so its two's complement encoding always carries a
    leading zero byte to stay positive: 2048 bits arrive as 257 bytes, and
    `len(raw) * 8` reports 2056. There is no such thing as RSA-2056, and a
    key size that is wrong by 8 bits is a key size nobody can act on.
    """
    encoded = mpint(odd_prime_like(2048))
    assert len(encoded) - 4 == 257            # 256 bytes plus the sign byte
    assert mpint_bits(encoded[4:]) == 2048
    assert parse_host_key(rsa_blob(2048))['key_size'] == 2048


def test_an_mpint_without_a_leading_zero_is_measured_the_same_way():
    """
    The other half of the same test: a 2047-bit modulus needs no sign byte,
    so it arrives in 256 bytes. A parser that "corrected" for the leading
    zero unconditionally would now be wrong by 8 in the other direction.
    """
    encoded = mpint(odd_prime_like(2047))
    assert len(encoded) - 4 == 256
    assert mpint_bits(encoded[4:]) == 2047


def test_an_empty_mpint_is_zero_bits():
    assert mpint_bits(b'') == 0


# --------------------------------------------------------------------------
# host key types and sizes
# --------------------------------------------------------------------------
@pytest.mark.parametrize("blob,key_type,size,curve", [
    (rsa_blob(2048), 'ssh-rsa', 2048, None),
    (rsa_blob(3072), 'ssh-rsa', 3072, None),
    (rsa_blob(4096), 'ssh-rsa', 4096, None),
    (ed25519_blob(), 'ssh-ed25519', 256, None),
    (ecdsa_blob(b'nistp256'), 'ecdsa-sha2-nistp256', 256, 'nistp256'),
    (ecdsa_blob(b'nistp384', 97), 'ecdsa-sha2-nistp384', 384, 'nistp384'),
    # 521, not 512: P-521's field is 2**521 - 1, and rounding it would be a
    # wrong number stated confidently.
    (ecdsa_blob(b'nistp521', 133), 'ecdsa-sha2-nistp521', 521, 'nistp521'),
    (dss_blob(1024), 'ssh-dss', 1024, None),
    (dss_blob(2048), 'ssh-dss', 2048, None),
])
def test_host_key_sizes_are_read_off_the_wire(blob, key_type, size, curve):
    """
    The whole point of PR-33, and the same argument pcapscan.certificates
    makes about X.509: "RSA" says nothing about quantum vulnerability,
    "RSA-2048" says everything, and the size is not in the KEXINIT anywhere.
    `ssh-rsa` in ServerHostKeyAlgos is a name, not a modulus.
    """
    parsed = parse_host_key(blob)
    assert parsed['error'] is None
    assert parsed['key_type'] == key_type
    assert parsed['key_size'] == size
    assert parsed['curve'] == curve
    assert parsed['label'] == '{0}-{1}'.format(key_type, size)
    assert parsed['fingerprint_sha256'].startswith('SHA256:')


def test_a_dss_key_is_sized_by_p_and_not_by_q():
    """
    q is 160 bits whatever p is, so a walk that read the wrong mpint would
    report every DSA host key ever generated as 160-bit -- plausible enough
    to go unnoticed and wrong by an order of magnitude.
    """
    assert parse_host_key(dss_blob(2048))['key_size'] == 2048


def test_an_rsa_signature_algorithm_still_names_an_rsa_key():
    """
    RFC 8332: `rsa-sha2-256` and `rsa-sha2-512` are SHA-2 *signatures* over
    an ordinary RSA key. A server that advertises only those has not stopped
    using RSA, and its modulus is still what decides how urgent it is.
    """
    parsed = parse_host_key(rsa_blob(3072, key_type=b'rsa-sha2-512'))
    assert parsed['key_size'] == 3072
    assert parsed['verdict'] == CLASSICAL


def test_an_openssh_certificate_host_key_is_sized_through_its_nonce():
    """
    A certificate blob puts a nonce between the type name and the key. Not
    skipping it reads the nonce as `e` and `e` as `n`, which does not fail
    -- it reports a 17-bit RSA key, confidently.
    """
    parsed = parse_host_key(cert_blob(rsa_blob(4096)))
    assert parsed['key_type'] == 'ssh-rsa-cert-v01@openssh.com'
    assert parsed['key_size'] == 4096


def test_fido_host_keys_are_sized_by_their_algorithm():
    blob = (ssh_string(b'sk-ssh-ed25519@openssh.com') + ssh_string(bytes(32))
            + ssh_string(b'ssh:'))
    assert parse_host_key(blob)['key_size'] == 256


# --------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cut", [0, 1, 4, 7, 11, 16, 40, 120, 250])
def test_a_truncated_host_key_blob_is_refused_rather_than_guessed(cut):
    """
    A handshake split across TCP segments is the normal case, not an
    anomaly, so a blob that stops part way through has to be survivable. It
    must also not produce a number: a truncated 4096-bit key silently
    reported as 960-bit would be worse than no answer at all.
    """
    reset_parse_stats()
    parsed = parse_host_key(rsa_blob(4096)[:cut])
    assert parsed['key_size'] is None
    assert parsed['error'] is not None
    assert sum(PARSE_STATS.values()) >= 1


def test_a_blob_that_is_not_a_host_key_at_all_is_refused():
    """An mpint misread as a type name is hundreds of bytes long."""
    reset_parse_stats()
    parsed = parse_host_key(mpint(odd_prime_like(2048)))
    assert parsed['error'] == 'not_a_host_key'
    assert PARSE_STATS['ssh_host_key_malformed'] == 1


def test_an_unknown_key_type_is_named_and_counted_not_sized():
    """
    An unrecognised key type is a gap in this module's table, not a finding
    about the traffic -- the distinction cryptomon.analysis draws for
    `unknown`. The name is kept so that the gap can be closed afterwards.
    """
    reset_parse_stats()
    parsed = parse_host_key(ssh_string(b'ssh-newthing') + ssh_string(b'key'))
    assert parsed['key_type'] == 'ssh-newthing'
    assert parsed['key_size'] is None
    assert parsed['error'] == 'unknown_key_type'
    assert PARSE_STATS['ssh_host_key_unknown_type'] == 1


def test_an_ecdsa_blob_whose_inner_curve_disagrees_is_refused():
    """
    RFC 5656 section 3.1 names the curve twice. Taking the size from the
    type name alone would report 384 bits for a key that is not one.
    """
    reset_parse_stats()
    blob = ecdsa_blob(b'nistp256', name=b'ecdsa-sha2-nistp384')
    assert parse_host_key(blob)['error'] == 'curve_mismatch'
    assert PARSE_STATS['ssh_host_key_curve_mismatch'] == 1


def test_host_key_parsing_never_raises_on_mutated_input():
    """
    Every length field in a host key blob is the peer's choice. The parser
    is reached from a capture, so an exception here is a lost session at
    best -- the same property tests/test_fuzz.py holds parse_ssh_stream to.
    """
    rnd = random.Random(20260922)
    seed = bytearray(rsa_blob(2048))
    for _ in range(500):
        blob = bytearray(seed)
        for _ in range(rnd.randint(1, 8)):
            blob[rnd.randrange(len(blob))] = rnd.randrange(256)
        parsed = parse_host_key(bytes(blob)[:rnd.randrange(1, len(blob))])
        assert isinstance(parsed, dict)


# --------------------------------------------------------------------------
# finding the reply in a stream
# --------------------------------------------------------------------------
def test_the_host_key_is_found_in_a_whole_server_stream():
    """
    The caller has one direction of a reassembled conversation: banner,
    KEXINIT, the reply, NEWKEYS. Everything before the reply has to be
    walked past rather than searched for.
    """
    parsed = parse_kex_reply(server_stream(rsa_blob(2048)))
    assert parsed['key_type'] == 'ssh-rsa'
    assert parsed['key_size'] == 2048
    assert parsed['kex_reply_code'] == 31


def test_group_exchange_message_31_is_not_mistaken_for_a_host_key():
    """
    The collision that makes a message-code-only walk wrong: in a
    group-exchange key exchange (RFC 4419) message 31 is
    SSH_MSG_KEX_DH_GEX_GROUP, carrying `mpint p, mpint g`, and the reply
    carrying the host key is 33. Reading p as a host key blob would name a
    key type out of the first four bytes of a prime.
    """
    stream = (b'SSH-2.0-OpenSSH_9.6\r\n' + kexinit() + gex_group()
              + gex_reply(rsa_blob(3072)))
    parsed = parse_kex_reply(stream)
    assert parsed['kex_reply_code'] == 33
    assert parsed['key_type'] == 'ssh-rsa'
    assert parsed['key_size'] == 3072


def test_a_stream_with_no_reply_says_so():
    """
    A capture that starts late, or one cut short, has no reply in it. That
    is different from a reply this module could not read.
    """
    parsed = parse_kex_reply(b'SSH-2.0-OpenSSH_9.6\r\n' + kexinit())
    assert parsed['error'] == 'no_kex_reply'
    assert parsed['key_type'] is None


def test_a_reply_split_across_segments_is_not_half_read():
    """A packet whose bytes have not all arrived is not a short packet."""
    stream = server_stream(rsa_blob(4096))
    parsed = parse_kex_reply(stream[:len(stream) - 200])
    assert parsed['key_size'] is None
    assert parsed['error'] is not None


def test_the_packet_walk_is_bounded():
    """
    After NEWKEYS the stream is ciphertext, and walking it is reading noise
    as lengths. The cap is what stops a crafted stream costing an unbounded
    walk; MAX_PACKETS exists for the same reason MAX_LIST_ITEMS does in the
    TLS parser.
    """
    stream = (b'SSH-2.0-OpenSSH_9.6\r\n'
              + ssh_packet(bytes([21])) * (MAX_PACKETS + 20)
              + ecdh_reply(rsa_blob(2048)))
    assert parse_kex_reply(stream)['error'] == 'no_kex_reply'


def test_stream_scanning_never_raises_on_mutated_input():
    rnd = random.Random(1)
    seed = bytearray(server_stream(ed25519_blob()))
    for _ in range(300):
        stream = bytearray(seed)
        for _ in range(rnd.randint(1, 10)):
            stream[rnd.randrange(len(stream))] = rnd.randrange(256)
        assert isinstance(parse_kex_reply(bytes(stream)), dict)


# --------------------------------------------------------------------------
# post-quantum markers
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", [
    'sntrup761x25519-sha512@openssh.com',
    'sntrup761x25519-sha512',
    'mlkem768x25519-sha256',
    'mlkem768nistp256-sha256',
    'mlkem1024nistp384-sha384',
])
def test_the_pq_key_exchanges_are_hybrid_not_post_quantum(name):
    """
    Every post-quantum SSH key exchange deployed today is a hybrid: the
    post-quantum KEM is combined with x25519 or a NIST curve so that it is
    no weaker than either. Recording these as `post-quantum` would overstate
    deployment and recording them as `classical` would erase the work, which
    is why cryptomon.analysis has a third verdict rather than two.
    """
    assert classify_kex_algorithms([name])[name] == HYBRID


@pytest.mark.parametrize("name", [
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521',
    'diffie-hellman-group14-sha256',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group1-sha1',
])
def test_the_classical_key_exchanges_are_classical(name):
    assert classify_kex_algorithms([name])[name] == CLASSICAL


def test_the_verdict_comes_from_the_one_classifier():
    """
    cryptomon.analysis.classify_algorithm is where "does this survive Shor"
    is decided, for TLS group names and SSH names alike. A second classifier
    in this module would be a second place for that answer to drift, and the
    two would disagree the first time a name was added to one of them.
    """
    from cryptomon.analysis import classify_algorithm
    names = ['sntrup761x25519-sha512@openssh.com', 'curve25519-sha256',
             'mlkem768x25519-sha256', 'ssh-ed25519']
    assert classify_kex_algorithms(names) == {
        name: classify_algorithm(name) for name in names}


def test_signalling_names_are_not_counted_as_algorithms():
    """
    `ext-info-c` (RFC 8308) and `kex-strict-*-v00@openssh.com` (OpenSSH's
    Terrapin countermeasure, CVE-2023-48795) ride in the key-exchange list
    but name no algorithm. Classifying them would put two or three entries
    in the `unknown` bucket on every SSH session, which reads as "we did not
    recognise this cipher" when nothing was proposed.
    """
    verdicts = classify_kex_algorithms(
        ['curve25519-sha256', 'ext-info-c', 'kex-strict-c-v00@openssh.com'])
    assert verdicts == {'curve25519-sha256': CLASSICAL}


def test_an_unrecognised_name_is_unknown_rather_than_classical():
    """An unrecognised algorithm is a gap in the table, not a finding."""
    assert classify_kex_algorithms(['nonsense-kex'])['nonsense-kex'] == UNKNOWN


# --------------------------------------------------------------------------
# the whole session
# --------------------------------------------------------------------------
def test_describe_ssh_session_is_one_flat_json_serialisable_record():
    """
    The record goes into a session document, out through the JSON and CSV
    exporters and into storage. A bytes object anywhere in it fails
    json.dumps at export time -- after the capture has been parsed, which is
    the most expensive moment to find out.
    """
    lists = {'KEXalgs': ['sntrup761x25519-sha512@openssh.com',
                         'curve25519-sha256',
                         'kex-strict-s-v00@openssh.com'],
             'ServerHostKeyAlgos': ['rsa-sha2-512', 'ssh-ed25519']}
    record = describe_ssh_session(
        b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5', lists,
        server_stream(ed25519_blob()))

    assert json.loads(json.dumps(record)) == record
    assert record['software'] == 'OpenSSH'
    assert record['software_version'] == '9.6p1'
    assert record['kex_post_quantum'] is True
    assert record['strict_kex'] is True
    assert record['host_key_type'] == 'ssh-ed25519'
    assert record['host_key_size'] == 256
    assert record['host_key_label'] == 'ssh-ed25519-256'
    assert record['host_key_verdict'] == CLASSICAL
    assert record['host_key_error'] is None


def test_a_classical_only_session_is_not_reported_as_quantum_ready():
    record = describe_ssh_session(b'SSH-2.0-dropbear_2022.83',
                                  {'KEXalgs': ['curve25519-sha256']})
    assert record['kex_post_quantum'] is False
    assert record['strict_kex'] is False


def test_a_session_with_no_reply_captured_has_no_host_key_and_no_error():
    """
    Three states, not two: no reply in the capture, a reply that would not
    parse, and a key. The first must not look like the second -- "we did not
    see it" and "we could not read it" are different findings.
    """
    seen_nothing = describe_ssh_session(b'SSH-2.0-OpenSSH_9.6', {})
    assert seen_nothing['host_key_size'] is None
    assert seen_nothing['host_key_error'] is None

    unreadable = describe_ssh_session(
        b'SSH-2.0-OpenSSH_9.6', {},
        b'SSH-2.0-OpenSSH_9.6\r\n' + ecdh_reply(rsa_blob(2048))[:20])
    assert unreadable['host_key_size'] is None
    assert unreadable['host_key_error'] is not None


def test_describe_ssh_session_survives_an_empty_call():
    """The builder may have neither banner nor lists for a flow it saw."""
    record = describe_ssh_session(None, None)
    assert record['banner'] is None
    assert record['kex_verdicts'] == {}


def test_no_key_collides_with_the_kexinit_name_lists():
    """
    This record is merged into a session's `ssh` dict beside the six KEXINIT
    lists. A collision would silently replace one of them, and the loss
    would only show up as an empty column in an export.
    """
    record = describe_ssh_session(b'SSH-2.0-OpenSSH_9.6',
                                  {'KEXalgs': ['curve25519-sha256']})
    assert not set(record) & set(SSH_SECTIONS)
