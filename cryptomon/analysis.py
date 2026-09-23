"""
What the records mean, separately from where they came from or where they go.

This layer takes an *iterable of session records* and returns counts and an
algorithm inventory. It opens no files, imports no database driver and knows
nothing about CycloneDX. That is what lets the offline exporter and the live
dashboard be one product rather than two: PR-25 turns the inventory below
into a CBOM, PR-36 turns the same summary into `/stats`, and neither of them
re-implements the judgement.

**The judgement is the point.** Counting ciphersuites is arithmetic; saying
which of them survive a cryptographically relevant quantum computer is the
question the tool was built to answer, and it belongs in exactly one place.

Five verdicts, and the distinction between the first three is not cosmetic:

  post-quantum  believed to resist Shor and Grover: ML-KEM, ML-DSA, and the
                other NIST selections, standing alone.
  hybrid        a post-quantum algorithm combined with a classical one, so
                that it is no weaker than either. X25519MLKEM768 is the
                common case, and every post-quantum key exchange seen in the
                corpus is of this kind. Recording it as "post-quantum" would
                overstate deployment; recording it as "classical" would erase
                the work. It is its own answer.
  classical     broken by Shor: RSA, finite-field and elliptic-curve
                Diffie-Hellman, DSA, ECDSA, EdDSA.
  symmetric     names no asymmetric primitive at all, which is what a TLS
                1.3 ciphersuite looks like: TLS_AES_256_GCM_SHA384 says
                nothing about the key exchange, because in TLS 1.3 the suite
                no longer carries it. Reporting that as "unknown" would read
                as "unrecognised", which it is not.
  unknown       not recognised. Counted, never guessed at, and never folded
                into "classical" -- an unrecognised algorithm is a gap in
                this table, not a finding about the traffic.

Symmetric ciphers are judged separately, because Grover halves an exhaustive
search rather than breaking the algorithm: AES-256 retains 128 bits against
it, AES-128 retains 64. Calling AES-128 "quantum-vulnerable" alongside RSA
would be wrong by several orders of magnitude, so it is reported as a
strength in bits.
"""
import collections
import re

POST_QUANTUM = 'post-quantum'
HYBRID = 'hybrid'
CLASSICAL = 'classical'
SYMMETRIC = 'symmetric'
UNKNOWN = 'unknown'
NOT_APPLICABLE = 'none'

# Verdicts about *protection*, as distinct from the verdicts above about
# quantum resistance. A protocol can be unbroken by Shor and still have no
# cryptography in it at all, and a report that answers only the first
# question says nothing about the 61% of this corpus's UDP that anyone on
# the segment can read today. `pcapscan/cleartext.py` produces these.
#
# `NOT_APPLICABLE` above is reused as the `none` rung rather than a fourth
# spelling of the same word -- but it is kept in its own field, never fed
# into `key_exchange_verdict`: "a resumed TLS session needed no key
# exchange" and "DHCP has no cryptography" are the same word about very
# different situations.
PROTECTION_OBSOLETE = 'obsolete'
PROTECTION_AUTHENTICATED = 'authenticated only'
PROTECTION_ENCRYPTED = 'encrypted'
PROTECTIONS = (NOT_APPLICABLE, PROTECTION_OBSOLETE,
               PROTECTION_AUTHENTICATED, PROTECTION_ENCRYPTED)

# Substrings naming a post-quantum primitive. Matched case-insensitively
# against the names this project's own tables produce, which follow the IANA
# registry and the draft names still in use for the Kyber round-3 groups.
PQ_MARKERS = (
    'mlkem', 'ml-kem', 'kyber',
    'mldsa', 'ml-dsa', 'dilithium',
    'falcon', 'sphincs', 'slh-dsa', 'slhdsa',
    'frodo', 'bike', 'hqc', 'classic-mceliece', 'mceliece',
    'ntru', 'sntrup', 'saber', 'sike',      # sike is broken, but it is PQ
    'xmss', 'lms',
)

# Substrings naming a classical primitive broken by Shor.
CLASSICAL_MARKERS = (
    'x25519', 'x448', 'secp', 'sect', 'brainpool', 'ffdhe', 'curvesm2',
    'rsa', 'ecdsa', 'ed25519', 'ed448', 'dsa', 'dh', 'gostr', 'eccsi',
    'gc256', 'gc512', 'sm2',
    # SSH spells the same primitives differently, and the SSH names are
    # where the hybrid PQ key exchanges show up in practice
    # (sntrup761x25519, mlkem768x25519) -- so missing these would classify
    # the most interesting SSH traffic as post-quantum rather than hybrid.
    'curve25519', 'curve448', 'nistp', 'diffiehellman', 'dss',
)

# Symmetric strength before Grover, read off the IANA ciphersuite name.
SYMMETRIC_BITS = (
    # First, and deliberately: RFC 4543's ENCR_NULL_AUTH_AES_GMAC is *null
    # encryption* with a GMAC for integrity, and its IKEv2 transform name is
    # `ENCR_NULL_AUTH_AES_256_GMAC`. Matching is by substring in this order,
    # so without this entry `AES_256` wins and an IPsec SA that encrypts
    # nothing at all is reported as "AES_256, 256 bits, 128 after Grover".
    # For a tool whose headline distinction is encrypted versus cleartext,
    # that is the worst single answer it could give.
    ('NULL_AUTH', 0),
    ('AES_256', 256), ('AES_128', 128), ('CHACHA20', 256),
    ('CAMELLIA_256', 256), ('CAMELLIA_128', 128),
    ('ARIA_256', 256), ('ARIA_128', 128),
    ('3DES', 112), ('DES_CBC', 56), ('DES40', 40), ('DES', 56),
    ('RC4', 128), ('NULL', 0),
)

# Ciphers that are broken today, by classical cryptanalysis, whatever their
# nominal key length. Reporting RC4 as "128 bits, 64 after Grover" would be
# an answer to the wrong question by a wide margin: it is not waiting for a
# quantum computer.
SYMMETRIC_BROKEN = ('RC4', '3DES', 'DES_CBC', 'DES40', 'DES', 'NULL')

# Anything at or below this after Grover is not a defensible symmetric
# choice for data that has to stay secret. 128 pre-Grover leaves 64.
GROVER_FLOOR_BITS = 64

_NON_ALNUM = re.compile(r'[^a-z0-9]+')


def _normalise(name):
    return _NON_ALNUM.sub('', str(name).lower())


# Longest first, so that "sntrup" is consumed before the "ntru" inside it.
_PQ_NORMALISED = tuple(sorted((_normalise(m) for m in PQ_MARKERS),
                              key=len, reverse=True))
_CLASSICAL_NORMALISED = tuple(_normalise(m) for m in CLASSICAL_MARKERS)


def classify_algorithm(name):
    """
    One algorithm name -> one of the verdicts above.

    Hybrid is decided by finding both a post-quantum and a classical marker
    in the same name, which is exactly how the hybrid groups are named:
    X25519MLKEM768 is x25519 and ML-KEM-768, and it is there because neither
    side is trusted alone yet.
    """
    if not name:
        return UNKNOWN
    flat = _normalise(name)
    if not flat or flat.startswith('unknown') or flat == 'grease':
        return UNKNOWN
    # Post-quantum markers are matched first and *removed*, because several
    # of them contain a classical name as a substring: ML-DSA and SLH-DSA
    # both end in "dsa", and matching that would report every NIST signature
    # selection as a hybrid of itself and DSA.
    remaining = flat
    pq = False
    for marker in _PQ_NORMALISED:
        if marker in remaining:
            pq = True
            remaining = remaining.replace(marker, '')
    classical = any(marker in remaining for marker in _CLASSICAL_NORMALISED)
    if pq and classical:
        return HYBRID
    if pq:
        return POST_QUANTUM
    if classical:
        return CLASSICAL
    return UNKNOWN


def classify_ciphersuite(name):
    """
    A ciphersuite name, judged on what it actually names.

    TLS 1.2 suites name their key exchange and authentication
    (TLS_ECDHE_RSA_...), so they carry a classical verdict. TLS 1.3 suites
    name only the symmetric cipher and hash, because the key exchange moved
    into an extension -- which is why the key exchange is counted separately
    and this says `symmetric` rather than pretending not to know.
    """
    verdict = classify_algorithm(name)
    if verdict == UNKNOWN and symmetric_strength(name)[0]:
        return SYMMETRIC
    return verdict


def symmetric_label(ciphersuite):
    """A readable strength for a ciphersuite, or None if it names no cipher."""
    cipher, bits, after = symmetric_strength(ciphersuite)
    if cipher is None:
        return None
    if cipher in SYMMETRIC_BROKEN:
        return '{0} (broken independently of any quantum computer)'.format(
            cipher)
    return '{0} ({1} bits, {2} after Grover)'.format(cipher, bits, after)


def classify_key_exchange(group):
    """A session's key exchange, where `None` means none was performed."""
    if group is None:
        return NOT_APPLICABLE
    return classify_algorithm(group)


def classify_certificate(certificate):
    """
    A certificate's signing key.

    The size travels with the verdict because it is the only thing that makes
    the verdict actionable: every RSA key is broken by Shor, and the ones
    that have to be replaced first are not chosen at random.
    """
    algorithm = certificate.get('public_key_algorithm')
    if not algorithm:
        # The certificate did not decode far enough to have a key -- it is
        # one of the `parse_error` records describe_certificate returns. It
        # was still on the wire, so it is still counted, but under a name
        # rather than under None. A None label becomes a None dict key in
        # the summary, and `json.dumps(..., sort_keys=True)` then cannot
        # order it against the string keys beside it: one unreadable
        # certificate anywhere in a capture killed the whole JSON export.
        # Found by fuzzing whole capture files through every exporter.
        return UNKNOWN, 'unreadable'
    bits = certificate.get('public_key_size')
    verdict = classify_algorithm(
        certificate.get('public_key_curve') or algorithm)
    label = algorithm if bits is None else '{0}-{1}'.format(algorithm, bits)
    return verdict, label


def symmetric_strength(ciphersuite):
    """
    (cipher name, bits before Grover, bits after) for a ciphersuite.

    Returns (None, None, None) when the name says nothing about the cipher,
    rather than assuming a default -- there is no safe default to assume.
    """
    if not ciphersuite:
        return None, None, None
    upper = str(ciphersuite).upper()
    for marker, bits in SYMMETRIC_BITS:
        if marker in upper:
            return marker, bits, bits // 2
    return None, None, None


class Summary:
    """
    Counts over a set of session records, plus the algorithm inventory.

    Deliberately a plain object with plain dicts inside: PR-25 serialises it
    into a CBOM and PR-36 into JSON for a dashboard, and neither should have
    to unpick a custom type to do it.
    """

    def __init__(self):
        self.sessions = 0
        self.protocols = collections.Counter()
        self.tls_versions = collections.Counter()
        self.ciphersuites = collections.Counter()
        self.key_exchange = collections.Counter()
        self.key_exchange_verdict = collections.Counter()
        self.signature_algorithms = collections.Counter()
        self.certificate_keys = collections.Counter()
        self.certificate_verdict = collections.Counter()
        self.symmetric_bits = collections.Counter()
        self.resumption = collections.Counter()
        self.hosts = collections.Counter()
        self.downgrades = []
        self.certificates_unreadable = 0
        # Encrypted ClientHello, counted because it is the qualifier on
        # every hostname this tool reports. While servers decline it the
        # hostname is the real one; once they accept, it is the public outer
        # name and the report must say so rather than quietly change meaning.
        self.ech = collections.Counter()
        self.algorithms = {}
        self.ssh_kex = collections.Counter()
        # Flows whose cryptography exists but cannot be read: a UDP-
        # encapsulated ESP tunnel whose IKE_SA_INIT is not in the capture.
        # Kept out of `key_exchange_verdict` so that "we could not see it"
        # is never reported as "there was none".
        self.opaque_flows = 0
        # Distinct certificates, by fingerprint. A CBOM needs each one as its
        # own asset with its own subject and validity, which a count of
        # "RSA-2048: 274" cannot supply.
        self.certificates = {}

    # -- building ---------------------------------------------------------
    def add(self, record):
        self.sessions += 1
        if 'ssh' in record:
            self._add_ssh(record)
            return
        if 'ikev2' in record:
            self._add_ikev2(record)
            return
        if 'tls' not in record:
            # A record from a handler that negotiated neither TLS nor SSH.
            # The UDP handlers emit these: an unprotected DNS or HSRP flow
            # has no ciphersuite to put in a `tls` block, so it has none.
            # Without this branch each one is counted as a TLS session that
            # performed no key exchange, and on the capture corpus that is
            # 1,058 cleartext UDP flows arriving in the report as resumed
            # TLS sessions -- moving the quantum-safe fraction by inventing
            # sessions that never negotiated anything.
            self.protocols[_record_protocol(record)] += 1
            return
        tls = record.get('tls') or {}
        self.protocols['tls'] += 1
        self._add_tls(record, tls)

    def _note(self, name, kind, verdict, record):
        """Add one use of one algorithm to the inventory."""
        if not name:
            return
        entry = self.algorithms.setdefault(
            (kind, str(name)),
            {'name': str(name), 'kind': kind, 'verdict': verdict,
             'count': 0, 'occurrences': [],
             # Which protocol versions were seen using it. A CBOM's
             # dependency graph hangs off this: "TLS 1.2 depends on
             # secp256r1" is a statement about observed traffic, and
             # attaching every algorithm to every version would not be.
             'protocols': collections.Counter()})
        entry['count'] += 1
        entry['protocols'][_protocol_label(record)] += 1
        if len(entry['occurrences']) < MAX_OCCURRENCES:
            # Provenance: CycloneDX `evidence.occurrences` wants to say where
            # an asset was observed, and "in this capture, talking to this
            # host" is the strongest statement a network observer can make.
            host = (record.get('tls') or {}).get('hostname')
            endpoint = (record.get('eth') or {}).get('dst') or {}
            entry['occurrences'].append({
                'hostname': host,
                'address': endpoint.get('ipv4') or endpoint.get('ipv6'),
                'port': endpoint.get('port'),
                'ts': record.get('ts'),
            })

    def _add_tls(self, record, tls):
        versions = tls.get('tls_versions')
        for version in (versions if isinstance(versions, list) else [versions]):
            if version:
                self.tls_versions[version] += 1

        suite = tls.get('ciphersuite')
        if suite:
            self.ciphersuites[suite] += 1
            self._note(suite, 'ciphersuite', classify_ciphersuite(suite),
                       record)
            label = symmetric_label(suite)
            if label:
                self.symmetric_bits[label] += 1

        group = tls.get('kex_group')
        verdict = classify_key_exchange(group)
        self.key_exchange[group or 'none'] += 1
        self.key_exchange_verdict[verdict] += 1
        if group:
            self._note(group, 'key-exchange', verdict, record)

        if tls.get('ech'):
            self.ech[tls['ech']] += 1

        state = tls.get('resumption') or 'unknown'
        self.resumption[state] += 1
        if tls.get('hostname'):
            self.hosts[tls['hostname']] += 1

        # A post-quantum offer the server turned down. This is the finding a
        # readiness report is for: the client is ready and the server is not.
        offered = tls.get('offered_kex_group')
        if offered and classify_algorithm(offered) in (POST_QUANTUM, HYBRID):
            forced = tls.get('retry_kex_group') or tls.get('kex_group')
            if classify_algorithm(forced) == CLASSICAL:
                self.downgrades.append({
                    'hostname': tls.get('hostname'),
                    'offered': offered,
                    'forced': forced,
                    'ts': record.get('ts'),
                })

        if tls.get('certificates_unreadable'):
            self.certificates_unreadable += 1
        for certificate in tls.get('certificates') or []:
            self._add_certificate(record, certificate)

    def _add_certificate(self, record, certificate):
        fingerprint = certificate.get('fingerprint_sha256')
        if fingerprint and len(self.certificates) < MAX_CERTIFICATES:
            kept = self.certificates.setdefault(fingerprint,
                                                dict(certificate, seen=0,
                                                     protocols=set()))
            kept['seen'] += 1
            kept['protocols'].add(_protocol_label(record))
        verdict, label = classify_certificate(certificate)
        self.certificate_keys[label] += 1
        self.certificate_verdict[verdict] += 1
        self._note(label, 'certificate-key', verdict, record)
        signature = certificate.get('signature_algorithm')
        if signature:
            self.signature_algorithms[signature] += 1
            self._note(signature, 'signature', classify_algorithm(signature),
                       record)

    def _add_ikev2(self, record):
        """
        An IPsec negotiation, from `pcapscan.ikev2`.

        IKEv2 is the one protocol here that states its cryptography instead of
        implying it: RFC 7296 puts the encryption algorithm, the integrity
        algorithm, the PRF and the key exchange on the wire as four separately
        numbered transforms, in the clear. So almost nothing is inferred here.

        The one thing that still has to be got right is proposed against
        selected. An IKE_SA_INIT request is a *menu* -- a strongSwan default
        offers a dozen transforms -- and counting a menu as a deployment would
        report every group on it as if it were in use. `pcapscan.ikev2` fills
        `kex_group` only when a response carrying an SA payload was captured,
        and this counts only that.
        """
        ike = record.get('ikev2') or {}
        self.protocols[_protocol_label(record).lower()] += 1
        if ike.get('opaque'):
            # An ESP tunnel. The key exchange did happen -- in an IKE_SA_INIT
            # this capture does not contain -- so counting it as `none` would
            # file it beside a resumed TLS session, which performed no key
            # exchange at all. Different fact, different counter. A readiness
            # report should be able to say how much traffic it could not
            # account for rather than quietly leaving it out of the totals.
            self.opaque_flows += 1
            return

        group = ike.get('kex_group')
        verdict = classify_key_exchange(group)
        self.key_exchange[group or 'none'] += 1
        self.key_exchange_verdict[verdict] += 1
        if group:
            self._note(group, 'key-exchange', verdict, record)

        cipher = ike.get('encryption')
        if cipher:
            self._note(cipher, 'cipher', SYMMETRIC, record)
            label = symmetric_label(cipher)
            if label:
                self.symmetric_bits[label] += 1
        for name, kind in ((ike.get('prf'), 'prf'),
                           (ike.get('integrity'), 'integrity')):
            if name and name != 'NONE':
                self._note(name, kind, SYMMETRIC, record)

        # The finding a readiness report is for, in its IKEv2 spelling: the
        # initiator asked for a KEM alongside its group (RFC 9370) and the
        # responder answered INVALID_KE_PAYLOAD or picked a proposal without
        # one. Same shape as the TLS HelloRetryRequest downgrade above.
        offered = ike.get('offered_kex_group')
        if offered and classify_algorithm(offered) in (POST_QUANTUM, HYBRID):
            forced = ike.get('retry_kex_group') or group
            if classify_algorithm(forced) == CLASSICAL:
                self.downgrades.append({
                    'hostname': ike.get('responder'),
                    'offered': offered,
                    'forced': forced,
                    'ts': record.get('ts'),
                })

    def _add_ssh(self, record):
        self.protocols['ssh'] += 1
        ssh = record.get('ssh') or {}
        for algorithm in ssh.get('KEXalgs') or []:
            if algorithm in SSH_SIGNALLING_NAMES:
                continue
            self.ssh_kex[algorithm] += 1
            self._note(algorithm, 'key-exchange',
                       classify_algorithm(algorithm), record)

    # -- reading ----------------------------------------------------------
    @property
    def inventory(self):
        """Distinct algorithms observed, most used first."""
        return sorted(self.algorithms.values(),
                      key=lambda a: (-a['count'], a['kind'], a['name']))

    @property
    def certificate_inventory(self):
        """Distinct certificates observed, most seen first."""
        return sorted(self.certificates.values(),
                      key=lambda c: (-c['seen'],
                                     c.get('subject') or '',
                                     c['fingerprint_sha256']))

    def readiness(self):
        """
        The headline: how many sessions used what, in one dict.

        `none` is separated out rather than merged into any verdict, because
        a resumed session performs no key exchange and counting it either way
        would be counting an event that did not happen.
        """
        performed = sum(count for verdict, count
                        in self.key_exchange_verdict.items()
                        if verdict != NOT_APPLICABLE)
        quantum_ready = (self.key_exchange_verdict[POST_QUANTUM]
                         + self.key_exchange_verdict[HYBRID])
        weak_symmetric = sum(count for label, count
                             in self.symmetric_bits.items()
                             if 'broken' in label)
        return {
            'sessions': self.sessions,
            'key_exchanges_performed': performed,
            'post_quantum': self.key_exchange_verdict[POST_QUANTUM],
            'hybrid': self.key_exchange_verdict[HYBRID],
            'classical': self.key_exchange_verdict[CLASSICAL],
            'unknown': self.key_exchange_verdict[UNKNOWN],
            'no_key_exchange': self.key_exchange_verdict[NOT_APPLICABLE],
            'quantum_safe_fraction': (round(quantum_ready / performed, 4)
                                      if performed else None),
            'post_quantum_refused': len(self.downgrades),
            'certificates_quantum_vulnerable':
                self.certificate_verdict[CLASSICAL],
            'certificates_post_quantum':
                self.certificate_verdict[POST_QUANTUM],
            'certificates_unreadable': self.certificates_unreadable,
            'ech_offered': self.ech.get('offered', 0),
            'ech_accepted': self.ech.get('accepted', 0),
            'deprecated_tls_versions': sum(
                self.tls_versions[v] for v in DEPRECATED_TLS_VERSIONS),
            'broken_symmetric_ciphers': weak_symmetric,
            'opaque_flows': self.opaque_flows,
        }

    def as_dict(self):
        return {
            'readiness': self.readiness(),
            'protocols': dict(self.protocols),
            'tls_versions': dict(self.tls_versions.most_common()),
            'ciphersuites': dict(self.ciphersuites.most_common()),
            'key_exchange': dict(self.key_exchange.most_common()),
            'key_exchange_verdict': dict(self.key_exchange_verdict),
            'symmetric_strength': dict(self.symmetric_bits.most_common()),
            'signature_algorithms': dict(self.signature_algorithms.most_common()),
            'certificate_keys': dict(self.certificate_keys.most_common()),
            'certificate_verdict': dict(self.certificate_verdict),
            'resumption': dict(self.resumption),
            'ech': dict(self.ech.most_common()),
            'ssh_key_exchange': dict(self.ssh_kex.most_common()),
            'top_hosts': dict(self.hosts.most_common(TOP_HOSTS)),
            'downgrades': self.downgrades,
            'inventory': [dict(entry, protocols=dict(entry['protocols']))
                          for entry in self.inventory],
            'certificates': [
                dict(certificate, protocols=sorted(certificate['protocols']))
                for certificate in self.certificate_inventory],
        }


# Bounds on what a summary holds, so that analysing a large capture costs a
# report rather than a second copy of the capture.
MAX_OCCURRENCES = 32
TOP_HOSTS = 50
MAX_CERTIFICATES = 512


def _record_protocol(record):
    """
    What a record with neither a `tls` nor an `ssh` block calls itself.

    Named from the record rather than assumed, so a handler added later does
    not need this function changed to be counted correctly.
    """
    cleartext = record.get('cleartext')
    if isinstance(cleartext, dict) and cleartext.get('protocol'):
        return str(cleartext['protocol'])
    for name in ('quic', 'dtls', 'ikev2', 'cleartext'):
        if name in record:
            return name
    return UNKNOWN


def _protocol_label(record):
    """'TLSv1.3', 'SSH', 'IKEv2' -- how this record's protocol is named."""
    if 'ssh' in record:
        return 'SSH'
    if 'ikev2' in record:
        # Three protocols share one handler and one record key, because port
        # 4500 carries all three; the CBOM wants them apart, since an ESP
        # tunnel is `ipsec` and an IKE negotiation is `ike`.
        return {'esp': 'ESP', 'ikev1': 'IKEv1'}.get(
            (record.get('ikev2') or {}).get('kind'), 'IKEv2')
    versions = (record.get('tls') or {}).get('tls_versions')
    if isinstance(versions, list):
        # A client offering 1.3 and 1.2 that ends up on 1.3 lists both; the
        # highest is the one in force.
        return max(versions) if versions else 'TLS'
    return versions or 'TLS'

# Deprecated by RFC 8996. Counted separately because "still negotiating TLS
# 1.0" is an immediate finding, not a quantum one.
DEPRECATED_TLS_VERSIONS = ('TLSv1.0', 'TLSv1.1')

# Names that appear in an SSH KEXINIT's algorithm list but are not
# algorithms: they signal a capability. `classify_algorithm` rightly answers
# `unknown` for them, since they name no primitive -- but counting them would
# put two or three entries in the unknown bucket on every single SSH session,
# which would read as a gap in the classification table rather than as what
# it is.
SSH_SIGNALLING_NAMES = frozenset((
    'ext-info-c', 'ext-info-s',
    'kex-strict-c-v00@openssh.com', 'kex-strict-s-v00@openssh.com',
))


def analyse(records):
    """Summarise an iterable of session records. Consumes it once."""
    summary = Summary()
    for record in records:
        summary.add(record)
    return summary
