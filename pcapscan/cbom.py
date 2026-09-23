"""
CycloneDX 1.6 Cryptography Bill of Materials, from observed traffic.

The headline deliverable, and the thing that makes this project more than a
packet decoder: a machine-readable inventory of the cryptography an estate
*actually uses*, in the format the rest of the industry has agreed on.

**Why a network CBOM is worth having next to a source one.** A CBOM generated
from source says what an application is capable of negotiating. This one says
what it negotiated -- against real servers, with real middleboxes in the way,
after whatever the deployment's configuration turned off. The two disagree in
both directions, and the disagreement is the interesting part: source says a
post-quantum group is compiled in, traffic says the server refused it 60 times.

The two can be joined, which is why every algorithm here carries its OID
where one is known. `evidence.occurrences` then records where each asset was
seen, which for a network observer means the capture, the host and the port.

Structure:

    components
      protocol    one per protocol version observed, carrying the cipher
                  suites negotiated under it
      algorithm   each distinct key exchange, signature and public key
      certificate each distinct X.509 certificate, by fingerprint
    dependencies
      protocol    -> the algorithms and certificates seen under it
      certificate -> its signature algorithm and its public key algorithm

The dependency graph is built from what was observed together, not from what
could in principle go together. "TLS 1.2 depends on secp256r1" is a statement
about this capture; attaching every algorithm to every version would be a
statement about nothing.

**The serial number is derived from the content** (item 37). Two runs over
the same traffic produce byte-identical documents, so a CBOM can be diffed
against last month's and the difference is a change in the estate rather than
a change in the clock. The timestamp lives in `metadata`, outside the hash.

Validated against the published schema in the test suite, not merely
constructed to look like it.
"""
import datetime
import hashlib
import json

from cryptomon.analysis import HYBRID, POST_QUANTUM, symmetric_strength

SPEC_VERSION = '1.6'
BOM_FORMAT = 'CycloneDX'
TOOL_NAME = 'pcapscan'
TOOL_VENDOR = 'Santander Security Research'

# CycloneDX `primitive`, by what the algorithm is for. A hybrid group is a
# `combiner`: that is precisely what X25519MLKEM768 is, two key agreements
# whose outputs are concatenated, and the schema has a word for it.
PRIMITIVE_KEY_AGREE = 'key-agree'
PRIMITIVE_KEM = 'kem'
PRIMITIVE_COMBINER = 'combiner'
PRIMITIVE_SIGNATURE = 'signature'
PRIMITIVE_PKE = 'pke'
# IKEv2 names its encryption, PRF and integrity transforms separately, so
# unlike a TLS ciphersuite each one maps onto a single CycloneDX primitive.
PRIMITIVE_BLOCK = 'block-cipher'
PRIMITIVE_AE = 'ae'
PRIMITIVE_MAC = 'mac'
PRIMITIVE_KDF = 'kdf'

# NIST post-quantum security category, by parameter set. Absent from a name
# means the algorithm makes no post-quantum claim, which is 0 -- not unknown.
NIST_LEVELS = (
    ('mlkem1024', 5), ('kyber1024', 5), ('mldsa87', 5), ('dilithium5', 5),
    ('mlkem768', 3), ('kyber768', 3), ('mldsa65', 3), ('dilithium3', 3),
    ('mlkem512', 1), ('kyber512', 1), ('mldsa44', 2), ('dilithium2', 2),
    ('sntrup761', 3), ('falcon1024', 5), ('falcon512', 1),
)

# Classical security in bits, for the groups and key sizes actually seen.
# RSA figures follow NIST SP 800-57: 2048 bits of modulus is 112 bits of
# security, not 2048, and reporting the modulus here would overstate it by an
# order of magnitude.
RSA_STRENGTH = ((15360, 256), (7680, 192), (3072, 128), (2048, 112),
                (1024, 80))
CURVE_STRENGTH = {'secp256r1': 128, 'secp384r1': 192, 'secp521r1': 256,
                  'x25519': 128, 'x448': 224, 'secp256k1': 128,
                  'brainpoolp256r1': 128, 'brainpoolp384r1': 192,
                  'brainpoolp512r1': 256}

# OIDs for the things this tool sees often enough to be worth naming. The
# point of carrying them is joining with a source-derived CBOM, which
# identifies assets by OID rather than by whatever string a parser chose.
OIDS = {
    'x25519': '1.3.101.110',
    'x448': '1.3.101.111',
    'secp256r1': '1.2.840.10045.3.1.7',
    'secp384r1': '1.3.132.0.34',
    'secp521r1': '1.3.132.0.35',
    'secp256k1': '1.3.132.0.10',
    'rsa': '1.2.840.113549.1.1.1',
    'ec': '1.2.840.10045.2.1',
    'ed25519': '1.3.101.112',
    'ed448': '1.3.101.113',
    'mlkem512': '2.16.840.1.101.3.4.4.1',
    'mlkem768': '2.16.840.1.101.3.4.4.2',
    'mlkem1024': '2.16.840.1.101.3.4.4.3',
    'mldsa44': '2.16.840.1.101.3.4.3.17',
    'mldsa65': '2.16.840.1.101.3.4.3.18',
    'mldsa87': '2.16.840.1.101.3.4.3.19',
}

# CycloneDX names protocols in its own vocabulary, and it is not this
# project's: the 1.6 enum is tls / ssh / ipsec / ike / sstp / wpa / other /
# unknown. So an IKE negotiation is `ike` carrying version "2.0", not a
# protocol called "IKEv2", and an ESP tunnel is `ipsec`.
PROTOCOL_TYPES = {'tls': 'tls', 'ssh': 'ssh'}
PROTOCOL_LABELS = {
    'SSH': ('ssh', None),
    'IKEv2': ('ike', '2.0'),
    'IKEv1': ('ike', '1.0'),
    'ESP': ('ipsec', None),
}

# The labels `cryptomon.analysis._protocol_label` produces for everything
# that is not a TLS version. `summary.protocols` is keyed by the lowercase
# form of each.
NON_TLS_LABELS = ('SSH', 'IKEv2', 'IKEv1', 'ESP')

# CycloneDX `ikev2TransformTypes` (RFC 7296 transform types 1-4), by this
# project's inventory kind. `esn` and `auth` are deliberately absent: ESN is
# not carried in the summary, and IKEv2's authentication method is negotiated
# inside the encrypted IKE_AUTH exchange, so a network observer never sees
# it. Emitting either would be inventing a value the traffic did not contain.
IKEV2_TRANSFORM_SLOTS = {'cipher': 'encr', 'prf': 'prf',
                         'integrity': 'integ', 'key-exchange': 'ke'}

MAX_OCCURRENCES = 32


def _flat(name):
    return ''.join(c for c in str(name).lower() if c.isalnum())


def _ref(kind, name):
    """A stable, readable bom-ref. Uniqueness is by construction."""
    return '{0}/{1}'.format(kind, _flat(name) or 'unnamed')


def _oid(name):
    flat = _flat(name)
    if flat in OIDS:
        return OIDS[flat]
    # A hybrid or a suffixed spelling: match the longest known name inside it,
    # so that X25519MLKEM768 resolves to ML-KEM-768's OID rather than to
    # nothing. The classical half is carried separately as the curve.
    for known in sorted(OIDS, key=len, reverse=True):
        if known in flat and len(known) > 3:
            return OIDS[known]
    return None


def nist_level(name):
    """NIST post-quantum category, 0 when no post-quantum claim is made."""
    flat = _flat(name)
    for marker, level in NIST_LEVELS:
        if marker in flat:
            return level
    return 0


def classical_bits(name, key_size=None):
    """
    Classical security in bits -- not key length.

    RSA-2048 is 112 bits of security. Putting 2048 in this field would
    overstate it by a factor of eighteen and make the document actively
    misleading to anything that sorts on it.
    """
    flat = _flat(name)
    if key_size and flat.startswith('rsa'):
        for modulus, bits in RSA_STRENGTH:
            if key_size >= modulus:
                return bits
        return 80
    for curve, bits in CURVE_STRENGTH.items():
        if curve in flat:
            return bits
    if key_size and ('ec' in flat or 'ecdsa' in flat):
        return key_size // 2
    _cipher, before, _after = symmetric_strength(name)
    return before


def primitive_for(entry):
    """What this algorithm is for, in CycloneDX's vocabulary."""
    verdict = entry['verdict']
    if entry['kind'] == 'key-exchange':
        if verdict == HYBRID:
            return PRIMITIVE_COMBINER
        if verdict == POST_QUANTUM:
            return PRIMITIVE_KEM
        return PRIMITIVE_KEY_AGREE
    if entry['kind'] == 'signature':
        return PRIMITIVE_SIGNATURE
    if entry['kind'] == 'certificate-key':
        # A certificate's key is used to verify a signature, whatever else
        # the algorithm could do.
        return PRIMITIVE_SIGNATURE
    if entry['kind'] == 'cipher':
        # An IKEv2 ENCR transform names one concrete cipher rather than a
        # suite, so the schema's own word for it is available: the AEAD modes
        # are `ae` and the rest are block ciphers -- except RFC 4543's
        # ENCR_NULL_AUTH_AES_GMAC, which occupies the ENCR slot while
        # encrypting nothing, and is a MAC.
        if _is_mac_only(entry['name']):
            return PRIMITIVE_MAC
        return PRIMITIVE_AE if _is_aead(entry['name']) else PRIMITIVE_BLOCK
    if entry['kind'] == 'prf':
        return PRIMITIVE_KDF
    if entry['kind'] == 'integrity':
        return PRIMITIVE_MAC
    return 'other'


def _is_aead(name):
    flat = _flat(name)
    if 'nullauth' in flat:
        return False        # RFC 4543: integrity only, nothing is encrypted
    return any(mode in flat for mode in ('gcm', 'ccm', 'poly1305', 'mgm'))


def _is_mac_only(name):
    """RFC 4543's ENCR_NULL_AUTH_AES_GMAC: a MAC wearing a cipher's slot."""
    return 'nullauth' in _flat(name)


def functions_for(entry):
    if entry['kind'] == 'key-exchange':
        if entry['verdict'] in (POST_QUANTUM, HYBRID):
            return ['encapsulate', 'decapsulate']
        return ['keyderive']
    if entry['kind'] in ('signature', 'certificate-key'):
        return ['sign', 'verify']
    if entry['kind'] == 'cipher':
        if _is_mac_only(entry['name']):
            return ['tag']
        return ['encrypt', 'decrypt']
    if entry['kind'] == 'prf':
        return ['keyderive']
    if entry['kind'] == 'integrity':
        return ['tag']
    return []


def _occurrences(entry):
    seen, out = set(), []
    for occurrence in entry.get('occurrences', [])[:MAX_OCCURRENCES]:
        host = occurrence.get('hostname') or occurrence.get('address')
        if not host:
            continue
        location = '{0}:{1}'.format(host, occurrence.get('port') or '')
        if location in seen:
            continue
        seen.add(location)
        out.append({'location': location})
    return out


def _algorithm_component(entry, source):
    name = entry['name']
    key_size = None
    if entry['kind'] == 'certificate-key' and '-' in name:
        head, _sep, tail = name.rpartition('-')
        if tail.isdigit():
            key_size = int(tail)
            name_for_oid = head
        else:
            name_for_oid = name
    else:
        name_for_oid = name

    properties = {'primitive': primitive_for(entry)}
    functions = functions_for(entry)
    if functions:
        properties['cryptoFunctions'] = functions
    bits = classical_bits(name_for_oid, key_size)
    if bits:
        properties['classicalSecurityLevel'] = bits
    properties['nistQuantumSecurityLevel'] = nist_level(name)
    if key_size:
        properties['parameterSetIdentifier'] = str(key_size)
    curve = _flat(name)
    for known in CURVE_STRENGTH:
        if known in curve:
            properties['curve'] = known
            break

    crypto = {'assetType': 'algorithm', 'algorithmProperties': properties}
    oid = _oid(name_for_oid)
    if oid:
        crypto['oid'] = oid

    component = {
        'type': 'cryptographic-asset',
        'bom-ref': _ref(entry['kind'], name),
        'name': name,
        'description': '{0}, observed {1} time(s); assessed {2}'.format(
            entry['kind'], entry['count'], entry['verdict']),
        'cryptoProperties': crypto,
    }
    occurrences = _occurrences(entry)
    if occurrences:
        component['evidence'] = {'occurrences': occurrences}
    return component


def _certificate_component(certificate, source):
    fingerprint = certificate['fingerprint_sha256']
    properties = {'certificateFormat': 'X.509'}
    for field, key in (('subjectName', 'subject'), ('issuerName', 'issuer'),
                       ('notValidBefore', 'not_before'),
                       ('notValidAfter', 'not_after')):
        if certificate.get(key):
            properties[field] = certificate[key]
    signature = certificate.get('signature_algorithm')
    if signature:
        properties['signatureAlgorithmRef'] = _ref('signature', signature)
    algorithm = certificate.get('public_key_algorithm')
    if algorithm:
        label = algorithm if not certificate.get('public_key_size') else \
            '{0}-{1}'.format(algorithm, certificate['public_key_size'])
        properties['subjectPublicKeyRef'] = _ref('certificate-key', label)

    component = {
        'type': 'cryptographic-asset',
        'bom-ref': 'certificate/{0}'.format(fingerprint),
        'name': certificate.get('subject') or fingerprint[:16],
        'hashes': [{'alg': 'SHA-256', 'content': fingerprint}],
        'cryptoProperties': {'assetType': 'certificate',
                             'certificateProperties': properties},
    }
    if certificate.get('subject_alt_names'):
        component['evidence'] = {'occurrences': [
            {'location': name}
            for name in certificate['subject_alt_names'][:MAX_OCCURRENCES]]}
    return component


def _protocol_labels(summary):
    """Every protocol observed, under the label the inventory files it under."""
    return set(summary.tls_versions) | {
        label for label in NON_TLS_LABELS
        if summary.protocols.get(label.lower())}


def _ikev2_transform_types(summary, protocol):
    """
    An IKE component's `ikev2TransformTypes`, as refs into this same BOM.

    This is the reason a network CBOM is worth having for IPsec: RFC 7296
    puts the encryption algorithm, the PRF, the integrity algorithm and the
    key exchange on the wire as four separately numbered transforms, and
    CycloneDX has a field for exactly those four. Nothing is inferred from a
    suite name, because IKEv2 never used one.
    """
    slots = {}
    for entry in summary.inventory:
        slot = IKEV2_TRANSFORM_SLOTS.get(entry['kind'])
        if slot is None or protocol not in entry['protocols']:
            continue
        slots.setdefault(slot, set()).add(_ref(entry['kind'], entry['name']))
    return {slot: sorted(refs) for slot, refs in sorted(slots.items())}


def _protocol_components(summary):
    """One component per protocol version, carrying its cipher suites."""
    suites_by_protocol = {}
    for entry in summary.inventory:
        if entry['kind'] != 'ciphersuite':
            continue
        for protocol in entry['protocols']:
            suites_by_protocol.setdefault(protocol, []).append(entry['name'])

    components = []
    for protocol in sorted(_protocol_labels(summary)
                           | set(suites_by_protocol)):
        kind, version = PROTOCOL_LABELS.get(protocol, ('tls', None))
        if kind == 'tls':
            version = protocol.replace('TLSv', '')
        properties = {'type': kind}
        if version:
            properties['version'] = version
        suites = sorted(set(suites_by_protocol.get(protocol, [])))
        if suites:
            properties['cipherSuites'] = [{'name': suite} for suite in suites]
        if kind == 'ike':
            transforms = _ikev2_transform_types(summary, protocol)
            if transforms:
                properties['ikev2TransformTypes'] = transforms
        refs = sorted({_ref(entry['kind'], entry['name'])
                       for entry in summary.inventory
                       if protocol in entry['protocols']
                       and entry['kind'] != 'ciphersuite'})
        if refs:
            properties['cryptoRefArray'] = refs
        components.append({
            'type': 'cryptographic-asset',
            'bom-ref': _ref('protocol', protocol),
            'name': protocol,
            'description': 'observed in {0} session(s)'.format(
                summary.tls_versions.get(protocol)
                or summary.protocols.get(protocol.lower(), 0)),
            'cryptoProperties': {'assetType': 'protocol',
                                 'protocolProperties': properties},
        })
    return components


def _dependencies(summary, components):
    """What was observed together, not what could go together."""
    defined = {component['bom-ref'] for component in components}
    dependencies = []

    for protocol in sorted(_protocol_labels(summary)):
        ref = _ref('protocol', protocol)
        if ref not in defined:
            continue
        depends = sorted({_ref(entry['kind'], entry['name'])
                          for entry in summary.inventory
                          if protocol in entry['protocols']} & defined)
        depends += sorted({'certificate/{0}'.format(fingerprint)
                           for fingerprint, certificate
                           in summary.certificates.items()
                           if protocol in certificate['protocols']} & defined)
        dependencies.append({'ref': ref, 'dependsOn': depends})

    for fingerprint, certificate in sorted(summary.certificates.items()):
        ref = 'certificate/{0}'.format(fingerprint)
        depends = []
        properties = _certificate_component(certificate, None)[
            'cryptoProperties']['certificateProperties']
        for key in ('signatureAlgorithmRef', 'subjectPublicKeyRef'):
            if properties.get(key) in defined:
                depends.append(properties[key])
        dependencies.append({'ref': ref, 'dependsOn': sorted(set(depends))})

    for entry in summary.inventory:
        ref = _ref(entry['kind'], entry['name'])
        if ref in defined and entry['kind'] != 'ciphersuite':
            dependencies.append({'ref': ref, 'dependsOn': []})
    # A ref may be reached twice -- two certificates can share a key
    # algorithm -- and CycloneDX requires one entry per ref.
    merged = {}
    for dependency in dependencies:
        target = merged.setdefault(dependency['ref'],
                                   {'ref': dependency['ref'],
                                    'dependsOn': []})
        target['dependsOn'] = sorted(set(target['dependsOn'])
                                     | set(dependency['dependsOn']))
    return [merged[ref] for ref in sorted(merged)]


def _serial_number(payload):
    """
    A serial number derived from the content, not from a random generator.

    Item 37. Two runs over the same traffic then produce byte-identical
    documents, so a CBOM can be diffed against last month's and the
    difference is a change in the estate rather than a change in the clock.
    The version and variant bits are set so the result is a well-formed
    UUID, which the schema requires.
    """
    digest = bytearray(hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    ).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40       # version 4
    digest[8] = (digest[8] & 0x3F) | 0x80       # RFC 4122 variant
    hexed = digest.hex()
    return 'urn:uuid:{0}-{1}-{2}-{3}-{4}'.format(
        hexed[0:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32])


def build(summary, source=None, timestamp=None):
    """The whole document, as a dict."""
    components = _protocol_components(summary)
    components += [_algorithm_component(entry, source)
                   for entry in summary.inventory
                   if entry['kind'] != 'ciphersuite']
    components += [_certificate_component(certificate, source)
                   for certificate in summary.certificate_inventory]
    dependencies = _dependencies(summary, components)

    readiness = summary.readiness()
    subject = {
        'type': 'data',
        'bom-ref': 'observed-traffic',
        'name': str(source) if source else 'observed traffic',
        'description': '{0} session(s) observed on the wire'.format(
            readiness['sessions']),
    }
    payload = {'components': components, 'dependencies': dependencies,
               'metadata': {'component': subject}}

    return {
        'bomFormat': BOM_FORMAT,
        'specVersion': SPEC_VERSION,
        'serialNumber': _serial_number(payload),
        'version': 1,
        'metadata': {
            'timestamp': (timestamp or datetime.datetime.now(
                datetime.timezone.utc)).isoformat(timespec='seconds').replace(
                    '+00:00', 'Z'),
            'tools': {'components': [{
                'type': 'application',
                'name': TOOL_NAME,
                'publisher': TOOL_VENDOR,
                'description': 'CBOM generated from observed network traffic, '
                               'not from source',
            }]},
            'component': subject,
            'properties': [
                {'name': 'pcapscan:sessions',
                 'value': str(readiness['sessions'])},
                {'name': 'pcapscan:key-exchanges-performed',
                 'value': str(readiness['key_exchanges_performed'])},
                {'name': 'pcapscan:quantum-safe-key-exchanges',
                 'value': str(readiness['post_quantum'] + readiness['hybrid'])},
                {'name': 'pcapscan:post-quantum-offers-refused',
                 'value': str(readiness['post_quantum_refused'])},
                {'name': 'pcapscan:certificates-quantum-vulnerable',
                 'value': str(readiness['certificates_quantum_vulnerable'])},
            ],
        },
        'components': components,
        'dependencies': dependencies,
    }


def write_cbom(summary, stream, source=None):
    """Write the CBOM as JSON. Signature matches the other exporters."""
    json.dump(build(summary, source), stream, indent=2, sort_keys=False)
    stream.write('\n')
