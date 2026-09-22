"""
The CBOM export.

The important test here is the first one: the generated document is validated
against the **published** CycloneDX 1.6 schema, vendored under tests/schema/.
A CBOM's whole value is that somebody else's tooling can read it, and a test
that checked the document looked the way we meant it to look would confirm
nothing at all about that.

The rest check the things a schema cannot: that the security levels are
security levels rather than key lengths, that the dependency graph says what
was observed rather than what could occur, and that the same traffic produces
the same document twice.
"""
import datetime
import io
import json
import pathlib
from urllib.parse import urlparse

import pytest

from cryptomon.analysis import analyse
from pcapscan.cbom import (SPEC_VERSION, build, classical_bits, nist_level,
                           write_cbom)
from pcapscan.sessions import iter_sessions

pytestmark = pytest.mark.smoke

HERE = pathlib.Path(__file__).resolve().parent
STREAMS = HERE / "fixtures" / "streams"
SCHEMA = HERE / "schema"


def corpus():
    records = []
    for path in sorted(STREAMS.glob("*.pcap")):
        records.extend(iter_sessions(path))
    return records


@pytest.fixture(scope='module')
def document():
    return build(analyse(corpus()), source='tests/fixtures/streams')


def validator():
    """
    A Draft 7 validator over the vendored CycloneDX schema.

    The two referenced schemas are registered by their `$id` rather than
    fetched, so this runs offline and cannot be broken by somebody else's
    hosting. `referencing` rather than the deprecated RefResolver, with a
    fallback so the test still works on jsonschema before 4.18.
    """
    jsonschema = pytest.importorskip("jsonschema")
    schemas = {name: json.loads((SCHEMA / f"{name}.schema.json").read_text())
               for name in ("bom-1.6", "spdx", "jsf-0.82")}
    root = schemas.pop("bom-1.6")
    try:
        from referencing import Registry, Resource
    except ImportError:                                   # jsonschema < 4.18
        store = {schema["$id"]: schema for schema in schemas.values()}
        return jsonschema.Draft7Validator(
            root, resolver=jsonschema.RefResolver.from_schema(root,
                                                              store=store))
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema))
        for schema in schemas.values())
    return jsonschema.Draft7Validator(root, registry=registry)


def refs(document):
    return {component['bom-ref'] for component in document['components']}


def by_name(document, name):
    return next(c for c in document['components'] if c['name'] == name)


# --------------------------------------------------------------------------
# the published specification
# --------------------------------------------------------------------------
def test_it_validates_against_the_published_cyclonedx_schema(document):
    """
    Against the real schema from CycloneDX/specification, not our reading of
    it. If this passes, a consumer that has never heard of this project can
    load the document.
    """
    errors = sorted(validator().iter_errors(document),
                    key=lambda e: list(e.path))
    assert not errors, '\n'.join(
        '{0}: {1}'.format(list(e.path), e.message) for e in errors[:5])


def test_the_envelope_says_what_it_is(document):
    assert document['bomFormat'] == 'CycloneDX'
    assert document['specVersion'] == SPEC_VERSION == '1.6'
    assert document['version'] == 1
    assert document['serialNumber'].startswith('urn:uuid:')


# --------------------------------------------------------------------------
# the content
# --------------------------------------------------------------------------
def test_every_asset_type_is_represented(document):
    kinds = {c['cryptoProperties']['assetType'] for c in document['components']}
    assert kinds == {'protocol', 'algorithm', 'certificate'}


def test_a_protocol_component_carries_its_cipher_suites(document):
    tls13 = by_name(document, 'TLSv1.3')['cryptoProperties']
    assert tls13['protocolProperties']['type'] == 'tls'
    assert tls13['protocolProperties']['version'] == '1.3'
    suites = [s['name'] for s in tls13['protocolProperties']['cipherSuites']]
    assert 'TLS_AES_256_GCM_SHA384' in suites


def test_a_certificate_component_carries_the_fields_a_cbom_needs(document):
    certificate = next(c for c in document['components']
                       if c['cryptoProperties']['assetType'] == 'certificate'
                       and ((urlparse(c['name']).hostname == 'sha384.badssl.com')
                            or (c['name'] == 'sha384.badssl.com')))
    properties = certificate['cryptoProperties']['certificateProperties']
    assert properties['certificateFormat'] == 'X.509'
    assert properties['subjectName'].startswith('CN=sha384.badssl.com')
    assert 'DigiCert' in properties['issuerName']
    assert properties['notValidBefore'] < properties['notValidAfter']
    assert properties['subjectPublicKeyRef'] in refs(document)
    assert properties['signatureAlgorithmRef'] in refs(document)
    assert certificate['hashes'][0]['alg'] == 'SHA-256'


def test_an_algorithm_component_carries_its_oid(document):
    """
    The reason a network CBOM can be joined to a source one: OIDs identify
    assets across tools, names do not.
    """
    key = by_name(document, 'RSA-2048')['cryptoProperties']
    assert key['oid'] == '1.2.840.113549.1.1.1'
    assert key['algorithmProperties']['primitive'] == 'signature'


def test_occurrences_record_where_an_asset_was_seen(document):
    """
    `evidence.occurrences` is provenance, and for a network observer the
    strongest available claim is "seen talking to this host on this port".
    """
    group = by_name(document, 'secp256r1')
    locations = [o['location'] for o in group['evidence']['occurrences']]

    def is_badssl_443(location):
        parsed = urlparse(location)
        if not parsed.netloc and parsed.path:
            parsed = urlparse(f"//{location}")
        return parsed.hostname == 'badssl.com' and parsed.port == 443

    assert any(is_badssl_443(location) for location in locations)


# --------------------------------------------------------------------------
# the judgements a schema cannot check
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,key_size,bits", [
    ('RSA', 2048, 112),     # NIST SP 800-57: not 2048
    ('RSA', 3072, 128),
    ('RSA', 4096, 128),
    ('RSA', 1024, 80),
    ('secp256r1', None, 128),
    ('secp384r1', None, 192),
    ('x25519', None, 128),
])
def test_classical_security_level_is_security_not_key_length(name, key_size,
                                                             bits):
    """
    An RSA-2048 key is 2048 bits long and provides 112 bits of security.
    Putting the key length in this field overstates it eighteenfold and
    misleads anything that sorts on it -- which is the entire point of
    publishing a machine-readable document.
    """
    assert classical_bits(name, key_size) == bits


@pytest.mark.parametrize("name,level", [
    ('ML-KEM-768', 3),
    ('X25519MLKEM768', 3),
    ('X25519Kyber768Draft00', 3),
    ('ML-KEM-1024', 5),
    ('ML-DSA-44', 2),
    ('x25519', 0),           # no post-quantum claim is not "unknown"
    ('RSA-2048', 0),
])
def test_nist_quantum_security_level(name, level):
    assert nist_level(name) == level


def test_a_hybrid_group_is_a_combiner(document):
    """
    CycloneDX has a word for exactly this, and X25519MLKEM768 is exactly
    that: two key agreements whose outputs are concatenated. Recording it as
    a plain `kem` would claim more than happened.
    """
    records = corpus() + [{
        'ptype': 'session', 'ts': 1.0, 'eth': {},
        'tls': {'kex_group': 'X25519MLKEM768', 'tls_versions': ['TLSv1.3'],
                'hostname': 'pq.test'}}]
    hybrid = by_name(build(analyse(records)), 'X25519MLKEM768')
    properties = hybrid['cryptoProperties']['algorithmProperties']
    assert properties['primitive'] == 'combiner'
    assert properties['nistQuantumSecurityLevel'] == 3
    assert properties['classicalSecurityLevel'] == 128
    assert properties['curve'] == 'x25519'
    assert hybrid['cryptoProperties']['oid'] == '2.16.840.1.101.3.4.4.2'


# --------------------------------------------------------------------------
# the dependency graph
# --------------------------------------------------------------------------
def test_every_reference_resolves(document):
    """
    The most common real defect in a generated CBOM: a bom-ref that points
    at nothing. A consumer either silently drops the edge or fails to load.
    """
    defined = refs(document)
    for component in document['components']:
        crypto = component['cryptoProperties']
        protocol = crypto.get('protocolProperties', {})
        for ref in protocol.get('cryptoRefArray', []):
            assert ref in defined, ref
        certificate = crypto.get('certificateProperties', {})
        for key in ('signatureAlgorithmRef', 'subjectPublicKeyRef'):
            if certificate.get(key):
                assert certificate[key] in defined, certificate[key]
    for dependency in document['dependencies']:
        assert dependency['ref'] in defined, dependency['ref']
        for ref in dependency['dependsOn']:
            assert ref in defined, ref


def test_each_reference_appears_once_in_dependencies(document):
    """CycloneDX allows one dependency entry per ref, and no more."""
    seen = [d['ref'] for d in document['dependencies']]
    assert len(seen) == len(set(seen))


def test_dependencies_describe_what_was_observed_together(document):
    """
    "TLS 1.2 depends on secp256r1" is a claim about this capture. Attaching
    every algorithm to every protocol version would be a claim about nothing,
    and would make the graph useless for the thing it is for.
    """
    tls12 = next(d for d in document['dependencies']
                 if d['ref'] == 'protocol/tlsv12')
    tls13 = next(d for d in document['dependencies']
                 if d['ref'] == 'protocol/tlsv13')
    # Certificates were readable under TLS 1.2 and encrypted under 1.3, so
    # the two must not depend on the same things.
    assert any(r.startswith('certificate/') for r in tls12['dependsOn'])
    assert not any(r.startswith('certificate/') for r in tls13['dependsOn'])


def test_a_certificate_depends_on_its_own_algorithms(document):
    certificate = next(c for c in document['components']
                       if c['cryptoProperties']['assetType'] == 'certificate')
    dependency = next(d for d in document['dependencies']
                      if d['ref'] == certificate['bom-ref'])
    properties = certificate['cryptoProperties']['certificateProperties']
    assert properties['subjectPublicKeyRef'] in dependency['dependsOn']
    assert properties['signatureAlgorithmRef'] in dependency['dependsOn']


# --------------------------------------------------------------------------
# item 37: the serial number is derived from the content
# --------------------------------------------------------------------------
def test_the_same_traffic_produces_the_same_serial_number():
    """
    So that a CBOM can be diffed against last month's and the difference is a
    change in the estate rather than a change in the clock.
    """
    records = corpus()
    first = build(analyse(records), source='x')
    second = build(analyse(records), source='x',
                   timestamp=datetime.datetime(2001, 1, 1,
                                               tzinfo=datetime.timezone.utc))
    assert first['serialNumber'] == second['serialNumber']
    assert first['metadata']['timestamp'] != second['metadata']['timestamp']


def test_different_traffic_produces_a_different_serial_number():
    records = corpus()
    changed = records[:-1]
    assert (build(analyse(records), source='x')['serialNumber']
            != build(analyse(changed), source='x')['serialNumber'])


def test_the_serial_number_is_a_well_formed_uuid(document):
    import re
    assert re.fullmatch(
        r'urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}'
        r'-[0-9a-f]{12}', document['serialNumber'])


# --------------------------------------------------------------------------
# the headline numbers travel with the document
# --------------------------------------------------------------------------
def test_the_readiness_figures_are_in_the_metadata(document):
    properties = {p['name']: p['value']
                  for p in document['metadata']['properties']}
    assert properties['pcapscan:sessions'] == '3'
    assert properties['pcapscan:post-quantum-offers-refused'] == '1'
    assert properties['pcapscan:certificates-quantum-vulnerable'] == '4'


def test_the_document_says_it_came_from_traffic(document):
    tool = document['metadata']['tools']['components'][0]
    assert tool['name'] == 'pcapscan'
    assert 'not from source' in tool['description']


def test_writing_produces_parseable_json():
    buffer = io.StringIO()
    write_cbom(analyse(corpus()), buffer, source='x.pcap')
    assert json.loads(buffer.getvalue())['bomFormat'] == 'CycloneDX'


def test_an_empty_capture_still_produces_a_valid_document():
    empty = build(analyse([]))
    assert empty['components'] == []
    assert not list(validator().iter_errors(empty))
