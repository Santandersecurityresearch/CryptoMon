"""
The capture upload UI.

Driven through TestClient against the real app, because the things worth
checking here are HTTP-shaped: what a status code says, what reaches the
filesystem, and what is left behind afterwards.

The filename tests are the ones to keep. Every path-traversal bug of this
kind starts with a well-meant attempt to clean up a name the sender chose,
so these assert that the name is not cleaned but *ignored* -- it never
reaches a path at all, and the malicious string survives untouched as a
label precisely because nothing ever tried to make it safe.
"""
import json
import os
import pathlib

import pytest

from conftest import FIXTURES

CAPTURE = FIXTURES / "streams" / "tls13_hello_retry.pcap"
CERTS = FIXTURES / "streams" / "tls12_certificate.pcap"


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """The real app, with uploads pointed at a temporary directory."""
    monkeypatch.setenv('DB_URL', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('DB_NAME', 'cryptomon_test')
    fastapi_testclient = pytest.importorskip("fastapi.testclient")

    from fapi.config import settings
    monkeypatch.setattr(settings, 'UPLOAD_DIR', str(tmp_path / 'uploads'))
    monkeypatch.setattr(settings, 'UPLOADS_ENABLED', True)
    monkeypatch.setattr(settings, 'API_KEY', '')
    monkeypatch.setattr(settings, 'MAX_UPLOAD_BYTES', 8 * 1024 * 1024)

    import api
    # Instantiated rather than entered as a context manager, which is what
    # skips the lifespan. The lifespan opens a Mongo client and waits on
    # `ensure_indexes`; none of this touches the database, so running it
    # would cost a 30-second socket timeout per test.
    yield fastapi_testclient.TestClient(api.app)


@pytest.fixture
def spool(tmp_path):
    return pathlib.Path(tmp_path / 'uploads')


def post(client, path=CAPTURE, filename='capture.pcap', **data):
    with open(path, 'rb') as handle:
        return client.post('/analyse/',
                           files={'capture': (filename, handle,
                                              'application/octet-stream')},
                           data=dict(as_json='true', **data))


# --------------------------------------------------------------------------
# the form and the happy path
# --------------------------------------------------------------------------
def test_the_form_renders(app_client):
    response = app_client.get('/analyse/')
    assert response.status_code == 200
    assert 'type="file"' in response.text
    assert 'python -m pcapscan' in response.text   # the terminal route too


def test_a_capture_comes_back_as_a_report(app_client):
    response = post(app_client)
    assert response.status_code == 200, response.text
    document = response.json()
    assert document['summary']['readiness']['sessions'] == 1
    assert len(document['meta']['report_id']) == 32


def test_a_browser_is_redirected_to_the_report(app_client):
    with open(CAPTURE, 'rb') as handle:
        response = app_client.post(
            '/analyse/', files={'capture': ('c.pcap', handle)},
            follow_redirects=False)
    assert response.status_code == 303
    assert '/analyse/reports/' in response.headers['location']


def test_the_report_page_shows_the_refused_post_quantum_offer(app_client):
    report_id = post(app_client).json()['meta']['report_id']
    page = app_client.get('/analyse/reports/{0}'.format(report_id))
    assert page.status_code == 200
    assert 'X25519Kyber768Draft00' in page.text
    assert 'refused' in page.text.lower()


def test_the_report_page_gives_the_denominator(app_client):
    """
    "0% quantum-safe" without saying 0% of what is the same mistake the CLI
    was careful to avoid. A resumed session performs no key exchange.
    """
    report_id = post(app_client).json()['meta']['report_id']
    page = app_client.get('/analyse/reports/{0}'.format(report_id)).text
    assert 'performed' in page
    assert 'resumed' in page


def test_the_report_is_available_as_json(app_client):
    report_id = post(app_client).json()['meta']['report_id']
    response = app_client.get('/analyse/reports/{0}/json'.format(report_id))
    assert response.status_code == 200
    assert response.json()['meta']['report_id'] == report_id


def test_certificates_reach_the_report(app_client):
    document = post(app_client, CERTS).json()
    assert document['summary']['certificate_keys']
    page = app_client.get('/analyse/reports/{0}'.format(
        document['meta']['report_id'])).text
    assert 'RSA-2048' in page


# --------------------------------------------------------------------------
# the filename is the sender's, so it is never used
# --------------------------------------------------------------------------
@pytest.mark.parametrize("filename", [
    '../../etc/passwd',
    '/etc/shadow',
    '..\\..\\windows\\system32\\config\\sam',
    'capture.pcap\x00.txt',
    'x' * 500,
    'y' * 5000,
    '.',
    '..',
])
def test_the_client_filename_never_reaches_a_path(app_client, spool, filename):
    """
    Not sanitised -- ignored. The file lands under an id this service chose,
    and the only place the sender's string appears is as a label in the
    report.

    An over-long name may be refused before it ever reaches this code:
    python-multipart 0.0.32 rejects one past its header limit while 0.0.20
    accepts it. Both outcomes are safe and which one happens is that
    library's business, so the assertion covers both rather than pinning a
    status code from somebody else's changelog.
    """
    response = post(app_client, filename=filename)
    if response.status_code != 200:
        assert 400 <= response.status_code < 500, response.status_code
        assert not spool.exists() or not list(spool.iterdir())
        return
    stored = sorted(p.name for p in spool.iterdir())
    assert len(stored) == 1
    name = stored[0]
    assert name.endswith('.json')
    assert len(name) == 37                       # 32 hex + '.json'
    assert all(c in '0123456789abcdef' for c in name[:32])


def test_the_original_name_is_kept_as_a_label_only(app_client):
    document = post(app_client, filename='../../etc/passwd').json()
    # Untouched, because nothing ever tried to make it safe.
    assert document['meta']['original_filename'] == '../../etc/passwd'


def test_a_long_filename_is_truncated_in_the_label(app_client):
    document = post(app_client, filename='y' * 500).json()
    assert len(document['meta']['original_filename']) <= 200


def test_a_part_with_no_filename_is_refused(app_client, spool):
    """
    Encoded without a filename, the part is not a file upload at all, and
    FastAPI says so rather than treating the bytes as one. Refused before
    anything is written.
    """
    response = post(app_client, filename='')
    assert response.status_code == 422
    assert not spool.exists() or not list(spool.iterdir())


# --------------------------------------------------------------------------
# limits
# --------------------------------------------------------------------------
def test_an_oversized_upload_is_refused_and_leaves_nothing_behind(
        app_client, spool, tmp_path, monkeypatch):
    """
    The cap is enforced while the stream is read, so the partial file is
    removed the moment it is passed -- checking afterwards would mean the
    disk is already full.
    """
    from fapi.config import settings
    monkeypatch.setattr(settings, 'MAX_UPLOAD_BYTES', 1024)
    big = tmp_path / 'big.pcap'
    big.write_bytes(os.urandom(64 * 1024))

    response = post(app_client, big)
    assert response.status_code == 413
    assert 'MAX_UPLOAD_BYTES' in response.json()['detail']
    assert not list(spool.iterdir())


def test_an_empty_upload_is_refused(app_client, spool, tmp_path):
    empty = tmp_path / 'empty.pcap'
    empty.write_bytes(b'')
    assert post(app_client, empty).status_code == 400
    assert not list(spool.iterdir())


def test_the_capture_is_deleted_once_it_has_been_analysed(app_client, spool):
    """
    A directory of other people's packet captures is a liability nobody
    asked for. Everything the report needs is in the report.
    """
    post(app_client)
    remaining = [p.name for p in spool.iterdir()]
    assert all(name.endswith('.json') for name in remaining), remaining


def test_a_file_that_is_not_a_capture_is_explained(app_client, tmp_path):
    rubbish = tmp_path / 'notes.pcap'
    rubbish.write_bytes(b'this is not a capture at all')
    response = post(app_client, rubbish)
    assert response.status_code == 422
    detail = response.json()['detail']
    assert detail['reason'] == 'not_a_capture'
    assert 'pcap' in detail['hint']


# --------------------------------------------------------------------------
# report ids are the sender's choice too
# --------------------------------------------------------------------------
@pytest.mark.parametrize("report_id", [
    '../../../etc/passwd',
    'not-hex-at-all-not-hex-at-all-xx',
    'ABCDEF01234567890123456789012345',   # uppercase is not this shape
    'a' * 31,
    'a' * 33,
    '',
])
def test_a_malformed_report_id_is_404_not_500(app_client, report_id):
    """
    The same lesson as `/data/{id}` in PR-06: an id in a URL is a string the
    sender chose, and answering 500 for a malformed one tells them they
    found an unhandled path.
    """
    response = app_client.get('/analyse/reports/{0}'.format(report_id))
    assert response.status_code == 404


def test_an_unknown_report_is_404(app_client):
    assert app_client.get(
        '/analyse/reports/{0}'.format('0' * 32)).status_code == 404


# --------------------------------------------------------------------------
# access
# --------------------------------------------------------------------------
def test_uploads_can_be_switched_off(app_client, monkeypatch):
    from fapi.config import settings
    monkeypatch.setattr(settings, 'UPLOADS_ENABLED', False)
    response = post(app_client)
    assert response.status_code == 403
    assert 'UPLOADS_ENABLED' in response.json()['detail']
    # The form still renders, and says so rather than 404ing.
    page = app_client.get('/analyse/')
    assert page.status_code == 200
    assert 'disabled' in page.text.lower()


def test_an_api_key_is_required_when_one_is_configured(app_client,
                                                       monkeypatch):
    from fapi.config import settings
    monkeypatch.setattr(settings, 'API_KEY', 'a-shared-secret')

    assert post(app_client).status_code == 401

    with open(CAPTURE, 'rb') as handle:
        response = app_client.post(
            '/analyse/', files={'capture': ('c.pcap', handle)},
            data={'as_json': 'true'},
            headers={'X-API-Key': 'a-shared-secret'})
    assert response.status_code == 200


def test_uploading_does_not_require_the_database_to_be_writable(app_client):
    """
    READ_ONLY guards documents, and an upload writes none. Making the
    feature depend on it would mean it does not work on a default install,
    which is the install almost everybody has.
    """
    from fapi.config import settings
    assert settings.READ_ONLY is True
    assert post(app_client).status_code == 200


# --------------------------------------------------------------------------
# the report renders the summary, not the records
# --------------------------------------------------------------------------
def test_the_page_is_built_from_the_summary(app_client, spool):
    """
    The design constraint that keeps this page independent of Lane E: the
    summary's shape is stable, the session record's is not. A report with
    its `sessions` list emptied must still render completely.
    """
    report_id = post(app_client).json()['meta']['report_id']
    stored = spool / '{0}.json'.format(report_id)
    document = json.loads(stored.read_text())
    document['sessions'] = []
    stored.write_text(json.dumps(document))

    page = app_client.get('/analyse/reports/{0}'.format(report_id))
    assert page.status_code == 200
    assert 'X25519Kyber768Draft00' in page.text
    assert 'sessions' in page.text
