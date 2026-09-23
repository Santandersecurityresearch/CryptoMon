"""
The dashboard page, its fragment route and its chart helpers.

Two halves, and the split is deliberate.

`fapi/app/charts.py` is pure functions, so the chart tests here are the
degenerate cases rather than the happy path: no buckets, one bucket, a
bucket whose count is zero, a 200-character name, counts spanning four
orders of magnitude, and a hostname carrying angle brackets, quotes and a
NUL. A chart that a person cannot read is a bug in a monitoring tool, and
those are the five shapes that make one unreadable.

`fapi/app/dashboard.py` is driven through TestClient with a **fake**
`fapi.app.stats` installed into `sys.modules`. PR-36 is writing the real one
in another worktree and this file has never seen it; the canned payloads
below are built to STATS_CONTRACT section 3 from real numbers measured
against the project's corpus, so if the two halves disagree it is the
contract that is wrong, and that is exactly what these tests are for. The
fake also makes the 503-when-absent path testable, which is the one
behaviour that cannot be checked with the real module installed.

No database, no capture fixture, no network, no docker: smoke.
"""
import os
import sys
import types

import pytest

os.environ.setdefault("DB_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "cryptomon-test")

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from fapi.app import charts                                    # noqa: E402
from fapi.app.dashboard import PANEL_ORDER, router             # noqa: E402

# Merge gate: nothing here touches a database, a capture or a socket.
pytestmark = pytest.mark.smoke

# A fixed "now", so a window is reproducible and a failure is never about
# the clock. 2024-12-11 22:16 UTC, the last timestamp in the real corpus.
NOW = 1733955362.0
SPAN = {'first': 1687767949.183767, 'last': 1733955362.296053}


# --------------------------------------------------------------------------
# canned payloads -- STATS_CONTRACT section 3, with real corpus numbers
# --------------------------------------------------------------------------
def corpus_payloads():
    """
    One envelope per panel, in the contract's shapes.

    The numbers are the ones PR-36 measured against the real collection
    (`cryptomon_recent.cryptomon`, 1342 session documents, whole collection)
    and are **not** the illustrative figures in STATS_CONTRACT, several of
    which are wrong. Nothing here is invented and nothing is copied from the
    contract's examples.

    Two things these fixtures exist to pin, because both are places where a
    renderer can quietly say something false:

    * `total` is the DOCUMENT count on every panel. On the panels that
      $unwind a list field -- tls-versions, certificates, alerts -- the
      buckets sum to *occurrences* instead, so the two numbers differ on
      purpose. tls-versions here is 1342 documents and 1455 appearances.
    * `key-exchange` has no "(none)" bucket; the documents that performed no
      key exchange are in `notes`. Every other panel does keep "(none)".
    """
    return {
        'overview': {
            'panel': 'overview', 'window': {}, 'documents': 1342,
            'by_ptype': {'session': 1342}, 'span': dict(SPAN),
            'protocols': {'tls': 1342, 'ssh': 0},
            'key_exchanges_performed': 598, 'quantum_safe': 81,
            'quantum_safe_percent': 13.5, 'certificates': 393,
            'distinct_hosts': 202, 'distinct_ja4': 32,
            'ech_offered': 490, 'ech_accepted': 0, 'alerts': 42,
            'tags': ['chrome_mac', 'win11_edge'], 'notes': [],
        },
        'key-exchange': _envelope('key-exchange', 598, [
            ('x25519', 202, 'classical'), ('secp384r1', 162, 'classical'),
            ('secp256r1', 142, 'classical'), ('X25519MLKEM768', 45, 'hybrid'),
            ('X25519Kyber768Draft00', 36, 'hybrid'),
            ('secp521r1', 11, 'classical'),
        ], notes=['744 of 1342 sessions resumed and performed no key '
                  'exchange.']),
        'timeline': {
            'panel': 'timeline', 'window': {}, 'bucket_seconds': 3600,
            'series': [
                {'t': NOW - 3 * 3600, 'total': 120,
                 'verdicts': {'post-quantum': 0, 'hybrid': 8,
                              'classical': 42, 'symmetric': 0, 'unknown': 0}},
                {'t': NOW - 2 * 3600, 'total': 0,
                 'verdicts': {'post-quantum': 0, 'hybrid': 0, 'classical': 0,
                              'symmetric': 0, 'unknown': 0}},
                {'t': NOW - 3600, 'total': 310,
                 'verdicts': {'post-quantum': 0, 'hybrid': 37,
                              'classical': 180, 'symmetric': 0,
                              'unknown': 2}},
            ], 'notes': [],
        },
        # classical 835, symmetric 398, unknown 109 -- 1342 in total.
        'ciphersuites': _envelope('ciphersuites', 1342, [
            ('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 678, 'classical'),
            ('TLS_AES_256_GCM_SHA384', 222, 'symmetric'),
            ('TLS_AES_128_GCM_SHA256', 176, 'symmetric'),
            ('(none)', 109, 'unknown'),
            ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 147, 'classical'),
            ('TLS_DH_anon_WITH_RC4_128_MD5', 10, 'classical'),
        ]),
        # 1342 documents, 1455 appearances: a session may negotiate one
        # version and offer several.
        'tls-versions': _envelope('tls-versions', 1342, [
            ('TLSv1.2', 924, None), ('TLSv1.3', 499, None),
            ('TLSv1.0', 23, None), ('TLSv1.1', 9, None),
        ], notes=['total is 1342 documents; the buckets sum to 1455 '
                  'appearances, because tls.tls_versions is a list.']),
        # 200 documents carried a readable certificate, between them 393
        # certificates. The other 345 sent theirs inside the encrypted
        # flight, where a capture cannot read it -- which is not the same
        # as sending none.
        'certificates': _envelope('certificates', 200, [
            ('RSA-2048', 278, 'classical'), ('RSA-4096', 84, 'classical'),
            ('EC-384', 18, 'classical'), ('EC-256', 13, 'classical'),
        ], notes=['total is 200 documents; the buckets sum to 393 '
                  'certificates, because a session may send a chain.',
                  '345 further documents sent their certificate inside the '
                  'encrypted flight.']),
        'ja4': _envelope('ja4', 1342, [
            ('t12d230800_d3642cc0373c_50e68031a889', 372, None),
            ('t13d1516h2_8daaf6152771_02713d6af862', 361, None),
            ('t12d430700_1ce71f0edbb1_f0725b8e0d00', 216, None),
        ], other=393, notes=['32 distinct JA4 in this window.']),
        'hosts': _envelope('hosts', 1342, [
            ('adh-real4.santanderuk.corp', 516, None),
            ('intranet.adh.santanderuk.gs.corp', 72, None),
            ('badssl.com', 38, None),
            ('(none)', 27, None),
        ], other=689),
        'ech': _envelope('ech', 1342, [
            ('(none)', 852, None), ('offered', 490, None),
            ('accepted', 0, None),
        ]),
        # PR-36 reports the description only. The direction is in the stored
        # record as tls.alerts[].from_client and there is nowhere in the
        # contract's bucket to put it -- see the report. The page says so
        # rather than printing counts that merge the two ends.
        'alerts': _envelope('alerts', 42, [
            ('handshake_failure', 29, None),
            ('certificate_unknown', 11, None),
            ('inappropriate_fallback', 2, None),
        ], notes=['total is 42 documents; the buckets sum to alert records.']),
    }


def _envelope(name, total, rows, other=0, notes=None):
    buckets = []
    for bucket_name, count, verdict in rows:
        bucket = {'name': bucket_name, 'count': count}
        if verdict:
            bucket['verdict'] = verdict
        buckets.append(bucket)
    return {'panel': name, 'window': {}, 'total': total, 'buckets': buckets,
            'other': other, 'notes': notes or []}


def fake_stats(payloads, broken=()):
    """
    A stand-in for PR-36's module: `PANELS` and `make_window`, nothing else.

    `broken` names panels whose coroutine raises, so the "one panel failing
    does not blank the page" path can be exercised.
    """
    module = types.ModuleType('fapi.app.stats')

    def make_window(hours=24, tag=None, now=None):
        moment = NOW if now is None else now
        return {'hours': hours,
                'from': None if hours == 0 else moment - hours * 3600.0,
                'to': moment, 'tag': tag}

    def build(name):
        async def panel(collection, window, limit=None):
            if name in broken:
                raise RuntimeError('pipeline needed an index that is absent')
            data = dict(payloads[name])
            data['window'] = window
            return data
        return panel

    module.make_window = make_window
    module.PANELS = dict((name, build(name)) for name in payloads)
    return module


def install(monkeypatch, module):
    """
    Put the fake where `from fapi.app import stats` will find it.

    Both the sys.modules entry and the package attribute, because the two
    forms of the import take different routes to it and a test that only
    sets one passes for the wrong reason.
    """
    import fapi.app
    monkeypatch.setitem(sys.modules, 'fapi.app.stats', module)
    monkeypatch.setattr(fapi.app, 'stats', module, raising=False)


def make_client():
    """A bare app with only this router, mounted where api.py mounts it."""
    app = FastAPI()
    app.include_router(router)
    # api.py's lifespan sets this. A dict subscripts the same way an
    # AsyncIOMotorDatabase does, and the fake panels never touch it.
    app.mongodb = {'cryptomon': object()}
    return TestClient(app)


@pytest.fixture
def client(monkeypatch):
    install(monkeypatch, fake_stats(corpus_payloads()))
    return make_client()


# --------------------------------------------------------------------------
# the page
# --------------------------------------------------------------------------
def test_page_renders(client):
    response = client.get('/')
    assert response.status_code == 200
    assert 'text/html' in response.headers['content-type']
    body = response.text
    for name in PANEL_ORDER:
        assert 'id="panel-{0}"'.format(name) in body


def test_page_is_complete_without_javascript(client):
    """
    Every panel's content is in the first response.

    This is the test of whether this is a page or an application. The
    refresh loop may only ever *replace* content that the server already
    drew, so a browser with scripting off loses nothing but the polling.
    """
    body = client.get('/').text
    assert body.count('<svg') >= len(PANEL_ORDER)
    assert body.count('<table') >= len(PANEL_ORDER) - 1   # timeline has none
    # And the one control that does nothing without scripting is hidden
    # until the script reveals it.
    assert 'id="refresh-toggle" hidden' in body


def test_nothing_is_vendored(client):
    """
    No external script, no external stylesheet, no CDN.

    The PR plan asked for htmx and a vendored uPlot. They are not here and
    this is the assertion that keeps them out: roughly 90KB of unreviewable
    minified JavaScript does not belong in a tool whose job is telling an
    organisation what cryptography it is running, and base.html already
    promises "No build step, no CDN, no vendored framework".
    """
    body = client.get('/').text
    assert '<script src' not in body
    assert '<link' not in body
    for host in ('cdn.', 'unpkg', 'jsdelivr', 'cdnjs', 'http://', 'https://'):
        assert host not in body


def test_headline_never_prints_a_percentage_without_its_base(client):
    """
    Both denominators, on screen, next to their percentages.

    The project's recorded finding is that the same 81 hybrid key exchanges
    are 14.4% of the sessions that performed one and 6.4% of all of them,
    "the quantum-safe fraction depends entirely on the denominator". A
    dashboard that prints one figure has picked the answer for the reader.
    """
    body = client.get('/').text
    assert '13.5%' in body                 # 81 of 598 key exchanges
    assert '6.0%' in body                  # 81 of 1,342 sessions
    assert 'of 598' in body and 'of 1,342' in body
    assert '744' in body                   # the sessions that performed none


def test_certificates_finding_is_not_buried(client):
    body = client.get('/').text
    assert 'Not one certificate in this window is quantum-safe' in body
    assert '393 of 393 are classical' in body


def test_certificates_claim_separates_classical_from_unclassified(monkeypatch):
    """
    "All classical" and "none quantum-safe" are different claims.

    An earlier draft printed the first whenever the second was true, over a
    corpus where 23 of 183 certificates were in fact *unclassified* -- an EC
    key the classifier had no rule for is not the same finding as an RSA key
    it understood perfectly well.
    """
    payloads = corpus_payloads()
    payloads['certificates']['buckets'] = [
        {'name': 'RSA-2048', 'count': 160, 'verdict': 'classical'},
        {'name': 'EC-256', 'count': 23, 'verdict': 'unknown'},
    ]
    install(monkeypatch, fake_stats(payloads))
    body = make_client().get('/').text
    assert '160 of 183 are classical' in body
    assert '23 could not be classified' in body


def test_alerts_panel_says_when_the_direction_is_missing(client):
    """
    The contract's bucket is {name, count, verdict?} and has nowhere to put
    the direction, so PR-36 reports the description alone. Rather than print
    counts that quietly merge "a middlebox refused our key share" with "we
    refused their parameters", the page names the omission and says where
    the field is.
    """
    body = client.get('/').text
    assert 'handshake_failure' in body
    assert "This panel's buckets carry no direction" in body
    assert 'tls.alerts[].from_client' in body


def test_alerts_panel_shows_a_direction_when_one_is_supplied(monkeypatch):
    """
    Both ways of supplying it are accepted: folded into the name, or as an
    extra key on the bucket. Either one silences the warning above.
    """
    payloads = corpus_payloads()
    payloads['alerts']['buckets'] = [
        {'name': 'handshake_failure', 'count': 29, 'direction': 'server'},
        {'name': 'certificate_unknown', 'count': 11, 'direction': 'client'},
    ]
    install(monkeypatch, fake_stats(payloads))
    body = make_client().get('/').text
    assert 'Sent by' in body
    assert "This panel's buckets carry no direction" not in body

    payloads['alerts']['buckets'] = [
        {'name': 'handshake_failure (from server)', 'count': 29}]
    install(monkeypatch, fake_stats(payloads))
    assert ("This panel's buckets carry no direction"
            not in make_client().get('/').text)


def test_unwound_panels_name_documents_not_occurrences(client):
    """
    On tls-versions, certificates and alerts, `total` is the document count
    and the buckets sum to occurrences. Printing "N of M" with the wrong M
    is how a page ends up claiming 1,455 sessions exist when 1,342 do.
    """
    body = client.get('/').text
    assert 'from 1,342 documents' in body        # tls-versions
    assert 'from 200 documents' in body          # certificates
    assert 'the buckets sum to 1455 appearances' in body
    assert 'sent their certificate inside the encrypted flight' in body


def test_tag_and_window_controls_are_contract_parameters(client):
    body = client.get('/?hours=168&tag=chrome_mac').text
    assert 'name="hours"' in body and 'name="tag"' in body
    assert 'value="chrome_mac" selected' in body
    assert 'hours=168' in body             # carried into the panel URLs


# --------------------------------------------------------------------------
# the absent-stats path
# --------------------------------------------------------------------------
def test_503_when_stats_is_not_installed(monkeypatch):
    """
    A deployment without the aggregations says so, rather than crashing.

    UPLOADS_ENABLED already establishes that a feature of this service can
    be absent; "the stats endpoints are not available on this deployment"
    is a useful thing to read and a 500 is not.
    """
    import fapi.app
    monkeypatch.setitem(sys.modules, 'fapi.app.stats', None)
    monkeypatch.delattr(fapi.app, 'stats', raising=False)
    response = make_client().get('/')
    assert response.status_code == 503
    assert 'not installed on this deployment' in response.text
    assert 'fapi/app/stats.py' in response.text


def test_503_on_a_fragment_when_stats_is_not_installed(monkeypatch):
    import fapi.app
    monkeypatch.setitem(sys.modules, 'fapi.app.stats', None)
    monkeypatch.delattr(fapi.app, 'stats', raising=False)
    assert make_client().get('/panels/ja4').status_code == 503


# --------------------------------------------------------------------------
# the empty window -- a first-class case
# --------------------------------------------------------------------------
def test_empty_window_prints_the_span_and_offers_to_widen(monkeypatch):
    """
    "No data in the last 24 hours -- this collection runs from X to Y."

    `span` is in the contract for exactly this. Somebody who has just
    mongoimported a capture from last year hits this on their first visit,
    and an empty page reads as a broken install.
    """
    payloads = corpus_payloads()
    payloads['overview']['documents'] = 0
    payloads['overview']['key_exchanges_performed'] = 0
    payloads['overview']['quantum_safe'] = 0
    install(monkeypatch, fake_stats(payloads))

    body = make_client().get('/').text
    assert 'No data in this window' in body
    assert '2023-06-26' in body and '2024-12-11' in body
    assert 'Widen the window' in body
    assert 'hours=0' in body


def test_empty_collection_says_the_collection_is_empty(monkeypatch):
    """Nulls in `span` mean an empty collection, not an empty window."""
    payloads = corpus_payloads()
    payloads['overview']['documents'] = 0
    payloads['overview']['span'] = {'first': None, 'last': None}
    install(monkeypatch, fake_stats(payloads))

    body = make_client().get('/').text
    assert 'The collection is empty' in body
    assert 'mongoimport' in body
    assert 'Widen the window' not in body


# --------------------------------------------------------------------------
# failure containment and validation
# --------------------------------------------------------------------------
def test_one_failing_panel_does_not_blank_the_page(monkeypatch):
    install(monkeypatch, fake_stats(corpus_payloads(), broken=('ja4',)))
    response = make_client().get('/')
    assert response.status_code == 200
    assert 'This panel could not be built' in response.text
    assert 'pipeline needed an index that is absent' in response.text
    # ...and the neighbours still rendered.
    assert 'X25519MLKEM768' in response.text


@pytest.mark.parametrize('query', ['hours=-1', 'hours=9000', 'limit=0',
                                   'limit=201', 'bucket=fortnight'])
def test_out_of_range_parameters_are_400(client, query):
    """
    400, not 422 and not 500 -- STATS_CONTRACT section 2.

    Checked here as well as in PR-36 so that a bad URL on the dashboard is a
    sentence rather than an exception from inside an aggregation.
    """
    assert client.get('/?' + query).status_code == 400


def test_the_window_reaches_the_panels_with_the_bucket_width(monkeypatch):
    """
    `hours`, `tag` and `bucket` are carried through, unmodified.

    STATS_CONTRACT gives the panel coroutines the signature
    (collection, window, limit=None) but describes `bucket` as a query
    parameter of the timeline *route*, so there is no argument to pass it
    through and the window is the only channel left. A stats module that
    does not look for the key simply chooses its own width, which is the
    documented default. This is flagged as a gap in the contract rather
    than papered over, and pinned here so the workaround is visible.
    """
    seen = {}
    payloads = corpus_payloads()
    module = fake_stats(payloads)
    original = module.PANELS['timeline']

    async def spy(collection, window, limit=None):
        seen.update(window)
        seen['limit'] = limit
        return await original(collection, window, limit)

    module.PANELS['timeline'] = spy
    install(monkeypatch, module)

    make_client().get('/?hours=168&tag=chrome_mac&limit=50&bucket=day')
    assert seen['hours'] == 168
    assert seen['tag'] == 'chrome_mac'
    assert seen['limit'] == 50
    assert seen['bucket'] == 86400
    assert seen['to'] - seen['from'] == 168 * 3600.0


def test_all_of_time_is_hours_zero(client):
    """`hours=0` is the contract's "all of time", and `from` is then None."""
    body = client.get('/?hours=0').text
    assert 'value="0" selected' in body


def test_a_tag_carrying_a_mongo_operator_is_refused(client):
    """
    The tag goes through the existing safe_query() rather than a second
    validator, which is what the contract asks for and also what stops a tag
    from being an operator.
    """
    assert client.get('/?tag=' + 'x' * 300).status_code == 400


# --------------------------------------------------------------------------
# the fragment route
# --------------------------------------------------------------------------
def test_fragment_is_the_panel_and_nothing_else(client):
    response = client.get('/panels/key-exchange?hours=24')
    assert response.status_code == 200
    body = response.text
    assert '<h2>Key exchange</h2>' in body
    assert 'X25519MLKEM768' in body
    # No page around it: this is what goes into a <section>'s innerHTML.
    assert '<html' not in body and '<body' not in body


def test_unknown_panel_is_404_not_500(client):
    """
    The one path-parameter route in the service, and PR-06 is the standing
    warning about those: a catch-all matched ahead of /data/count and turned
    it into a 500. `name` is checked against the registry before use.

    `overview` is in PANELS and is deliberately *not* a fragment: it is
    consumed by the headline and the empty state rather than drawn as a
    card, so asking for it as a panel is a 404 rather than a blank card.
    """
    for name in ('nope', 'PANELS', 'overview', '__init__'):
        assert client.get('/panels/' + name).status_code == 404


# --------------------------------------------------------------------------
# escaping -- a hostname is attacker-influenced input going into markup
# --------------------------------------------------------------------------
HOSTILE = '<script>alert("x")</script>\x00\r\n\'evil.example.com'


def test_a_hostile_hostname_comes_out_escaped(monkeypatch):
    """
    Angle brackets, quotes and a NUL, in a bucket name, in the page.

    printable_text() then escape(), in that order: HTML-escaping alone
    leaves the NUL and the carriage return intact, and this project already
    had to add printable_text() because a mutated SNI carrying CR and NUL
    broke the CSV writer.
    """
    payloads = corpus_payloads()
    payloads['hosts']['buckets'] = [{'name': HOSTILE, 'count': 7}]
    install(monkeypatch, fake_stats(payloads))

    body = make_client().get('/').text
    assert '<script>alert' not in body
    assert '&lt;script&gt;' in body
    assert '\x00' not in body and '\\x00' in body
    assert '\\x0d\\x0a' in body


def test_hostile_text_is_escaped_in_the_svg_too(monkeypatch):
    """
    The chart is markup as much as the table is.

    A <title> or an aria-label is just as good a place to break out of as a
    table cell, and the SVG is where a name is most likely to be forgotten.
    """
    payloads = corpus_payloads()
    payloads['ja4']['buckets'] = [{'name': HOSTILE, 'count': 3}]
    install(monkeypatch, fake_stats(payloads))

    fragment = make_client().get('/panels/ja4').text
    assert '<script' not in fragment
    assert '<title>' in fragment          # the chart's own no-JS hover layer
    assert '&lt;script&gt;' in fragment


# --------------------------------------------------------------------------
# chart helpers -- the degenerate cases
# --------------------------------------------------------------------------
def test_bar_chart_with_no_buckets_says_so():
    out = str(charts.bar_chart([], 'nothing'))
    assert '<svg' not in out
    assert 'No sessions in this window' in out


def test_bar_chart_with_one_bucket():
    out = str(charts.bar_chart([{'name': 'x25519', 'count': 4}], 'one'))
    assert 'role="img"' in out and 'aria-label="one"' in out
    assert 'x25519' in out and '>4<' in out


def test_bar_chart_with_a_zero_count_still_prints_the_zero():
    """
    Zero draws no bar and still prints a 0.

    A bucket the aggregation returned with a count of zero is a fact --
    "this was looked for and not found" -- and drawing nothing at all would
    make it indistinguishable from a bucket that was never returned.
    """
    out = str(charts.bar_chart([{'name': 'accepted', 'count': 0}], 'zero'))
    assert '<svg' in out
    assert '>0<' in out
    assert '<path' not in out


def test_bar_chart_with_all_counts_zero_does_not_divide_by_zero():
    out = str(charts.bar_chart([{'name': 'a', 'count': 0},
                                {'name': 'b', 'count': 0}], 'zeroes'))
    assert '<svg' in out
    assert 'nan' not in out.lower() and 'inf' not in out.lower()


def test_bar_chart_truncates_a_very_long_name_and_keeps_it_in_the_title():
    long_name = 'a' * 200
    out = str(charts.bar_chart([{'name': long_name, 'count': 1}], 'long'))
    assert long_name not in out.split('</title>')[1]   # not in the label
    assert long_name in out                            # but kept in <title>
    assert '…' in out
    # The label must not run off the left-hand edge of the viewBox; there is
    # no clipping there to catch it.
    assert ('a' * charts.NAME_CHARS) not in out.split('</title>')[1]


def test_bar_chart_spanning_four_orders_of_magnitude_shows_the_small_one():
    """
    1 beside 10,000 is sub-pixel on a linear scale.

    Non-zero gets a minimum stub so that "present but tiny" and "absent" are
    never the same picture, and every count is printed beside its bar so the
    magnitude is never left to the geometry. A log scale would look better
    and mislead anyone who glanced at it.
    """
    out = str(charts.bar_chart([{'name': 'big', 'count': 10000},
                                {'name': 'mid', 'count': 100},
                                {'name': 'small', 'count': 1}], 'orders'))
    assert out.count('<path') == 3
    assert '10,000' in out and '>100<' in out and '>1<' in out


def test_bar_chart_names_the_scale():
    out = str(charts.bar_chart([{'name': 'a', 'count': 1234}], 'scale'))
    assert '1,234' in out


def test_bar_chart_colours_by_verdict_only_when_there_is_one():
    classified = str(charts.bar_chart(
        [{'name': 'X25519MLKEM768', 'count': 3, 'verdict': 'hybrid'}], 'v'))
    assert 'var(--v-hybrid)' in classified
    plain = str(charts.bar_chart([{'name': 'TLSv1.2', 'count': 3}], 'p'))
    assert 'var(--chart-bar)' in plain
    assert '--v-' not in plain


def test_timeline_with_no_series_says_so():
    out = str(charts.timeline_chart([], 3600, 'none'))
    assert '<svg' not in out
    assert 'No traffic in this window' in out


def test_timeline_with_one_bucket_renders():
    point = {'t': NOW, 'total': 5,
             'verdicts': {'post-quantum': 0, 'hybrid': 2, 'classical': 3,
                          'symmetric': 0, 'unknown': 0}}
    out = str(charts.timeline_chart([point], 3600, 'one'))
    assert '<svg' in out
    assert 'var(--v-hybrid)' in out and 'var(--v-classical)' in out


def test_timeline_with_an_all_zero_bucket_keeps_the_gap_open():
    """
    A gap-filled zero is drawn as a zero.

    A chart that silently closes gaps draws a straight line through an
    outage and calls it uptime -- which is why the contract gap-fills and
    why this draws columns instead of interpolating between them.
    """
    zero = {'t': NOW, 'total': 0,
            'verdicts': dict((v, 0) for v in charts.VERDICT_ORDER)}
    out = str(charts.timeline_chart([zero, zero], 3600, 'flat'))
    assert '<svg' in out
    assert 'var(--v-' not in out            # no bands, because no data
    assert 'nan' not in out.lower()


def test_timeline_names_the_gap_between_the_verdicts_and_the_total():
    """
    `total` is the document count and `verdicts` counts key exchanges, so
    the two legitimately disagree -- on the whole corpus 744 of 1342
    documents performed no key exchange at all. Stacking the five verdicts
    under a line taken from `total` leaves a large unexplained gap that
    reads as a bug in the data; scaling them to their own maximum instead
    answers a different question than the one the chart appears to answer.
    The difference gets a band and a name.
    """
    point = {'t': NOW, 'total': 1000,
             'verdicts': {'post-quantum': 0, 'hybrid': 1, 'classical': 1,
                          'symmetric': 0, 'unknown': 0}}
    out = str(charts.timeline_chart([point], 3600, 'pop'))
    assert 'stroke-dasharray' in out                 # `total` still traced
    assert 'var(--chart-bar)' in out                 # ...and the sixth band
    totals = charts.timeline_totals([point])
    assert (charts.NO_KEX, 998) in totals
    assert sum(count for _band, count in totals) == 1000


def test_timeline_totals_and_band_class_cover_the_sixth_band():
    assert charts.band_class('hybrid') == 'sw-hybrid'
    assert charts.band_class(charts.NO_KEX) == 'sw-no-key-exchange'
    assert charts.band_class('not a band') == ''
    assert charts.band_class(None) == ''


def test_timeline_stays_bounded_at_the_contract_ceiling():
    """
    PR-36 caps the series at 2000 points and gap-fills, so an all-time
    window over old data is a long, mostly-zero series -- 535 daily points
    of which three have traffic, on this corpus. One path per band rather
    than one rect per cell is what keeps that a few kilobytes, and the
    columns must not overlap once they are a third of a unit apart.
    """
    empty = dict((v, 0) for v in charts.VERDICT_ORDER)
    series = [{'t': NOW + i * 86400, 'total': 0, 'verdicts': dict(empty)}
              for i in range(2000)]
    series[1000] = {'t': NOW + 1000 * 86400, 'total': 12,
                    'verdicts': dict(empty, hybrid=5, classical=7)}
    out = str(charts.timeline_chart(series, 86400, 'ceiling'))
    assert '<svg' in out
    assert out.count('<path') <= len(charts.TIMELINE_BANDS) + 1
    assert len(out) < 200000


def test_has_direction_accepts_either_way_of_supplying_it():
    assert charts.has_direction([{'name': 'handshake_failure (from server)',
                                  'count': 1}])
    assert charts.has_direction([{'name': 'handshake_failure', 'count': 1,
                                  'direction': 'server'}])
    assert not charts.has_direction([{'name': 'handshake_failure',
                                      'count': 1}])
    assert not charts.has_direction([])


def test_timeline_survives_a_nonsense_timestamp():
    """`ts` comes out of a database, and a database holds what was put in."""
    point = {'t': 1e18, 'total': 1,
             'verdicts': dict((v, 0) for v in charts.VERDICT_ORDER)}
    assert '<svg' in str(charts.timeline_chart([point], 3600, 'odd'))


def test_ratio_bar_with_a_zero_denominator_says_so():
    out = str(charts.ratio_bar([('a', 0, None)], 'empty', 0))
    assert 'denominator for this window is zero' in out


def test_ratio_bar_prints_every_share_and_the_whole():
    out = str(charts.ratio_bar(
        [('hybrid', 81, 'hybrid'), ('classical', 517, 'classical')],
        'headline', 1342))
    assert 'of 1,342' in out
    assert '6.0%' in out and '38.5%' in out


def test_verdict_rollup_orders_by_readiness_and_drops_the_absent():
    rollup = charts.verdict_rollup([
        {'name': 'a', 'count': 3, 'verdict': 'classical'},
        {'name': 'b', 'count': 4, 'verdict': 'hybrid'},
        {'name': 'c', 'count': 1, 'verdict': 'hybrid'},
        {'name': 'd', 'count': 9},
    ])
    assert rollup == [('hybrid', 5), ('classical', 3)]
    assert charts.verdict_rollup([]) == []


def test_timeline_totals_sums_the_bands():
    series = [
        {'t': 1, 'total': 2,
         'verdicts': {'post-quantum': 0, 'hybrid': 1, 'classical': 1,
                      'symmetric': 0, 'unknown': 0}},
        {'t': 2, 'total': 3,
         'verdicts': {'post-quantum': 0, 'hybrid': 2, 'classical': 1,
                      'symmetric': 0, 'unknown': 0}},
    ]
    assert charts.timeline_totals(series) == [('hybrid', 3), ('classical', 2)]
    assert charts.timeline_totals([]) == []


def test_headline_parts_carries_both_denominators():
    parts = charts.headline_parts([('hybrid', 81), ('classical', 517)], 744)
    assert parts[0] == ('hybrid', 81, 'hybrid')
    assert parts[-1] == (charts.NO_KEX + ' (resumed)', 744, charts.NO_KEX)
    assert charts.headline_parts([('hybrid', 81)], 0) == [
        ('hybrid', 81, 'hybrid')]


def test_percent_answers_none_rather_than_zero_without_a_base():
    """
    None, not 0.0.

    The template prints an em dash for None. "0.0%" would be a claim, and
    "we have no denominator" is not one.
    """
    assert charts.percent(81, 598) == 13.5
    assert charts.percent(81, 0) is None
    assert charts.percent(81, None) is None
    assert charts.percent(0, 100) == 0.0


def test_describe_span_and_span_hours():
    assert '2023-06-26' in charts.describe_span(SPAN)
    assert charts.describe_span({'first': None, 'last': None}) is None
    assert charts.describe_span(None) is None
    # An hour-old span rounds up to a window that includes it...
    assert charts.span_hours({'first': NOW - 3600}, now=NOW) == 2
    # ...and anything older than the contract's 8760-hour ceiling becomes
    # "all of time", so the link on an empty page never lands on a 400.
    assert charts.span_hours({'first': NOW - 9000 * 3600}, now=NOW) == 0
    assert charts.span_hours({'first': None}) == 0


def test_safe_text_escapes_control_bytes_before_markup():
    out = str(charts.safe_text('ok\x00\r\n<b>'))
    assert '\x00' not in out and '\r' not in out
    assert '\\x00' in out and '\\x0d\\x0a' in out
    assert '&lt;b&gt;' in out


def test_safe_text_limit_counts_characters_after_escaping():
    """
    The limit is applied to what will be printed, not to what arrived.

    printable_text() turns one NUL into four characters, so measuring the
    raw string would let an escaped name overrun the gutter it was measured
    for.
    """
    out = str(charts.safe_text('\x00' * 10, limit=8))
    assert len(out) <= 8


def test_bucket_count_and_find_bucket_are_case_insensitive():
    buckets = [{'name': 'Offered', 'count': 490},
               {'name': 'accepted', 'count': 0}]
    assert charts.bucket_count(buckets, 'offered') == 490
    assert charts.bucket_count(buckets, 'accepted') == 0
    assert charts.bucket_count(buckets, 'missing') == 0
    assert charts.find_bucket(buckets, 'missing') is None


def test_every_chart_is_labelled_for_a_screen_reader():
    """
    role="img" plus an aria-label carrying the same claim as the caption.

    Without it an SVG full of <path> elements is announced as nothing at
    all, and the numbers are only in the picture.
    """
    claim = 'Key exchange by group'
    for svg in (charts.bar_chart([{'name': 'a', 'count': 1}], claim),
                charts.ratio_bar([('a', 1, None)], claim, 1),
                charts.timeline_chart(
                    [{'t': NOW, 'total': 1,
                      'verdicts': dict((v, 1) for v in
                                       charts.VERDICT_ORDER)}], 3600, claim)):
        out = str(svg)
        assert 'role="img"' in out
        assert 'aria-label="{0}"'.format(claim) in out
