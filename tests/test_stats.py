"""
The `/stats/*` aggregations.

Most of this asserts on the **pipeline** rather than on the answer. An
assertion about the answer passes just as happily when a future rewrite
fetches every document and counts them in Python, which is exactly the
change this module exists to prevent; an assertion that stage one is an
indexable `$match` and that a `$group` does the counting does not. So the
fake collection here records what it was handed, and the tests read it.

The database-backed tests at the bottom are the other half: a pipeline can
be the right shape and still be rejected by a real server or wrong about
real documents. They are **not** marked `smoke` and they skip quickly when
there is no MongoDB, because CI has none -- with a short
serverSelectionTimeoutMS, so that a database-less run does not look hung.
"""
import asyncio
import os

import pytest

os.environ.setdefault("DB_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "cryptomon-test")

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from cryptomon import analysis                                 # noqa: E402
from cryptomon.alerts import describe_description              # noqa: E402
from fapi.app import stats                                     # noqa: E402

# Marked per test rather than per module: the merge gate must stay fast and
# database-free, and the bottom half of this file is neither.
smoke = pytest.mark.smoke


# --------------------------------------------------------------------------
# a collection that remembers what it was asked
# --------------------------------------------------------------------------
class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    async def to_list(self, length=None):
        return self.rows


class FakeCollection:
    """
    Records every pipeline and answers with whatever was queued.

    `answers` is a list of row-lists returned in order; anything not queued
    comes back empty, which is the shape every panel has to survive anyway.
    """

    def __init__(self, answers=None):
        self.pipelines = []
        self.kwargs = {}
        self.answers = list(answers or [])

    def aggregate(self, pipeline, **kwargs):
        self.pipelines.append(pipeline)
        self.kwargs = kwargs
        return FakeCursor(self.answers.pop(0) if self.answers else [])


def rows(*pairs):
    return [{'_id': name, 'count': count} for name, count in pairs]


def faceted(buckets, other=None):
    """What a `_bucket_pipeline` carrying a limit returns."""
    answer = {'buckets': buckets, 'other': []}
    if other is not None:
        answer['other'] = [{'_id': None, 'count': other}]
    return [answer]


def counted(n):
    return [{'count': n}]


def run(coroutine):
    return asyncio.run(coroutine)


def stages(pipeline):
    return [next(iter(stage)) for stage in pipeline]


def find_stage(pipeline, name):
    for stage in pipeline:
        if name in stage:
            return stage[name]
    return None


WINDOW = stats.make_window(hours=24, now=1_000_000.0)
ALL_TIME = stats.make_window(hours=0, now=1_000_000.0)

BUCKET_PANELS = ['key-exchange', 'ciphersuites', 'tls-versions',
                 'certificates', 'hosts', 'ja4', 'alerts', 'ech']


# --------------------------------------------------------------------------
# the window
# --------------------------------------------------------------------------
@smoke
def test_window_has_exactly_the_contract_keys():
    assert set(WINDOW) == {'hours', 'from', 'to', 'tag'}


@smoke
def test_window_arithmetic_is_epoch_seconds_not_dates():
    assert WINDOW['to'] == 1_000_000.0
    assert WINDOW['from'] == 1_000_000.0 - 24 * 3600
    assert isinstance(WINDOW['from'], float)
    assert WINDOW['tag'] is None


@smoke
def test_zero_hours_means_all_of_time():
    assert ALL_TIME['hours'] == 0
    assert ALL_TIME['from'] is None
    assert ALL_TIME['to'] == 1_000_000.0


@smoke
def test_window_defaults_to_now():
    import time
    before = time.time()
    window = stats.make_window()
    assert before <= window['to'] <= time.time()
    assert window['hours'] == 24


@smoke
@pytest.mark.parametrize('hours', [-1, 8761, 100000, 'soon', None])
def test_bad_hours_is_400(hours):
    with pytest.raises(Exception) as caught:
        stats.make_window(hours=hours)
    assert caught.value.status_code == 400


@smoke
@pytest.mark.parametrize('hours', [0, 1, 24, 8760])
def test_good_hours_accepted(hours):
    assert stats.make_window(hours=hours)['hours'] == hours


@smoke
@pytest.mark.parametrize('limit', [0, -1, 201, 'lots'])
def test_bad_limit_is_400(limit):
    with pytest.raises(Exception) as caught:
        stats.validate_limit(limit)
    assert caught.value.status_code == 400


@smoke
@pytest.mark.parametrize('limit', [1, 20, 200])
def test_good_limit_accepted(limit):
    assert stats.validate_limit(limit) == limit


@smoke
def test_no_limit_means_no_truncation():
    assert stats.validate_limit(None) is None


@smoke
def test_bad_bucket_is_400():
    with pytest.raises(Exception) as caught:
        stats.validate_bucket('fortnight')
    assert caught.value.status_code == 400


@smoke
def test_tag_goes_through_the_existing_validator():
    """safe_query's ceiling, not a second validator written here."""
    from fapi.app.query import MAX_VALUE_LENGTH
    with pytest.raises(Exception) as caught:
        stats.make_window(tag='x' * (MAX_VALUE_LENGTH + 1))
    assert caught.value.status_code == 400


@smoke
def test_empty_tag_is_no_filter():
    assert stats.make_window(tag='')['tag'] is None


# --------------------------------------------------------------------------
# the pipelines
# --------------------------------------------------------------------------
@smoke
@pytest.mark.parametrize('panel', BUCKET_PANELS)
def test_first_stage_is_an_indexable_match(panel):
    """
    Stage one filters on ts (or tag + ts), which is what the indexes cover.

    Anything else -- an $unwind first, a $project first -- makes the whole
    collection the input to the pipeline whatever the window said.
    """
    collection = FakeCollection()
    run(stats.PANELS[panel](collection, WINDOW, 20))
    assert collection.pipelines
    for pipeline in collection.pipelines:
        assert stages(pipeline)[0] == '$match', panel
        match = pipeline[0]['$match']
        assert match['ts'] == {'$gte': WINDOW['from'], '$lte': WINDOW['to']}


def _group_inside_facet(pipeline):
    facet = find_stage(pipeline, '$facet')
    if not facet:
        return False
    return any('$group' in stage or '$count' in stage
               for branch in facet.values() for stage in branch)


@smoke
@pytest.mark.parametrize('panel', BUCKET_PANELS)
def test_counting_happens_in_a_group_stage(panel):
    """No $group anywhere means the counting has moved into Python."""
    collection = FakeCollection()
    run(stats.PANELS[panel](collection, WINDOW, 20))
    grouped = [p for p in collection.pipelines
               if '$group' in stages(p) or _group_inside_facet(p)]
    assert grouped, panel


@smoke
@pytest.mark.parametrize('panel', BUCKET_PANELS)
def test_sort_precedes_the_limit(panel):
    """
    Truncation must drop the *smallest* buckets, not an arbitrary set.

    The limit lives inside the $facet so that `other` can be summed from
    what it dropped, which puts the $sort before the $facet.
    """
    collection = FakeCollection()
    run(stats.PANELS[panel](collection, WINDOW, 20))
    seen = False
    for pipeline in collection.pipelines:
        names = stages(pipeline)
        facet = find_stage(pipeline, '$facet') or {}
        if not any('$limit' in stage
                   for branch in facet.values() for stage in branch):
            continue
        seen = True
        assert names.index('$sort') < names.index('$facet')
        assert find_stage(pipeline, '$sort') == {'count': -1, '_id': 1}
    assert seen, panel


@smoke
@pytest.mark.parametrize('panel', list(stats.PANELS))
def test_no_forbidden_stages(panel):
    """
    $dateTrunc needs MongoDB 5.0 and buys nothing on a float epoch;
    $function, $accumulator and $where run caller-shaped code on the
    database server.
    """
    collection = FakeCollection()
    run(stats.PANELS[panel](collection, WINDOW, 20))
    text = repr(collection.pipelines)
    for forbidden in ('$dateTrunc', '$function', '$accumulator', '$where'):
        assert forbidden not in text, (panel, forbidden)


@smoke
@pytest.mark.parametrize('panel', list(stats.PANELS))
def test_disk_use_is_never_enabled(panel):
    collection = FakeCollection()
    run(stats.PANELS[panel](collection, WINDOW, 20))
    assert collection.kwargs == {}


@smoke
def test_all_of_time_drops_the_ts_bound_entirely():
    """
    `hours=0` is a scan by definition; leaving `ts <= now` in place would
    turn a sequential scan into an index walk and would drop any document
    whose clock ran fast.
    """
    collection = FakeCollection()
    run(stats.PANELS['ciphersuites'](collection, ALL_TIME, 20))
    assert 'ts' not in collection.pipelines[0][0]['$match']


@smoke
def test_tag_is_matched_exactly_alongside_ts():
    collection = FakeCollection()
    window = stats.make_window(hours=24, tag='win11_edge', now=1_000_000.0)
    run(stats.PANELS['hosts'](collection, window, 20))
    match = collection.pipelines[0][0]['$match']
    assert match['tag'] == 'win11_edge'
    # tag before ts, the order of the tag_ts index.
    assert list(match)[:2] == ['tag', 'ts']


@smoke
@pytest.mark.parametrize('panel,path', [
    ('tls-versions', '$tls.tls_versions'),
    ('certificates', '$tls.certificates'),
    ('alerts', '$tls.alerts')])
def test_list_valued_fields_are_unwound(panel, path):
    """A list field counted without $unwind counts lists, not entries."""
    collection = FakeCollection()
    run(stats.PANELS[panel](collection, WINDOW, 20))
    unwinds = [find_stage(p, '$unwind') for p in collection.pipelines]
    assert any(u and u['path'] == path for u in unwinds), panel


@smoke
def test_timeline_buckets_arithmetically():
    collection = FakeCollection()
    run(stats.timeline(collection, WINDOW))
    group = find_stage(collection.pipelines[0], '$group')
    assert group['_id']['bucket'] == {
        '$subtract': ['$ts', {'$mod': ['$ts', 3600]}]}


# --------------------------------------------------------------------------
# the envelope
# --------------------------------------------------------------------------
@smoke
def test_envelope_shape():
    collection = FakeCollection([faceted(rows(('x25519', 3)), other=0),
                                 counted(1)])
    answer = run(stats.key_exchange(collection, WINDOW, 20))
    assert set(answer) == {'panel', 'window', 'total', 'buckets', 'other',
                           'notes'}
    assert answer['panel'] == 'key-exchange'
    assert answer['window'] == WINDOW
    assert isinstance(answer['notes'], list)
    assert isinstance(answer['total'], int)


@smoke
def test_buckets_sort_by_count_then_name():
    collection = FakeCollection([faceted(rows(('b', 5), ('a', 5), ('c', 9)))])
    answer = run(stats.hosts(collection, WINDOW, 20))
    assert [b['name'] for b in answer['buckets']] == ['c', 'a', 'b']


@smoke
@pytest.mark.parametrize('raw', [None, ''])
def test_missing_names_become_the_none_string(raw):
    collection = FakeCollection([faceted(rows((raw, 4)))])
    answer = run(stats.hosts(collection, WINDOW, 20))
    assert answer['buckets'][0]['name'] == '(none)'


@smoke
def test_a_name_is_never_a_number():
    collection = FakeCollection([faceted(rows((443, 2)))])
    answer = run(stats.hosts(collection, WINDOW, 20))
    assert answer['buckets'][0]['name'] == '443'


@smoke
def test_other_is_what_the_limit_dropped():
    collection = FakeCollection([faceted(rows(('a', 10)), other=7)])
    answer = run(stats.ech(collection, WINDOW, 1))
    assert answer['other'] == 7
    # total counts everything that went into the panel, dropped included.
    assert answer['total'] == 17


@smoke
def test_other_is_zero_when_nothing_was_truncated():
    collection = FakeCollection([faceted(rows(('a', 10)))])
    assert run(stats.ech(collection, WINDOW, 20))['other'] == 0


@smoke
@pytest.mark.parametrize('panel', BUCKET_PANELS)
def test_empty_collection_gives_an_empty_panel_not_a_crash(panel):
    answer = run(stats.PANELS[panel](FakeCollection(), WINDOW, 20))
    assert answer['buckets'] == []
    assert answer['total'] == 0
    assert answer['other'] == 0


# --------------------------------------------------------------------------
# the verdicts
# --------------------------------------------------------------------------
@smoke
def test_verdicts_come_from_the_shared_table():
    collection = FakeCollection([
        faceted(rows(('X25519MLKEM768', 5), ('x25519', 7))), counted(0)])
    answer = run(stats.key_exchange(collection, WINDOW, 20))
    verdicts = {b['name']: b['verdict'] for b in answer['buckets']}
    assert verdicts['X25519MLKEM768'] == analysis.HYBRID
    assert verdicts['x25519'] == analysis.CLASSICAL


@smoke
def test_ml_dsa_is_not_pushed_into_the_hybrid_bucket():
    """
    The recorded finding this panel must not re-open: a naive substring
    match sees "dsa" inside ML-DSA and reports a pure post-quantum
    selection as a hybrid of itself and DSA. Deferring to
    cryptomon.analysis is what keeps that fix in one place; a `$switch` on
    the database server would be a second copy without it.
    """
    collection = FakeCollection([faceted(rows(('ML-DSA-65', 1))), counted(0)])
    answer = run(stats.key_exchange(collection, WINDOW, 20))
    assert answer['buckets'][0]['verdict'] == analysis.POST_QUANTUM


@smoke
@pytest.mark.parametrize('panel,name,expected', [
    ('key-exchange', 'X25519Kyber768Draft00', analysis.HYBRID),
    ('key-exchange', 'secp384r1', analysis.CLASSICAL),
    ('key-exchange', 'nonsense-group', analysis.UNKNOWN),
    ('ciphersuites', 'TLS_AES_256_GCM_SHA384', analysis.SYMMETRIC),
    ('ciphersuites', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
     analysis.CLASSICAL),
])
def test_verdict_strings_are_the_five(panel, name, expected):
    answers = [faceted(rows((name, 1)))]
    if panel == 'key-exchange':
        answers.append(counted(0))
    answer = run(stats.PANELS[panel](FakeCollection(answers), WINDOW, 20))
    assert answer['buckets'][0]['verdict'] == expected
    assert expected in stats.VERDICTS


@smoke
@pytest.mark.parametrize('panel,answers', [
    ('hosts', [faceted(rows(('a', 1)))]),
    ('ja4', [faceted(rows(('t13d', 1)))]),
    ('ech', [faceted(rows(('offered', 1)))]),
    ('tls-versions', [counted(1), faceted(rows(('TLSv1.3', 1)))])])
def test_only_classifying_panels_carry_a_verdict(panel, answers):
    answer = run(stats.PANELS[panel](FakeCollection(answers), WINDOW, 20))
    assert 'verdict' not in answer['buckets'][0], panel


@smoke
def test_no_key_exchange_is_a_note_and_never_a_bucket():
    """
    classify_key_exchange(None) answers 'none', which is not one of the
    five verdicts -- a resumed session performed no key exchange, and
    filing it under any verdict would report an event that did not happen.
    """
    collection = FakeCollection([faceted(rows(('x25519', 3))), counted(625)])
    answer = run(stats.key_exchange(collection, WINDOW, 20))
    assert [b['name'] for b in answer['buckets']] == ['x25519']
    assert any('625' in note for note in answer['notes'])
    assert all(b['verdict'] in stats.VERDICTS for b in answer['buckets'])


@smoke
def test_certificate_labels_and_verdicts_come_from_the_table():
    collection = FakeCollection([
        [{'documents': [{'count': 4}], 'unreadable': [{'count': 2}]}],
        faceted([{'_id': {'public_key_algorithm': 'RSA',
                          'public_key_size': 2048}, 'count': 9},
                 {'_id': {'public_key_algorithm': 'EC',
                          'public_key_size': 384,
                          'public_key_curve': 'secp384r1'}, 'count': 3}])])
    answer = run(stats.certificates(collection, WINDOW, 20))
    assert {b['name']: b['verdict'] for b in answer['buckets']} == {
        'RSA-2048': analysis.CLASSICAL, 'EC-384': analysis.CLASSICAL}
    assert answer['total'] == 4          # documents, not certificates
    assert any('2 further' in note for note in answer['notes'])


@smoke
def test_unreadable_certificate_keeps_the_tables_own_label():
    """
    classify_certificate answers 'unreadable' rather than None for a
    certificate that did not decode far enough to have a key. A None label
    becomes a None dict key, and one of those killed a whole JSON export.
    """
    collection = FakeCollection([
        [{'documents': [{'count': 1}], 'unreadable': []}],
        faceted([{'_id': {}, 'count': 1}])])
    answer = run(stats.certificates(collection, WINDOW, 20))
    assert answer['buckets'][0]['name'] == 'unreadable'
    assert answer['buckets'][0]['verdict'] == analysis.UNKNOWN


@smoke
def test_alert_names_come_from_the_alert_registry():
    """Two integers in the record; the registry is written down once."""
    collection = FakeCollection([
        counted(42),
        faceted(rows(({'description': 40, 'from_client': False}, 29),
                     ({'description': 46, 'from_client': True}, 11)))])
    answer = run(stats.alerts(collection, WINDOW, 20))
    assert [b['name'] for b in answer['buckets']] == [
        '{0} (server)'.format(describe_description(40)),
        '{0} (client)'.format(describe_description(46))]
    assert answer['total'] == 42


@smoke
def test_alerts_are_grouped_by_direction_as_well_as_code():
    """
    The direction is the half that carries the finding.

    Over the project corpus every handshake_failure came from the server and
    every certificate_unknown from the client. Grouped on the code alone
    those are one row each and "a middlebox refused our key share" reads the
    same as "we refused their parameters".
    """
    collection = FakeCollection([counted(2), faceted(rows())])
    run(stats.alerts(collection, WINDOW, 20))
    group = next(stage['$group'] for stage in collection.pipelines[-1]
                 if '$group' in stage)
    assert group['_id'] == {'description': '$tls.alerts.description',
                            'from_client': '$tls.alerts.from_client'}


@smoke
def test_an_alert_written_before_the_direction_was_recorded_has_no_suffix():
    """Absent is "not known", not a third direction."""
    collection = FakeCollection([
        counted(1), faceted(rows(({'description': 40}, 1)))])
    answer = run(stats.alerts(collection, WINDOW, 20))
    assert answer['buckets'][0]['name'] == describe_description(40)


@smoke
def test_unwind_panels_say_which_number_total_is():
    collection = FakeCollection([counted(1342),
                                 faceted(rows(('TLSv1.2', 924),
                                              ('TLSv1.3', 499)))])
    answer = run(stats.tls_versions(collection, WINDOW, 20))
    assert answer['total'] == 1342
    assert sum(b['count'] for b in answer['buckets']) == 1423
    assert any('1423' in note for note in answer['notes'])


# --------------------------------------------------------------------------
# overview and timeline
# --------------------------------------------------------------------------
def overview_answers(**branches):
    facet = {'documents': [], 'by_ptype': [], 'protocols': [],
             'key_exchange': [], 'certificates': [], 'hosts': [], 'ja4': [],
             'ech': [], 'alerts': [], 'tags': []}
    facet.update(branches)
    return [[facet], [{'ts': 1.0}], [{'ts': 9.0}]]


@smoke
def test_overview_keys_are_all_present_even_at_zero():
    answer = run(stats.overview(FakeCollection(overview_answers()), WINDOW))
    for key in ('panel', 'window', 'documents', 'by_ptype', 'span',
                'protocols', 'key_exchanges_performed', 'quantum_safe',
                'quantum_safe_percent', 'certificates', 'distinct_hosts',
                'distinct_ja4', 'ech_offered', 'ech_accepted', 'alerts',
                'tags', 'notes'):
        assert key in answer, key
    assert answer['quantum_safe_percent'] == 0.0
    assert answer['protocols'] == {'tls': 0, 'ssh': 0}
    assert answer['span'] == {'first': 1.0, 'last': 9.0}


@smoke
def test_overview_span_ignores_the_window():
    collection = FakeCollection(overview_answers())
    run(stats.overview(collection, WINDOW))
    span_pipelines = collection.pipelines[1:]
    assert len(span_pipelines) == 2
    for pipeline in span_pipelines:
        assert pipeline[0]['$match'] == {'ts': {'$exists': True}}
        assert '$limit' in stages(pipeline)


@smoke
def test_overview_empty_window_points_at_the_span():
    """
    The path somebody who imported last year's capture takes: the default
    window is empty, and the page has to say where the data actually is.
    """
    answer = run(stats.overview(FakeCollection(overview_answers()), WINDOW))
    assert answer['documents'] == 0
    assert any('hours=0' in note for note in answer['notes'])


@smoke
def test_overview_quantum_safe_counts_hybrid_and_post_quantum():
    collection = FakeCollection(overview_answers(
        documents=[{'count': 1027}],
        key_exchange=rows(('X25519MLKEM768', 45),
                          ('X25519Kyber768Draft00', 36),
                          ('x25519', 202), (None, 744))))
    answer = run(stats.overview(collection, WINDOW))
    assert answer['key_exchanges_performed'] == 283
    assert answer['quantum_safe'] == 81
    assert answer['quantum_safe_percent'] == round(100 * 81 / 283, 1)


@smoke
def test_overview_reports_both_document_shapes():
    collection = FakeCollection(overview_answers(
        documents=[{'count': 3}], by_ptype=rows(('client', 2), ('server', 1))))
    answer = run(stats.overview(collection, WINDOW))
    assert answer['by_ptype'] == {'client': 2, 'server': 1}
    assert any('frame' in note for note in answer['notes'])


@smoke
def test_timeline_is_gap_filled_with_all_five_verdicts():
    collection = FakeCollection([[
        {'_id': {'bucket': 1000.0, 'kex': 'x25519'}, 'count': 9},
        {'_id': {'bucket': 1000.0, 'kex': 'X25519MLKEM768'}, 'count': 3},
        {'_id': {'bucket': 1000.0 + 3 * 3600, 'kex': None}, 'count': 4}]])
    answer = run(stats.timeline(collection, WINDOW))
    assert answer['bucket_seconds'] == 3600
    assert [p['t'] for p in answer['series']] == [1000.0, 4600.0, 8200.0,
                                                  11800.0]
    assert answer['series'][0]['total'] == 12
    assert answer['series'][0]['verdicts'] == {
        analysis.POST_QUANTUM: 0, analysis.HYBRID: 3, analysis.CLASSICAL: 9,
        analysis.SYMMETRIC: 0, analysis.UNKNOWN: 0}
    # The empty buckets are real points. A chart that closes its gaps draws
    # a straight line through an outage and calls it uptime.
    assert answer['series'][1]['total'] == 0
    assert set(answer['series'][1]['verdicts']) == set(stats.VERDICTS)
    # A document that performed no key exchange is traffic and no verdict.
    assert answer['series'][3]['total'] == 4
    assert sum(answer['series'][3]['verdicts'].values()) == 0


@smoke
@pytest.mark.parametrize('hours,expected', [
    (1, 60), (24, 3600), (48, 3600), (24 * 30, 86400), (0, 86400)])
def test_timeline_bucket_width_follows_the_window(hours, expected):
    assert stats._choose_seconds({'hours': hours}, None) == expected


@smoke
def test_timeline_bucket_parameter_overrides():
    answer = run(stats.timeline(FakeCollection([[]]), WINDOW, bucket='day'))
    assert answer['bucket_seconds'] == 86400


@smoke
def test_a_query_parameter_cannot_ask_for_half_a_million_points():
    """
    `?bucket=minute&hours=8760` is 525,600 gap-filled points. The width is
    widened before the aggregation runs, not after -- re-bucketing the rows
    afterwards would already have paid for fetching them.
    """
    window = stats.make_window(hours=8760, now=1_000_000.0)
    answer = run(stats.timeline(FakeCollection([[]]), window,
                                bucket='minute'))
    assert answer['bucket_seconds'] == 86400
    assert any('widened' in note for note in answer['notes'])


@smoke
def test_empty_timeline_is_an_empty_series():
    answer = run(stats.timeline(FakeCollection([[]]), WINDOW))
    assert answer['series'] == []
    assert answer['panel'] == 'timeline'


# --------------------------------------------------------------------------
# the routes
# --------------------------------------------------------------------------
@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(stats.router, prefix="/stats")
    app.mongodb = {"cryptomon": FakeCollection()}
    return TestClient(app, raise_server_exceptions=False)


@smoke
@pytest.mark.parametrize('panel', list(stats.PANELS))
def test_registry_keys_are_the_url_segments(client, panel):
    response = client.get("/stats/" + panel)
    assert response.status_code == 200, response.text
    assert response.json()['panel'] == panel


@smoke
def test_no_catch_all_route():
    """
    PR-06: `GET /data/count` was swallowed by `/{id}` and handed to
    ObjectId(), which answered 500. A `{panel}` path parameter here would
    be the same defect under a different name.
    """
    for route in stats.router.routes:
        assert '{' not in route.path, route.path


@smoke
def test_index_lists_the_panels(client):
    body = client.get("/stats/").json()
    assert body['panels'] == list(stats.PANELS)
    assert body['window_defaults']['hours'] == 24
    assert body['window_defaults']['limit'] == 20
    assert set(body['span']) == {'first', 'last'}


@smoke
@pytest.mark.parametrize('url', [
    "/stats/overview?hours=-1",
    "/stats/key-exchange?hours=99999",
    "/stats/hosts?limit=0",
    "/stats/hosts?limit=201",
    "/stats/timeline?bucket=fortnight",
    "/stats/ja4?tag=" + "x" * 300,
])
def test_out_of_range_parameters_answer_400(client, url):
    response = client.get(url)
    assert response.status_code == 400, response.text


@smoke
def test_reads_need_no_write_credential(client):
    """Reads have always been open on this API, and /stats is a read."""
    from fapi.config import settings
    before = (settings.READ_ONLY, settings.API_KEY)
    settings.READ_ONLY, settings.API_KEY = True, 'secret'
    try:
        assert client.get("/stats/ciphersuites").status_code == 200
    finally:
        settings.READ_ONLY, settings.API_KEY = before


@smoke
@pytest.mark.parametrize('panel', list(stats.PANELS))
def test_panels_take_their_collection_as_an_argument(panel):
    """
    Never `request.app.mongodb` inside a panel: taking the collection as an
    argument is what makes every test above possible.
    """
    function = stats.PANELS[panel]
    assert function.__code__.co_varnames[:3] == ('collection', 'window',
                                                 'limit')


# --------------------------------------------------------------------------
# against a real MongoDB, when there is one
# --------------------------------------------------------------------------
# Not marked smoke. `STATS_TEST_DB_URL` points these at a server other than
# the default, which is how they were run against the project's corpus.
MONGO_URL = os.environ.get("STATS_TEST_DB_URL", "mongodb://127.0.0.1:27017")
LIVE_DB = "cryptomon_stats_selftest"


def session(ts, **tls):
    return {'ptype': 'session', 'ts': ts, 'tag': 'selftest',
            'tls': dict({'hostname': None, 'ech': None, 'ja4': None,
                         'ciphersuite': None, 'kex_group': None,
                         'tls_versions': None}, **tls)}


# Small, but deliberately covering every shape the panels have to survive:
# a list-valued tls_versions beside a string one, a session with no
# ciphersuite, a certificate chain of two, an alert, and an SSH session
# with no `tls` at all.
CORPUS = [
    session(1000.0, kex_group='x25519', ciphersuite='TLS_AES_128_GCM_SHA256',
            tls_versions=['TLSv1.3', 'TLSv1.2'], hostname='a.example',
            ja4='t13d1516h2_x_y', ech='offered'),
    session(1100.0, kex_group='X25519MLKEM768',
            ciphersuite='TLS_AES_256_GCM_SHA384', tls_versions='TLSv1.3',
            hostname='a.example', ja4='t13d1516h2_x_y', ech='offered',
            alerts=[{'level': 2, 'description': 40, 'from_client': False}]),
    session(1200.0, tls_versions='TLSv1.2', hostname='b.example',
            ja4='t12i_x_y',
            certificates=[{'public_key_algorithm': 'RSA',
                           'public_key_size': 2048,
                           'fingerprint_sha256': 'aa'},
                          {'public_key_algorithm': 'RSA',
                           'public_key_size': 4096,
                           'fingerprint_sha256': 'bb'}]),
    {'ptype': 'session', 'ts': 1300.0, 'tag': 'selftest',
     'ssh': {'KEXalgs': ['sntrup761x25519-sha512@openssh.com']}},
]

LIVE_WINDOW = {'hours': 0, 'from': None, 'to': 9999.0, 'tag': 'selftest'}


@pytest.fixture(scope="module")
def loaded():
    """
    A throwaway collection on a real server, or a skip.

    Loaded and dropped through pymongo rather than motor so that no event
    loop outlives a test: motor binds a client to the loop it was made in,
    and `live()` below therefore builds one inside each `asyncio.run`.
    """
    pytest.importorskip("motor.motor_asyncio")
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(MONGO_URL, serverSelectionTimeoutMS=500)
    try:
        client.admin.command('ping')
    except Exception as exc:
        client.close()
        pytest.skip("no MongoDB at {0} ({1})".format(MONGO_URL, exc))
    collection = client[LIVE_DB]["cryptomon"]
    collection.drop()
    collection.insert_many([dict(document) for document in CORPUS])
    collection.create_index([("ts", pymongo.DESCENDING)], name="ts_desc")
    collection.create_index([("tag", pymongo.ASCENDING),
                             ("ts", pymongo.DESCENDING)], name="tag_ts")
    yield collection
    client.drop_database(LIVE_DB)
    client.close()


def live(call):
    """Run `call(collection)` against the real server, loop and all."""
    import motor.motor_asyncio as motor_asyncio

    async def main():
        client = motor_asyncio.AsyncIOMotorClient(
            MONGO_URL, serverSelectionTimeoutMS=2000)
        try:
            return await call(client[LIVE_DB]["cryptomon"])
        finally:
            client.close()
    return asyncio.run(main())


@pytest.mark.parametrize('panel', list(stats.PANELS))
def test_every_pipeline_is_accepted_by_a_real_server(loaded, panel):
    """
    The fake above cannot tell a valid pipeline from an invalid one. This
    can: an empty $facet branch, a nested $facet, or a $group id the server
    will not accept fails here and nowhere else.
    """
    answer = live(lambda c: stats.PANELS[panel](c, LIVE_WINDOW, 20))
    assert answer['panel'] == panel


def test_real_counts(loaded):
    kex = live(lambda c: stats.key_exchange(c, LIVE_WINDOW, 20))
    assert kex['total'] == 2
    assert {b['name']: b['count'] for b in kex['buckets']} == {
        'x25519': 1, 'X25519MLKEM768': 1}
    # The SSH session has no `tls` and is not in the denominator either.
    assert any('1 of 3' in note for note in kex['notes'])

    versions = live(lambda c: stats.tls_versions(c, LIVE_WINDOW, 20))
    assert versions['total'] == 3        # three TLS documents
    assert {b['name']: b['count'] for b in versions['buckets']} == {
        'TLSv1.3': 2, 'TLSv1.2': 2}      # four version appearances

    certs = live(lambda c: stats.certificates(c, LIVE_WINDOW, 20))
    assert certs['total'] == 1
    assert {b['name']: b['count'] for b in certs['buckets']} == {
        'RSA-2048': 1, 'RSA-4096': 1}

    alerted = live(lambda c: stats.alerts(c, LIVE_WINDOW, 20))
    assert alerted['total'] == 1
    # The CORPUS alert carries from_client: False, and the direction is
    # part of the name -- see _alert_name.
    assert alerted['buckets'][0]['name'] == (
        '{0} (server)'.format(describe_description(40)))

    suites = live(lambda c: stats.ciphersuites(c, LIVE_WINDOW, 20))
    assert {b['name'] for b in suites['buckets']} == {
        'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', '(none)'}


def test_real_overview(loaded):
    answer = live(lambda c: stats.overview(c, LIVE_WINDOW))
    assert answer['documents'] == 4
    assert answer['by_ptype'] == {'session': 4}
    assert answer['protocols'] == {'tls': 3, 'ssh': 1}
    assert answer['key_exchanges_performed'] == 2
    assert answer['quantum_safe'] == 1
    assert answer['quantum_safe_percent'] == 50.0
    assert answer['certificates'] == 2
    assert answer['distinct_hosts'] == 2
    assert answer['distinct_ja4'] == 2
    assert answer['ech_offered'] == 2
    assert answer['ech_accepted'] == 0
    assert answer['alerts'] == 1
    assert answer['tags'] == ['selftest']
    assert answer['span'] == {'first': 1000.0, 'last': 1300.0}


def test_real_timeline(loaded):
    answer = live(lambda c: stats.timeline(c, LIVE_WINDOW, bucket='minute'))
    assert answer['bucket_seconds'] == 60
    assert [p['t'] for p in answer['series']] == [960.0, 1020.0, 1080.0,
                                                  1140.0, 1200.0, 1260.0]
    assert answer['series'][0]['verdicts'][analysis.CLASSICAL] == 1
    assert answer['series'][2]['verdicts'][analysis.HYBRID] == 1
    assert answer['series'][1]['total'] == 0


def test_empty_window_against_a_real_server(loaded):
    """
    A default window over an old capture matches nothing. Every panel has
    to answer a page rather than a crash, and overview has to say where the
    data actually is.
    """
    window = stats.make_window(hours=24, tag='selftest')
    for panel in stats.PANELS:
        answer = live(lambda c: stats.PANELS[panel](c, window, 20))
        if panel == 'overview':
            assert answer['documents'] == 0
            assert answer['span']['first'] == 1000.0
            assert any('hours=0' in note for note in answer['notes'])
        elif panel == 'timeline':
            assert answer['series'] == []
        else:
            assert answer['total'] == 0
            assert answer['buckets'] == []


def test_the_window_match_can_be_served_by_an_index(loaded):
    """
    An index-backed plan must exist for the standard pipeline's first
    stage. Asserted against the whole plan rather than the winning one:
    four documents are too few for the planner to prefer an index, and the
    claim being made is that `ts_desc` covers this query -- which is what
    says no new index belongs in fapi/app/indexes.py for these panels.
    """
    window = stats.make_window(hours=24)
    pipeline = stats._bucket_pipeline(
        stats._match(window, {'tls': {'$exists': True}}),
        '$tls.ciphersuite', 20)

    async def explain(collection):
        return await collection.database.command(
            'explain', {'aggregate': collection.name, 'pipeline': pipeline,
                        'cursor': {}}, verbosity='queryPlanner')

    plan = repr(live(explain))
    assert 'IXSCAN' in plan, plan[:2000]


@smoke
def test_alert_buckets_carry_the_direction_as_its_own_key():
    """
    The dashboard needs the sender in a column, not parsed out of a label.

    The name carries it too, spelled as `pcapscan.export._alert_label` spells
    it, so a CSV cell and a dashboard bar read the same. But `charts.py` was
    looking for either a `direction` key or the substring "from ", found
    neither in "handshake_failure (server)", and rendered a red block saying
    "the aggregation is not reporting it" directly above rows that plainly
    said (server) -- while the "Sent by" column never appeared at all.
    """
    collection = FakeCollection([
        counted(2),
        faceted(rows(({'description': 40, 'from_client': False}, 29),
                     ({'description': 46, 'from_client': True}, 11)))])
    answer = run(stats.alerts(collection, WINDOW, 20))
    assert [b.get('direction') for b in answer['buckets']] == \
        ['server', 'client']
