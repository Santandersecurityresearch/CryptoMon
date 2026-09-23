"""
`/stats/*` -- the rollups, counted in MongoDB.

Every number on this page is produced by an aggregation pipeline. Nothing
here pulls documents into Python and counts them, and that is the whole
point of the module rather than a style preference: the collection this
serves is fed at line rate by `cryptomon.py` and by `mongoimport` of a
723MB capture dump, and a `/stats` page that reads a million documents to
print twelve numbers is a denial of service somebody else can trigger.

Three rules hold everywhere below.

* **`$match` first, and on something indexed.** Every pipeline begins with a
  match on `ts`, or `tag` + `ts` -- the `ts_desc` and `tag_ts` indexes in
  `fapi/app/indexes.py`. The one exception is `hours=0`, which means "all of
  time" and is a collection scan by definition; there is no index that makes
  "give me everything" cheap, and pretending otherwise by leaving a
  `ts <= now` bound in place would only turn a sequential scan into a random
  one while quietly dropping any document whose clock ran fast.

* **The classification table is not copied.** `$group` reduces tens of
  millions of documents to tens of rows -- the whole 1342-session corpus
  holds six distinct key exchange groups -- and only then does Python ask
  `cryptomon.analysis` what each *name* means. Re-implementing the verdicts
  as a Mongo `$switch` would put a second copy of the table in a second
  language, and the second copy drifts. This project already has the
  worked example: the table's post-quantum markers are matched *and removed*
  before the classical ones, because ML-DSA and SLH-DSA both end in "dsa"
  and a naive substring match reports every NIST signature selection as a
  hybrid of itself and DSA. That fix lives in one function. A `$switch`
  would not have it. The same argument applies to `cryptomon.alerts` for
  the alert code names.

* **`allowDiskUse` stays off.** A pipeline on this collection that needs
  100MB of scratch is a pipeline that should have had an index, and the
  error is the signal. Nothing here passes it.

Two document shapes share the collection and a panel that assumes one of
them is wrong on somebody's deployment:

* the live eBPF path (`cryptomon/__init__.py:handle_data`) writes **one
  document per frame**, with `ptype` of `client` or `server`, `ts` set at
  insertion, and only the single-frame view of `tls`;
* `python -m pcapscan -f ndjson | mongoimport`
  (`pcapscan/sessions.py:document`) writes **one document per session**,
  with `ptype` of `session`, `ts` from the capture, and the fields that only
  a reassembled handshake has: `certificates`, `alerts`, `resumption`,
  `proposed`, `selected`, `ja4s`.

So `overview.by_ptype` is not decoration -- it is how a reader tells whether
`total` counts sessions or frames -- and every panel whose number changes
meaning between the two says so in `notes`.

`total` is always **the number of documents the panel counted**. For the
panels that `$unwind` a list the buckets sum to *occurrences* instead, which
is a different and larger number; each of those says which is which in
`notes`, because a certificate chain contributing three rows to a bar chart
that is labelled "sessions" is a lie told in units.
"""
import inspect
import time
from typing import Union

from fastapi import APIRouter, HTTPException, Query, Request, status

from cryptomon.alerts import describe_description
from cryptomon.analysis import (CLASSICAL, HYBRID, POST_QUANTUM, SYMMETRIC,
                                SYMMETRIC_BROKEN, UNKNOWN,
                                classify_certificate, classify_ciphersuite,
                                classify_key_exchange, symmetric_strength)
from fapi.app.query import safe_query

router = APIRouter()

# The five verdicts, taken from the classification table rather than
# retyped. A literal here would be a third copy of the same strings.
VERDICTS = (POST_QUANTUM, HYBRID, CLASSICAL, SYMMETRIC, UNKNOWN)

# A bucket name is always a non-empty string, so a missing, null or empty
# value gets this one. A null name reaches a chart library as a legend entry
# with no label and a tooltip that says "null", which reads as a bug in the
# page rather than as what it is: traffic where the field was not present.
NONE = '(none)'

DEFAULT_HOURS = 24
# A year. Beyond this the answer is `hours=0`, and the ceiling exists so
# that a hand-typed number cannot ask for a window arithmetic cannot hold.
MAX_HOURS = 8760
DEFAULT_LIMIT = 20
MIN_LIMIT = 1
MAX_LIMIT = 200

MINUTE, HOUR, DAY = 60, 3600, 86400
BUCKET_SECONDS = {'minute': MINUTE, 'hour': HOUR, 'day': DAY}
# Next size up, for the widening in `_series_seconds`. Each is a whole
# multiple of the one below it, which is what makes widening exact.
_WIDER = {MINUTE: HOUR, HOUR: DAY}

# A gap-filled series is one point per bucket whether or not there was
# traffic, so `?bucket=minute&hours=8760` asks for 525,600 points. The cap
# is the same class of defence as the one in `fapi/app/query.py`: a query
# parameter must not be able to choose how much work the server does.
MAX_SERIES_POINTS = 2000

# Distinct capture-run labels reported by `overview`. A long-running
# deployment relabels every run, so this is bounded and the truncation is
# stated rather than silent.
MAX_TAGS = 200


# --------------------------------------------------------------------------
# the window
# --------------------------------------------------------------------------
def make_window(hours=DEFAULT_HOURS, tag=None, now=None):
    """
    The time window every panel is scoped to, validated.

    `hours=0` means all of time, and then `from` is None -- see the module
    docstring for why that also removes the upper bound from the match.

    `from`/`to` are float epoch seconds because that is what `ts` is on both
    write paths (`dt.datetime.now().timestamp()` live, the pcap frame
    timestamp offline). They are deliberately *not* BSON dates: half the
    collection would then not match, and the mismatch would show up as an
    empty dashboard rather than as an error.

    Raises 400 rather than returning a broken window, so that a caller who
    skips the HTTP layer -- a test, the dashboard's server-side render --
    gets the same answer the route does.
    """
    hours = _validate_hours(hours)
    # `?tag=` is an empty box on a form, which means "no filter" and not
    # "documents whose tag is the empty string".
    if tag == '':
        tag = None
    if tag is not None:
        # One validator, not two. safe_query already knows which fields may
        # be filtered on and how long a value may be, and it answers 400.
        tag = safe_query({'tag': tag})['tag']
    to = float(time.time() if now is None else now)
    return {'hours': hours,
            'from': None if hours == 0 else to - hours * 3600.0,
            'to': to,
            'tag': tag}


def _bad_request(detail):
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                         detail=detail)


def _validate_hours(hours):
    """0 <= hours <= 8760, or 400."""
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        raise _bad_request("hours must be a whole number of hours.")
    if not 0 <= hours <= MAX_HOURS:
        raise _bad_request(
            "hours must be between 0 and {0}; 0 means all of time.".format(
                MAX_HOURS))
    return hours


def validate_limit(limit):
    """1 <= limit <= 200, or 400. None passes through as "no truncation"."""
    if limit is None:
        return None
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise _bad_request("limit must be a whole number.")
    if not MIN_LIMIT <= limit <= MAX_LIMIT:
        raise _bad_request("limit must be between {0} and {1}.".format(
            MIN_LIMIT, MAX_LIMIT))
    return limit


def validate_bucket(bucket):
    """One of minute/hour/day, or None to choose from the window. Else 400."""
    if bucket is None or bucket == '':
        return None
    if bucket not in BUCKET_SECONDS:
        raise _bad_request("bucket must be one of {0}.".format(
            ', '.join(sorted(BUCKET_SECONDS))))
    return bucket


def _match(window, *extra):
    """
    The first stage of every pipeline: tag, then the ts range.

    Written in that order because it is the order of the `tag_ts` index.
    Mongo does not care about key order when choosing a plan, but the next
    person reading this does, and the index it is meant to hit should be
    legible from the stage.
    """
    match = {}
    if window.get('tag') is not None:
        match['tag'] = window['tag']
    if window.get('from') is not None:
        match['ts'] = {'$gte': window['from'], '$lte': window['to']}
    for term in extra:
        match.update(term)
    return match


# --------------------------------------------------------------------------
# running a pipeline
# --------------------------------------------------------------------------
async def _run(collection, pipeline):
    """
    Run an aggregation and return its rows.

    motor's `aggregate()` returns a cursor synchronously rather than a
    coroutine, which is why this is not simply `await collection.aggregate`.
    The awaitable branch is there so a fake collection written the obvious
    way -- `async def aggregate` -- also works, since every panel takes its
    collection as an argument precisely so it can be tested against one.
    """
    cursor = collection.aggregate(pipeline)
    if inspect.isawaitable(cursor):
        cursor = await cursor
    return await cursor.to_list(length=None)


async def _count(collection, match):
    """How many documents the match selects, counted server-side."""
    rows = await _run(collection, [{'$match': match}, {'$count': 'count'}])
    # $count emits nothing at all for an empty result set, which is not the
    # same as emitting zero.
    return int(rows[0]['count']) if rows else 0


def _bucket_pipeline(match, key, limit=None, unwind=None, preserve=False):
    """
    The shape shared by every counting panel.

    `$match` (indexed) -> optionally `$unwind` -> `$group` -> `$sort` ->
    `$facet`, where the facet splits the already-grouped rows into the ones
    that survive `limit` and a single summed row for the ones that do not.
    The split is done in Mongo rather than by fetching every group and
    slicing in Python, because `hosts` groups by SNI and the number of
    distinct hostnames a network sees has no useful upper bound.
    """
    pipeline = [{'$match': match}]
    if unwind is not None:
        pipeline.append({'$unwind': {'path': unwind,
                                     'preserveNullAndEmptyArrays': preserve}})
    pipeline.append({'$group': {'_id': key, 'count': {'$sum': 1}}})
    # count first, then the value, so that the truncation `limit` performs
    # is "the smallest groups" and not "whichever groups came back first".
    pipeline.append({'$sort': {'count': -1, '_id': 1}})
    if limit is not None:
        pipeline.append({'$facet': {
            'buckets': [{'$limit': limit}],
            'other': [{'$skip': limit},
                      {'$group': {'_id': None,
                                  'count': {'$sum': '$count'}}}]}})
    return pipeline


async def _grouped(collection, match, key, limit=None, unwind=None,
                   preserve=False):
    """
    Run `_bucket_pipeline` and return (rows, other, counted).

    `counted` is sum(rows) + other -- how many *things* were grouped. For a
    panel with no `$unwind` that is also the document count; for one with an
    `$unwind` it is the number of list entries, and the panel supplies the
    document count separately.
    """
    pipeline = _bucket_pipeline(match, key, limit, unwind, preserve)
    rows = await _run(collection, pipeline)
    other = 0
    if limit is not None:
        faceted = rows[0] if rows else {}
        tail = faceted.get('other') or []
        other = int(tail[0]['count']) if tail else 0
        rows = faceted.get('buckets') or []
    counted = other + sum(int(row.get('count') or 0) for row in rows)
    return rows, other, counted


async def _span(collection):
    """
    The `ts` range of the whole collection, ignoring the window.

    Two sorted limit-1 aggregations rather than a `$min`/`$max` `$group`:
    `$group` would have to visit every document, while a sort on `ts` backed
    by `ts_desc` reads one index entry from each end. A descending index
    serves an ascending sort by being scanned backwards, so one index covers
    both.

    This exists so that the dashboard can say "nothing in the last 24 hours;
    this collection runs from X to Y" rather than showing an empty page,
    which is the single most likely thing to happen to somebody who has just
    imported a capture from last year.
    """
    edges = []
    for direction in (1, -1):
        rows = await _run(collection, [
            # $exists keeps a document with no ts out of the answer instead
            # of letting it sort to the front and report a span of None.
            {'$match': {'ts': {'$exists': True}}},
            {'$sort': {'ts': direction}},
            {'$limit': 1},
            {'$project': {'_id': 0, 'ts': 1}}])
        edges.append(rows[0].get('ts') if rows else None)
    return {'first': edges[0], 'last': edges[1]}


# --------------------------------------------------------------------------
# shaping the answer
# --------------------------------------------------------------------------
def _name(raw):
    """A bucket name: a non-empty string, never null and never a number."""
    if raw is None:
        return NONE
    if isinstance(raw, str):
        return raw or NONE
    return str(raw)


def _buckets(rows, classifier=None):
    """
    Grouped rows -> the envelope's `buckets`.

    The classifier is handed the **raw** grouped value, not the display
    name: `classify_ciphersuite(None)` is a considered answer from the
    shared table, and `classify_ciphersuite('(none)')` would be a question
    about a string this module invented.
    """
    out = []
    for row in rows:
        raw = row.get('_id')
        bucket = {'name': _name(raw), 'count': int(row.get('count') or 0)}
        if classifier is not None:
            bucket['verdict'] = classifier(raw)
        out.append(bucket)
    return _sorted(out)


def _sorted(buckets):
    """Count descending, then name ascending -- the order the UI relies on."""
    return sorted(buckets, key=lambda b: (-b['count'], b['name']))


def _envelope(panel, window, total, buckets, other=0, notes=None):
    return {'panel': panel,
            'window': dict(window),
            'total': int(total),
            'buckets': buckets,
            'other': int(other),
            'notes': list(notes or [])}


# Said once, on the panels where it changes what the number means. A frame
# and a session are not the same unit, and the two write paths produce one
# of each.
FRAME_NOTE = ("Documents written by the live eBPF capture are one per frame, "
              "so a client hello and its server hello are counted separately; "
              "the offline pcapscan import writes one per session. "
              "overview.by_ptype says which this collection holds.")

# Said on the panels whose field only the offline importer ever writes.
SESSION_ONLY_NOTE = ("Only the offline pcapscan import records this; "
                     "documents written by the live eBPF capture contribute "
                     "nothing to this panel.")


# --------------------------------------------------------------------------
# the panels
# --------------------------------------------------------------------------
async def overview(collection, window, limit=None):
    """
    The headline numbers, in one pass over the window plus the span.

    A `$facet` rather than a dozen round trips: the `$match` runs once, the
    index is consulted once, and every branch sees the same set of
    documents -- which also means the numbers cannot disagree with each
    other because a write landed between two queries.

    `limit` is ignored; this panel truncates nothing but the tag list, which
    has its own bound.
    """
    match = _match(window)
    pipeline = [{'$match': match}, {'$facet': {
        'documents': [{'$count': 'count'}],
        'by_ptype': [{'$group': {'_id': '$ptype', 'count': {'$sum': 1}}}],
        # $type rather than a truthiness test: an empty sub-document is
        # still a TLS session that was seen, and `{'$gt': ['$tls', None]}`
        # would need the reader to know BSON's type ordering to check.
        'protocols': [{'$group': {
            '_id': None,
            'tls': {'$sum': {'$cond': [
                {'$eq': [{'$type': '$tls'}, 'object']}, 1, 0]}},
            'ssh': {'$sum': {'$cond': [
                {'$eq': [{'$type': '$ssh'}, 'object']}, 1, 0]}}}}],
        # Grouped by name, then classified in Python -- a handful of rows,
        # not a second copy of the verdict table. See the module docstring.
        'key_exchange': [{'$group': {'_id': '$tls.kex_group',
                                     'count': {'$sum': 1}}}],
        'certificates': [{'$unwind': '$tls.certificates'},
                         {'$count': 'count'}],
        'hosts': [{'$match': {'tls.hostname': {'$ne': None}}},
                  {'$group': {'_id': '$tls.hostname'}}, {'$count': 'count'}],
        'ja4': [{'$match': {'tls.ja4': {'$ne': None}}},
                {'$group': {'_id': '$tls.ja4'}}, {'$count': 'count'}],
        'ech': [{'$group': {'_id': '$tls.ech', 'count': {'$sum': 1}}}],
        'alerts': [{'$unwind': '$tls.alerts'}, {'$count': 'count'}],
        'tags': [{'$match': {'tag': {'$ne': None}}},
                 {'$group': {'_id': '$tag'}}, {'$sort': {'_id': 1}},
                 {'$limit': MAX_TAGS + 1}]}}]
    rows = await _run(collection, pipeline)
    facet = rows[0] if rows else {}
    span = await _span(collection)

    documents = _first(facet, 'documents', 'count', 0)
    by_ptype = {_name(row.get('_id')): int(row.get('count') or 0)
                for row in facet.get('by_ptype') or []}
    protocols = facet.get('protocols') or [{}]
    ech = {_name(row.get('_id')): int(row.get('count') or 0)
           for row in facet.get('ech') or []}

    performed = 0
    quantum_safe = 0
    for row in facet.get('key_exchange') or []:
        group, count = row.get('_id'), int(row.get('count') or 0)
        if group is None:
            continue                     # resumed, or a frame with no share
        performed += count
        if classify_key_exchange(group) in (POST_QUANTUM, HYBRID):
            quantum_safe += count

    tags = [row['_id'] for row in facet.get('tags') or [] if row.get('_id')]
    notes = []
    if len(tags) > MAX_TAGS:
        tags = tags[:MAX_TAGS]
        notes.append("More than {0} capture tags are present; the list is "
                     "truncated.".format(MAX_TAGS))
    if documents == 0 and span['first'] is not None:
        notes.append(
            "No documents fall in this window. The collection runs from "
            "{0} to {1}; ask for hours=0 to see all of it.".format(
                span['first'], span['last']))
    if by_ptype.get('client') or by_ptype.get('server'):
        notes.append(FRAME_NOTE)

    return {
        'panel': 'overview',
        'window': dict(window),
        'documents': documents,
        'by_ptype': by_ptype,
        'span': span,
        'protocols': {'tls': int(protocols[0].get('tls') or 0),
                      'ssh': int(protocols[0].get('ssh') or 0)},
        'key_exchanges_performed': performed,
        'quantum_safe': quantum_safe,
        # 0.0 rather than null when nothing performed a key exchange: a
        # numeric field that is sometimes null breaks the chart that reads
        # it, and `key_exchanges_performed` is sitting right beside it to
        # say that the zero means "nothing happened" and not "nothing safe".
        'quantum_safe_percent': (round(100.0 * quantum_safe / performed, 1)
                                 if performed else 0.0),
        'certificates': _first(facet, 'certificates', 'count', 0),
        'distinct_hosts': _first(facet, 'hosts', 'count', 0),
        'distinct_ja4': _first(facet, 'ja4', 'count', 0),
        'ech_offered': ech.get('offered', 0),
        'ech_accepted': ech.get('accepted', 0),
        'alerts': _first(facet, 'alerts', 'count', 0),
        'tags': tags,
        'notes': notes,
    }


def _first(facet, branch, field, default):
    rows = facet.get(branch) or []
    return int(rows[0].get(field, default)) if rows else default


async def key_exchange(collection, window, limit=None):
    """
    Which key exchange groups were negotiated, and what each one is worth.

    The documents that performed no key exchange are deliberately *not* a
    bucket. `classify_key_exchange(None)` answers `none`, which is not one
    of the contract's five verdicts and is not a judgement about an
    algorithm -- it is the absence of one. Counting a resumed session as
    "classical" would report an event that did not happen, and counting it
    as "unknown" would read as a gap in the classification table. It goes in
    `notes`, as a denominator.
    """
    base = _match(window, {'tls': {'$exists': True}})
    rows, other, counted = await _grouped(
        collection, dict(base, **{'tls.kex_group': {'$ne': None}}),
        '$tls.kex_group', limit)
    # `{'$ne': None}` and `{None}` partition the TLS documents in the
    # window between them, so this is the exact denominator rather than a
    # subtraction that would drift if either match changed.
    none = await _count(collection, dict(base, **{'tls.kex_group': None}))

    notes = []
    if none:
        notes.append(
            "{0} of {1} documents in this window performed no key exchange "
            "(a resumed session, or a frame carrying no key share) and are "
            "not counted here.".format(none, none + counted))
    notes.append("SSH records the algorithms each side proposed rather than "
                 "the one chosen, so SSH documents are not counted here.")
    notes.append(FRAME_NOTE)
    return _envelope('key-exchange', window, counted,
                     _buckets(rows, classify_key_exchange), other, notes)


async def ciphersuites(collection, window, limit=None):
    """
    Negotiated ciphersuites.

    A TLS 1.3 suite is classified `symmetric`, not `unknown`:
    TLS_AES_256_GCM_SHA384 names no asymmetric primitive because in TLS 1.3
    the suite no longer carries the key exchange. That is the shared table's
    judgement and the reason `key-exchange` is a separate panel.
    """
    match = _match(window, {'tls': {'$exists': True}})
    rows, other, counted = await _grouped(collection, match,
                                          '$tls.ciphersuite', limit)
    buckets = _buckets(rows, classify_ciphersuite)

    notes = []
    if any(b['name'] == NONE for b in buckets):
        notes.append("\"{0}\" is a document with no negotiated ciphersuite "
                     "recorded: a resumed or encrypted handshake where the "
                     "server hello was not read.".format(NONE))
    broken = sum(row.get('count') or 0 for row in rows
                 if (symmetric_strength(row.get('_id'))[0] or '')
                 in SYMMETRIC_BROKEN)
    if broken:
        notes.append(
            "{0} of the documents shown negotiated a cipher that is broken "
            "independently of any quantum computer ({1}).".format(
                broken, ', '.join(SYMMETRIC_BROKEN)))
    notes.append(FRAME_NOTE)
    return _envelope('ciphersuites', window, counted, buckets, other, notes)


async def tls_versions(collection, window, limit=None):
    """
    TLS versions seen.

    `tls.tls_versions` holds the negotiated version as a string when the
    server hello was read, and the client's *offered list* when it was not.
    Both shapes are counted -- `$unwind` treats a non-array as a list of one
    -- which is what `cryptomon.analysis` does with the same field, so the
    two halves of the product agree. It does mean a session that offered
    1.3, 1.2, 1.1 and 1.0 appears under all four, and `notes` says so.
    """
    match = _match(window, {'tls': {'$exists': True}})
    documents = await _count(collection, match)
    # preserveNullAndEmptyArrays so that a document with no version at all
    # is still represented, as "(none)", instead of vanishing between the
    # document count and the buckets with nothing to explain the difference.
    rows, other, counted = await _grouped(collection, match,
                                          '$tls.tls_versions', limit,
                                          unwind='$tls.tls_versions',
                                          preserve=True)
    notes = [
        "total is documents; the buckets sum to {0} version appearances, "
        "because a client hello that offered several versions is counted "
        "under each of them.".format(counted),
        "A document carries the negotiated version where the server hello "
        "was read and the offered list where it was not.",
        FRAME_NOTE,
    ]
    return _envelope('tls-versions', window, documents,
                     _buckets(rows), other, notes)


async def certificates(collection, window, limit=None):
    """
    Certificate signing keys, by algorithm and size.

    Grouped on the three fields `classify_certificate` reads, so the label
    and the verdict both come from the shared table rather than being
    rebuilt here -- including its answer for a certificate that did not
    decode far enough to have a key, which is `unreadable` and not `None`.
    A `None` key in a summary is what killed a whole JSON export once.
    """
    base = _match(window)
    # `.0` rather than `{'$exists': True}`: an empty list is a document with
    # no certificate, and it would count towards `total` while contributing
    # nothing to any bucket.
    match = dict(base, **{'tls.certificates.0': {'$exists': True}})
    counts = await _run(collection, [{'$match': base}, {'$facet': {
        'documents': [{'$match': {'tls.certificates.0': {'$exists': True}}},
                      {'$count': 'count'}],
        'unreadable': [{'$match': {'tls.certificates_unreadable': True}},
                       {'$count': 'count'}]}}])
    facet = counts[0] if counts else {}
    documents = _first(facet, 'documents', 'count', 0)
    unreadable = _first(facet, 'unreadable', 'count', 0)

    rows, other, counted = await _grouped(
        collection, match,
        {'public_key_algorithm': '$tls.certificates.public_key_algorithm',
         'public_key_size': '$tls.certificates.public_key_size',
         'public_key_curve': '$tls.certificates.public_key_curve'},
        limit, unwind='$tls.certificates')

    buckets = []
    for row in rows:
        verdict, label = classify_certificate(row.get('_id') or {})
        buckets.append({'name': _name(label),
                        'count': int(row.get('count') or 0),
                        'verdict': verdict})

    notes = [
        "total is documents; the buckets sum to {0} certificates, because a "
        "chain contributes its leaf and every intermediate, and a "
        "certificate served to several sessions is counted once per "
        "session.".format(counted),
    ]
    if unreadable:
        notes.append(
            "{0} further documents sent a certificate inside the encrypted "
            "flight, where it cannot be read. They are not counted here; "
            "\"not readable\" and \"not sent\" are different "
            "claims.".format(unreadable))
    notes.append(SESSION_ONLY_NOTE)
    return _envelope('certificates', window, documents, buckets, other, notes)


async def hosts(collection, window, limit=None):
    """Server names, from SNI."""
    match = _match(window, {'tls': {'$exists': True}})
    rows, other, counted = await _grouped(collection, match,
                                          '$tls.hostname', limit)
    buckets = _buckets(rows)
    notes = []
    if any(b['name'] == NONE for b in buckets):
        notes.append("\"{0}\" is a document whose client sent no server name "
                     "-- a connection to an address, or a handshake where "
                     "the extension was not read.".format(NONE))
    notes.append("Where a server accepted Encrypted ClientHello the name "
                 "here is the public outer name and not the destination; "
                 "the ech panel gives the count.")
    notes.append(FRAME_NOTE)
    return _envelope('hosts', window, counted, buckets, other, notes)


async def ja4(collection, window, limit=None):
    """
    JA4 client fingerprints.

    Client fingerprints only. `tls.ja4s` is the server's and is a different
    population -- mixing the two would produce a bar chart in which no bar
    could be compared with any other.
    """
    match = _match(window, {'tls': {'$exists': True}})
    rows, other, counted = await _grouped(collection, match, '$tls.ja4', limit)
    buckets = _buckets(rows)
    notes = []
    if any(b['name'] == NONE for b in buckets):
        notes.append("\"{0}\" is a document with no client fingerprint: a "
                     "server-side record, or a client hello that could not "
                     "be fingerprinted.".format(NONE))
    notes.append("Server fingerprints are recorded separately as tls.ja4s "
                 "and are not counted here.")
    notes.append(FRAME_NOTE)
    return _envelope('ja4', window, counted, buckets, other, notes)


async def alerts(collection, window, limit=None):
    """
    TLS alerts, by description **and direction**.

    The record stores two integers (`{'level': 2, 'description': 40}`) and
    the names come from `cryptomon.alerts`, for the same reason the verdicts
    come from `cryptomon.analysis`: the registry is written down once. The
    level is not grouped on, because RFC 8446 section 6 made it advisory and
    `cryptomon.alerts.severity` already declines to consult it -- a peer that
    sends handshake_failure at level 1 has still refused the handshake.

    `from_client` **is** grouped on, and it is the half that carries the
    finding. Over this project's corpus all 29 `handshake_failure` came from
    the server and all 11 `certificate_unknown` from the client; merged into
    one row per code, "a middlebox refused our key share" and "we refused
    their parameters" are indistinguishable. The direction goes into the
    bucket name rather than a new field, spelled exactly as
    `pcapscan.export._alert_label` already spells it, so a CSV row and a
    dashboard bar say the same words. A record written before the direction
    was recorded has no suffix, which reads as "not known" rather than as a
    third direction.
    """
    base = _match(window)
    match = dict(base, **{'tls.alerts.0': {'$exists': True}})
    documents = await _count(collection, match)
    rows, other, counted = await _grouped(
        collection, match,
        {'description': '$tls.alerts.description',
         'from_client': '$tls.alerts.from_client'},
        limit, unwind='$tls.alerts')
    buckets = _sorted([{'name': _alert_name(row.get('_id') or {}),
                        'count': int(row.get('count') or 0)}
                       for row in rows])
    notes = [
        "total is documents; the buckets sum to {0} alerts, because one "
        "handshake can carry more than one.".format(counted),
        "close_notify is sent under the negotiated keys and is never "
        "visible to a passive observer, so an empty panel is not evidence "
        "that connections closed badly -- every alert here was sent during "
        "a handshake.",
        SESSION_ONLY_NOTE,
    ]
    return _envelope('alerts', window, documents, buckets, other, notes)


def _alert_name(key):
    """
    One grouped alert as `handshake_failure (server)`.

    Same spelling as `pcapscan.export._alert_label`, minus the level, which
    this panel does not group on.
    """
    description = key.get('description')
    name = NONE if description is None else describe_description(description)
    sender = key.get('from_client')
    if sender is None:
        return name
    return '{0} ({1})'.format(name, 'client' if sender else 'server')


async def ech(collection, window, limit=None):
    """
    Encrypted ClientHello: offered, accepted, or neither.

    "(none)" is kept as a bucket rather than pushed into a note because it
    is the denominator this panel exists to show. "465 offered" means
    nothing without the number that did not.
    """
    match = _match(window, {'tls': {'$exists': True}})
    rows, other, counted = await _grouped(collection, match, '$tls.ech', limit)
    notes = [
        "\"{0}\" is a client that did not offer Encrypted "
        "ClientHello.".format(NONE),
        "Once a server accepts ECH the hostname this tool reports is the "
        "public outer name rather than the site visited, which is why the "
        "accepted count qualifies every other panel that names a host.",
        FRAME_NOTE,
    ]
    return _envelope('ech', window, counted, _buckets(rows), other, notes)


async def timeline(collection, window, limit=None, bucket=None):
    """
    Traffic over time, split by key-exchange verdict.

    Bucketed arithmetically -- `ts - (ts mod width)` -- rather than with
    `$dateTrunc`, which needs MongoDB 5.0 and buys nothing when `ts` is
    already a float epoch. This runs on 4.4.

    The series is **gap-filled**: every bucket between the first and the
    last is present, with zeros where there was no traffic. A chart that
    silently closes its gaps draws a straight line through an outage and
    calls it uptime.

    `total` counts documents; `verdicts` counts the key exchanges among
    them, so the five sum to `total` only in a window where every document
    performed one. `limit` is ignored -- the series length is governed by
    the window and the bucket width.
    """
    seconds, widened = await _series_seconds(collection, window, bucket)
    match = _match(window)
    rows = await _run(collection, [
        {'$match': match},
        {'$group': {
            '_id': {'bucket': {'$subtract': ['$ts',
                                             {'$mod': ['$ts', seconds]}]},
                    'kex': '$tls.kex_group'},
            'count': {'$sum': 1}}},
        {'$sort': {'_id.bucket': 1}}])

    points = {}
    for row in rows:
        key = row.get('_id') or {}
        at = key.get('bucket')
        if at is None:
            continue                     # a document with no usable ts
        count = int(row.get('count') or 0)
        point = points.setdefault(float(at), _empty_point(float(at)))
        point['total'] += count
        group = key.get('kex')
        if group is None:
            continue                     # counted in total, no verdict
        verdict = classify_key_exchange(group)
        if verdict in point['verdicts']:
            point['verdicts'][verdict] += count

    series = _gap_fill(points, seconds)
    notes = []
    if widened:
        notes.append(
            "Buckets were widened to {0} seconds; the window asked for more "
            "than {1} points.".format(seconds, MAX_SERIES_POINTS))
    notes.append("total counts documents. The verdicts count the key "
                 "exchanges among them, so they sum to total only where "
                 "every document performed one.")
    notes.append(FRAME_NOTE)
    return {'panel': 'timeline',
            'window': dict(window),
            'bucket_seconds': seconds,
            'series': series,
            'notes': notes}


def _empty_point(at):
    return {'t': at, 'total': 0,
            'verdicts': dict((verdict, 0) for verdict in VERDICTS)}


def _gap_fill(points, seconds):
    """
    Every bucket between the first and last with data, zeros included.

    Bounded by the data rather than by the window on purpose: a `hours=0`
    request against a collection holding one afternoon should draw that
    afternoon, not two years of zeros leading up to it.
    """
    if not points:
        return []
    at = min(points)
    last = max(points)
    series = []
    while at <= last and len(series) <= MAX_SERIES_POINTS:
        series.append(points.get(at) or _empty_point(at))
        at += seconds
    return series


def _choose_seconds(window, bucket):
    """
    The bucket width: the argument, then the window, then the span.

    The window is consulted because the dashboard reaches these panels
    through `PANELS`, whose signature is `(collection, window, limit)` and
    has nowhere to put a bucket -- so it carries the width in the window
    instead. Accepting either spelling, a name or a width in seconds, means
    neither half has to know how the other was called; without this the
    dashboard's bucket control would validate, be carried all the way here,
    and then be silently ignored.
    """
    if bucket is not None:
        return BUCKET_SECONDS[bucket]
    carried = window.get('bucket')
    if carried in BUCKET_SECONDS:
        return BUCKET_SECONDS[carried]
    if carried in set(BUCKET_SECONDS.values()):
        return int(carried)
    hours = window.get('hours') or 0
    if hours == 0:
        return DAY
    if hours <= 2:
        return MINUTE
    if hours <= 48:
        return HOUR
    return DAY


async def _series_seconds(collection, window, bucket):
    """
    (bucket width, whether it had to be widened).

    The width is widened *before* the aggregation runs, not after, because
    the thing being prevented is the aggregation returning half a million
    rows -- re-bucketing them afterwards would already have paid for them.
    """
    seconds = _choose_seconds(window, validate_bucket(bucket))
    if window.get('from') is not None:
        span = max(0.0, float(window['to']) - float(window['from']))
    else:
        # "All of time" has no arithmetic span, so ask the collection.
        # Two index lookups, which is cheaper than being wrong about it.
        edges = await _span(collection)
        span = (0.0 if edges['first'] is None
                else max(0.0, float(edges['last']) - float(edges['first'])))
    widened = False
    while seconds in _WIDER and span / seconds > MAX_SERIES_POINTS:
        seconds = _WIDER[seconds]
        widened = True
    return seconds, widened


# The registry. The keys are the URL path segments and the dashboard's panel
# ids; they do not change.
PANELS = {
    'overview': overview,
    'key-exchange': key_exchange,
    'ciphersuites': ciphersuites,
    'tls-versions': tls_versions,
    'certificates': certificates,
    'hosts': hosts,
    'ja4': ja4,
    'alerts': alerts,
    'ech': ech,
    'timeline': timeline,
}


# --------------------------------------------------------------------------
# the routes
# --------------------------------------------------------------------------
# One explicit route per panel, and deliberately no `@router.get("/{panel}")`.
# FastAPI matches in declaration order, and a catch-all path parameter is
# exactly how `GET /data/count` came to return 500 in PR-06 -- it was
# swallowed by `/{id}` and handed to ObjectId(). The fix then was explicit
# routes and it is the fix now. A registry that the dashboard iterates is not
# a reason to route through one.
def _collection(request):
    return request.app.mongodb["cryptomon"]


def _window(hours, tag):
    return make_window(hours=hours, tag=tag)


HOURS_Q = Query(default=DEFAULT_HOURS,
                description="How far back to look. 0 means all of time.")
TAG_Q = Query(default=None, description="Match one capture run's tag exactly.")
LIMIT_Q = Query(default=DEFAULT_LIMIT,
                description="Largest buckets to return, 1-200. The rest are "
                            "summed into `other`.")
BUCKET_Q = Query(default=None,
                 description="minute, hour or day. Chosen from the window "
                             "when not given.")


@router.get("/", response_description="The panels this API serves")
async def stats_index(request: Request):
    """
    What is here, what the defaults are, and what the collection covers.

    `span` is included so that the first thing the dashboard loads already
    knows whether the default window can possibly have anything in it.
    """
    return {'panels': list(PANELS),
            'window_defaults': {'hours': DEFAULT_HOURS,
                                'max_hours': MAX_HOURS,
                                'limit': DEFAULT_LIMIT,
                                'min_limit': MIN_LIMIT,
                                'max_limit': MAX_LIMIT,
                                'buckets': dict(BUCKET_SECONDS)},
            'span': await _span(_collection(request))}


@router.get("/overview", response_description="Headline counts")
async def stats_overview(request: Request, hours: int = HOURS_Q,
                         tag: Union[str, None] = TAG_Q):
    return await overview(_collection(request), _window(hours, tag))


@router.get("/key-exchange", response_description="Key exchange groups")
async def stats_key_exchange(request: Request, hours: int = HOURS_Q,
                             tag: Union[str, None] = TAG_Q,
                             limit: int = LIMIT_Q):
    return await key_exchange(_collection(request), _window(hours, tag),
                              validate_limit(limit))


@router.get("/ciphersuites", response_description="Negotiated ciphersuites")
async def stats_ciphersuites(request: Request, hours: int = HOURS_Q,
                             tag: Union[str, None] = TAG_Q,
                             limit: int = LIMIT_Q):
    return await ciphersuites(_collection(request), _window(hours, tag),
                              validate_limit(limit))


@router.get("/tls-versions", response_description="TLS versions")
async def stats_tls_versions(request: Request, hours: int = HOURS_Q,
                             tag: Union[str, None] = TAG_Q,
                             limit: int = LIMIT_Q):
    return await tls_versions(_collection(request), _window(hours, tag),
                              validate_limit(limit))


@router.get("/certificates", response_description="Certificate signing keys")
async def stats_certificates(request: Request, hours: int = HOURS_Q,
                             tag: Union[str, None] = TAG_Q,
                             limit: int = LIMIT_Q):
    return await certificates(_collection(request), _window(hours, tag),
                              validate_limit(limit))


@router.get("/hosts", response_description="Server names, from SNI")
async def stats_hosts(request: Request, hours: int = HOURS_Q,
                      tag: Union[str, None] = TAG_Q,
                      limit: int = LIMIT_Q):
    return await hosts(_collection(request), _window(hours, tag),
                       validate_limit(limit))


@router.get("/ja4", response_description="JA4 client fingerprints")
async def stats_ja4(request: Request, hours: int = HOURS_Q,
                    tag: Union[str, None] = TAG_Q,
                    limit: int = LIMIT_Q):
    return await ja4(_collection(request), _window(hours, tag),
                     validate_limit(limit))


@router.get("/alerts", response_description="TLS alerts")
async def stats_alerts(request: Request, hours: int = HOURS_Q,
                       tag: Union[str, None] = TAG_Q,
                       limit: int = LIMIT_Q):
    return await alerts(_collection(request), _window(hours, tag),
                        validate_limit(limit))


@router.get("/ech", response_description="Encrypted ClientHello")
async def stats_ech(request: Request, hours: int = HOURS_Q,
                    tag: Union[str, None] = TAG_Q,
                    limit: int = LIMIT_Q):
    return await ech(_collection(request), _window(hours, tag),
                     validate_limit(limit))


@router.get("/timeline", response_description="Traffic over time by verdict")
async def stats_timeline(request: Request, hours: int = HOURS_Q,
                         tag: Union[str, None] = TAG_Q,
                         bucket: Union[str, None] = BUCKET_Q):
    return await timeline(_collection(request), _window(hours, tag),
                          bucket=validate_bucket(bucket))
