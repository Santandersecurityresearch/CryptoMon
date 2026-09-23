"""
The dashboard. One page that answers "what cryptography is on this network".

Mounted at the site root by api.py -- the upload UI moved to /analyse in
PR-28 expressly to leave "/" free for this.

Three decisions worth stating, because each of them is a thing that was
considered and rejected:

* **Nothing is vendored and there is no framework.** The PR plan said
  "Jinja2 + htmx + vendored uPlot". htmx and uPlot are roughly 90KB of
  minified JavaScript that no one here can review, going into a service
  whose job is to tell an organisation what cryptography it is running; and
  base.html already promises "No build step, no CDN, no vendored framework".
  The charts are server-rendered SVG (fapi/app/charts.py) and the live
  refresh is a couple of dozen lines of inline script. With JavaScript off
  the page still renders completely, which is the test of whether this is a
  page or an application.

* **fapi.app.stats is imported inside the handler, not at module scope.**
  Partly so this module can be tested and shipped independently of PR-36,
  but mostly because it is the better behaviour: a deployment without the
  stats aggregations should say so, the way UPLOADS_ENABLED already
  establishes that a feature of this service can be absent. An ImportError
  at module scope would take the whole application down at startup instead.

* **One failing panel does not blank the page.** Panels are gathered with
  return_exceptions=True and a panel that raised is drawn as a card saying
  which one broke. A dashboard is a monitoring tool; the moment it is most
  needed is the moment something is wrong with it.

The numbers themselves come from fapi/app/stats.py through the interface
frozen in STATS_CONTRACT: `PANELS[name](collection, window, limit)` and
`make_window(hours, tag)`. This module never writes an aggregation pipeline
and never reaches into a document; if a panel's shape is wrong, it is wrong
in one place.
"""
import asyncio
import pathlib

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from fapi.app import charts
from fapi.app.query import safe_query

router = APIRouter()

TEMPLATES = Jinja2Templates(
    directory=str(pathlib.Path(__file__).resolve().parent / "templates"))

# Restated from STATS_CONTRACT section 2 rather than imported, because this
# module has to answer 400 for an out-of-range window *before* it can know
# whether fapi.app.stats is even installed. The contract freezes these
# numbers, so the duplication cannot drift without the contract changing.
DEFAULT_HOURS = 24
MAX_HOURS = 8760
DEFAULT_LIMIT = 20
MAX_LIMIT = 200
# The three bucket widths the contract allows on the timeline.
BUCKETS = {'minute': 60, 'hour': 3600, 'day': 86400}

# How often the inline refresh loop re-fetches a panel, and the choices
# offered in the window control. 0 hours is the contract's "all of time".
REFRESH_SECONDS = 30
WINDOW_CHOICES = ((1, 'Last hour'), (24, 'Last 24 hours'),
                  (24 * 7, 'Last 7 days'), (24 * 30, 'Last 30 days'),
                  (0, 'All time'))

# The order the panels appear in, which is the order the questions get
# asked: how exposed are we, on what key exchange, is it moving, with what
# suites and certificates, who are these clients, is the naming about to go
# dark, and what is being refused. `overview` is consumed by the headline
# and the empty state rather than drawn as a card of its own.
PANEL_ORDER = ('key-exchange', 'timeline', 'ciphersuites', 'tls-versions',
               'certificates', 'ja4', 'hosts', 'ech', 'alerts')

PANEL_TITLES = {
    'key-exchange': 'Key exchange',
    'timeline': 'Over time',
    'ciphersuites': 'Ciphersuites',
    'tls-versions': 'TLS versions',
    'certificates': 'Certificates',
    'ja4': 'Client fingerprints (JA4)',
    'hosts': 'Server names',
    'ech': 'Encrypted ClientHello',
    'alerts': 'Alerts',
}


def _stats():
    """
    fapi.app.stats, or None when this deployment does not have it.

    Imported here rather than at module scope on purpose -- see the module
    docstring. ImportError only: an ImportError raised from *inside* a stats
    module that does exist would be swallowed by a broader except and
    reported as "not mounted", which is a different and much more confusing
    failure.
    """
    try:
        from fapi.app import stats
    except ImportError:
        return None
    return stats


def _collection(request):
    """
    The cryptomon collection, or 503.

    app.mongodb is set by api.py's lifespan. It is absent when the
    application is constructed without entering the lifespan, which is how
    the tests run and also how a misconfigured deployment starts.
    """
    database = getattr(request.app, 'mongodb', None)
    if database is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No database connection. This usually means the "
                   "application was started without its lifespan.")
    return database["cryptomon"]


def _window_params(hours, tag, limit, bucket):
    """
    Validate the query string, or 400.

    The same bounds STATS_CONTRACT section 2 puts on /stats/*, checked here
    too so that a bad URL on the dashboard is a 400 with a sentence rather
    than a 500 from inside an aggregation -- and so the page can be reasoned
    about without PR-36 installed. `tag` goes through the existing
    safe_query() rather than a second validator, which is what the contract
    asks for and also what stops a tag from being a Mongo operator.
    """
    if hours is None:
        hours = DEFAULT_HOURS
    if not (0 <= hours <= MAX_HOURS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="hours must be between 0 and {0}; 0 means all of "
                   "time.".format(MAX_HOURS))
    if limit is None:
        limit = DEFAULT_LIMIT
    if not (1 <= limit <= MAX_LIMIT):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="limit must be between 1 and {0}.".format(MAX_LIMIT))
    if bucket is not None and bucket not in BUCKETS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bucket must be one of: {0}.".format(
                ', '.join(sorted(BUCKETS))))
    if tag is not None:
        safe_query({'tag': tag})
    return hours, tag, limit, bucket


def _window(stats, hours, tag, bucket):
    """
    Build the contract's window dict.

    `bucket` is carried as an extra key. STATS_CONTRACT gives the panel
    coroutines the signature (collection, window, limit=None) but describes
    `bucket` as a query parameter of the timeline *route* -- so there is no
    argument to pass it through, and the window is the only channel left. A
    stats module that does not look for it simply chooses its own bucket
    width from the window, which is the documented default behaviour. This
    is flagged in the PR report as a gap in the contract rather than papered
    over here.
    """
    window = stats.make_window(hours=hours, tag=tag)
    if bucket is not None:
        window = dict(window)
        window['bucket'] = BUCKETS[bucket]
    return window


async def _gather(stats, collection, window, limit, names):
    """
    Run the named panels concurrently, keeping failures local.

    A panel that raises becomes {'_error': ...} and is drawn as a card
    saying so. The alternative -- letting one aggregation's exception reach
    the exception handler -- replaces nine working panels with a stack
    trace.
    """
    wanted = [n for n in names if n in stats.PANELS]
    results = await asyncio.gather(
        *[stats.PANELS[name](collection, window, limit) for name in wanted],
        return_exceptions=True)
    panels = {}
    for name, result in zip(wanted, results):
        if isinstance(result, BaseException):
            panels[name] = {'_error': '{0}: {1}'.format(
                type(result).__name__, result)}
        elif not isinstance(result, dict):
            # The contract says a panel answers a dict. Something else is a
            # bug in the panel, not a reason to raise AttributeError three
            # layers into a template.
            panels[name] = {'_error': 'panel returned {0}, not a dict'.format(
                type(result).__name__)}
        else:
            panels[name] = result
    for name in names:
        panels.setdefault(name, {'_error': 'no such panel in PANELS'})
    return panels


def _context(request, hours, tag, limit, bucket):
    """Everything both the full page and a fragment need to draw a panel."""
    return {
        'ch': charts,
        'hours': hours, 'tag': tag, 'limit': limit, 'bucket': bucket,
        'titles': PANEL_TITLES,
        'panel_order': PANEL_ORDER,
        'window_choices': WINDOW_CHOICES,
        'refresh_seconds': REFRESH_SECONDS,
        'verdict_order': charts.VERDICT_ORDER,
    }


@router.get("/", response_class=HTMLResponse, name="dashboard",
            response_description="The cryptography dashboard")
async def dashboard(request: Request, hours: int = DEFAULT_HOURS,
                    tag: str = None, limit: int = DEFAULT_LIMIT,
                    bucket: str = None):
    """
    The whole page, rendered on the server.

    Everything here is a read. There is deliberately no write guard: reads
    have always been open on this API, and STATS_CONTRACT section 4 says the
    same of /stats.
    """
    hours, tag, limit, bucket = _window_params(hours, tag, limit, bucket)
    stats = _stats()
    if stats is None:
        return _unavailable(request, hours, tag, limit, bucket)

    collection = _collection(request)
    window = _window(stats, hours, tag, bucket)
    names = ('overview',) + PANEL_ORDER
    panels = await _gather(stats, collection, window, limit, names)

    overview = panels.get('overview') or {}
    context = _context(request, hours, tag, limit, bucket)
    context.update({
        'window': window,
        'panels': panels,
        'overview': overview,
        # The empty window is a first-class case, not an afterthought: the
        # single most likely first experience of this page is somebody who
        # has just imported a capture from last year, and a blank page reads
        # as a broken install. `span` is in the contract precisely so that
        # this branch has something true to say.
        'is_empty': not overview.get('_error') and not overview.get(
            'documents'),
        'span_text': charts.describe_span(overview.get('span')),
        'span_hours': charts.span_hours(overview.get('span')),
    })
    return TEMPLATES.TemplateResponse(request, "dashboard.html", context)


@router.get("/panels/{name}", response_class=HTMLResponse,
            name="dashboard_panel",
            response_description="One panel, as an HTML fragment")
async def dashboard_panel(request: Request, name: str,
                          hours: int = DEFAULT_HOURS, tag: str = None,
                          limit: int = DEFAULT_LIMIT, bucket: str = None):
    """
    One panel's markup, for the refresh loop to drop into the page.

    This is the one path-parameter route in the service, which PR-06 is a
    standing warning about: a catch-all path parameter matched ahead of
    `/data/count` and turned it into a 500. It is safe here for two reasons
    that are worth checking still hold if routes are ever added. There is no
    sibling route under `/panels/`, so there is nothing for it to shadow;
    and `name` is checked against the PANELS registry before it is used for
    anything, so an unknown segment is a 404 rather than a KeyError.
    """
    hours, tag, limit, bucket = _window_params(hours, tag, limit, bucket)
    stats = _stats()
    if stats is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The stats aggregations are not installed on this "
                   "deployment.")
    if name not in stats.PANELS or name not in PANEL_TITLES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No such panel: {0!r}.".format(name))

    collection = _collection(request)
    window = _window(stats, hours, tag, bucket)
    panels = await _gather(stats, collection, window, limit, (name,))
    context = _context(request, hours, tag, limit, bucket)
    context.update({'window': window, 'name': name, 'data': panels[name]})
    return TEMPLATES.TemplateResponse(request, "dashboard_fragment.html",
                                      context)


def _unavailable(request, hours, tag, limit, bucket):
    """
    The page a deployment without fapi.app.stats gets.

    503 and a sentence, not a 500 and a stack trace. "The stats endpoints
    are not available on this deployment" is a useful thing to read; an
    internal server error is not, and it sends whoever sees it looking for a
    crash that has not happened.
    """
    context = _context(request, hours, tag, limit, bucket)
    return TEMPLATES.TemplateResponse(
        request, "dashboard_unavailable.html", context,
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


__all__ = ['router', 'PANEL_ORDER', 'PANEL_TITLES', 'BUCKETS',
           'DEFAULT_HOURS', 'MAX_HOURS', 'DEFAULT_LIMIT', 'MAX_LIMIT']
