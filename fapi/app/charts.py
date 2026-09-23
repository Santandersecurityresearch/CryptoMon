"""
Hand-authored SVG for the dashboard.

Every function here is pure: values in, a string of markup out. No request,
no template globals, no database, no clock in anything that matters. That is
deliberate -- it is what lets tests/test_dashboard.py feed each one a
200-character hostname, a bucket whose count is zero and an empty list, and
assert on the result without standing up an application.

**Nothing is vendored.** The PR plan for the dashboard said "Jinja2 + htmx +
vendored uPlot": ~90KB of minified JavaScript that nobody in this repository
can review, added to a tool whose whole purpose is telling people what
cryptography they are running. base.html already promises "No build step, no
CDN, no vendored framework", and bom.json already carries a recorded finding
for misdescribing a dependency. The payloads here are tens of buckets, not a
million points. Server-rendered SVG costs nothing and can be read.

Three rules the code follows throughout:

* **Every string that came out of the database is hostile.** A hostname, a
  JA4 fingerprint and an alert description are all chosen by a peer. They go
  through printable_text() -- the function this project had to add after a
  mutated SNI carrying CR and NUL broke the CSV writer, see
  cryptomon/utils.py -- and then through escape(), in that order, because
  HTML-escaping alone leaves a NUL and a carriage return intact in the
  output.

* **Colour never carries a fact on its own.** The verdict hues were chosen by
  running them through a CVD and contrast validator rather than by eye, but
  every mark is also labelled in words and every chart is repeated as a table
  in the page. Colour is the fast path, not the only path.

* **Stroke and text are currentColor.** The page's --fg flows in, so the
  charts follow the light and dark themes base.html already defines without a
  second set of rules. A literal hue appears only where the colour means
  something -- the verdict -- and then as a CSS custom property the template
  defines once for both themes.
"""
import datetime as dt

from markupsafe import Markup, escape

from cryptomon.analysis import (CLASSICAL, HYBRID, POST_QUANTUM, SYMMETRIC,
                                UNKNOWN)
from cryptomon.utils import printable_text

# The order verdicts are stacked and listed in, best-prepared first. It is
# also the order the colour palette was validated in -- the validator checks
# *adjacent* pairs, so reordering this invalidates that check. Imported from
# cryptomon.analysis rather than retyped, because a second copy of these five
# strings is a second copy to drift.
VERDICT_ORDER = (POST_QUANTUM, HYBRID, CLASSICAL, SYMMETRIC, UNKNOWN)

# The CSS custom property that paints each verdict. Defined once, for both
# themes, in dashboard.html's {% block head %}.
VERDICT_VAR = {v: '--v-{0}'.format(v) for v in VERDICT_ORDER}

# The sixth band, and the one that is not a verdict. `timeline[].total` is
# the number of *documents* in the bucket and `verdicts` counts only the key
# exchanges among them, so the two do not agree: a resumed session performs
# no key exchange, and on this project's corpus that is the majority of
# documents. Drawing the five verdicts under a line taken from `total`
# leaves a large unexplained gap that reads as a bug in the data. Naming the
# difference instead makes the stack sum to `total` and puts the denominator
# on screen, which is the standing rule on this page.
NO_KEX = 'no key exchange'
NO_KEX_VAR = '--chart-bar'

# The timeline's stack order, bottom to top, and what paints each band. The
# sixth band reuses --chart-bar, which is what the headline ratio bar gives
# the same quantity, so the two charts on the page agree about what the
# colour means.
TIMELINE_BANDS = VERDICT_ORDER + (NO_KEX,)
BAND_VAR = dict(VERDICT_VAR, **{NO_KEX: NO_KEX_VAR})

# --------------------------------------------------------------------------
# Geometry. Everything is in viewBox units and CSS scales the result, so
# these are proportions rather than pixels and the charts stay legible on a
# phone without a media query.
# --------------------------------------------------------------------------
VIEW_W = 760.0
# The left gutter is sized for the longest name that is allowed through
# (NAME_CHARS) at the label's font size, in the monospace face the CSS asks
# for: 40 characters at roughly 0.6em of an 11-unit font is 264 units, which
# fits 300 minus the 8-unit inset with room to spare. Get this wrong and a
# long ciphersuite name runs off the left-hand side of the viewBox, where
# there is no clipping to catch it.
NAME_W = 300.0          # left gutter, for the bucket name
NUM_W = 84.0            # right gutter, for the count printed beside the bar
ROW_H = 24.0
BAR_H = 14.0
PAD_T = 10.0
PAD_B = 24.0
# A bar for a count of 1 beside a bar for a count of 10,000 is sub-pixel.
# Non-zero gets at least this much width, so that "present but tiny" and
# "absent" are never the same picture; the number printed beside it is what
# carries the magnitude.
MIN_STUB = 3.0
# Longer names are cut for the label and kept whole in the <title> and in the
# table the template prints underneath. 40 clears a ciphersuite name (38
# characters) and a JA4 fingerprint (39), which are the two long things that
# actually occur in this corpus.
NAME_CHARS = 40


def safe_text(value, limit=None):
    """
    One hostile string, made safe to put in markup, optionally shortened.

    printable_text() first, escape() second. The other order would escape the
    angle brackets and leave the NUL, and a NUL in an attribute value is a
    truncation waiting for whatever parses it next.

    The statistics key is deliberately not the parser's: rendering a page is
    not parsing a packet, and incrementing 'nonprintable_text' from here
    would make the parser's own statistics report traffic that never
    happened.
    """
    if value is None:
        text = ''
    elif isinstance(value, str):
        text = printable_text(value, 'nonprintable_dashboard') or ''
    else:
        text = str(value)
    if limit is not None and len(text) > limit:
        # A one-character ellipsis, so the cut is visible and the string
        # still fits the gutter it was measured for.
        text = text[:max(0, limit - 1)] + '…'
    return escape(text)


def _num(value):
    """A count, digit-grouped. Anything not a number prints as itself."""
    try:
        return escape('{0:,}'.format(int(value)))
    except (TypeError, ValueError):
        return safe_text(value, 24)


def _f(value):
    """Coordinates, trimmed. Keeps the markup small and diffable."""
    try:
        text = '{0:.2f}'.format(float(value))
    except (TypeError, ValueError):
        return '0'
    if '.' in text:
        text = text.rstrip('0').rstrip('.')
    return text or '0'


def _bar_path(x, y, width, height, radius=3.0):
    """
    A bar with its *data end* rounded and its baseline end square.

    Rounding both ends puts a curve where the axis is, which reads as a gap
    between the bar and the thing it is measured from.
    """
    if width <= 0:
        return ''
    radius = min(radius, width, height / 2.0)
    return ('M{x},{y} H{inner} A{r},{r} 0 0 1 {end},{ytop} '
            'V{ybot} A{r},{r} 0 0 1 {inner},{bottom} H{x} Z').format(
                x=_f(x), y=_f(y), inner=_f(x + width - radius),
                r=_f(radius), end=_f(x + width), ytop=_f(y + radius),
                ybot=_f(y + height - radius), bottom=_f(y + height))


def _svg(body, width, height, label, extra_class=''):
    """
    Wrap a body in the one <svg> element every chart here shares.

    The <div> around it is not decoration. A viewBox scales to its container,
    so on a phone a 760-unit chart would shrink an 11-unit label to four
    physical pixels. The CSS gives the <svg> a min-width and lets this box
    scroll instead, which keeps the type legible and confines the scrolling
    to the chart rather than to the page.
    """
    classes = 'chart' + ((' ' + extra_class) if extra_class else '')
    return Markup(
        '<div class="chart-box"><svg class="{cls}" viewBox="0 0 {w} {h}" '
        'role="img" aria-label="{label}" '
        'preserveAspectRatio="xMinYMin meet">{body}</svg></div>').format(
            cls=classes, w=_f(width), h=_f(height), label=label,
            body=Markup(body))


def empty_chart(message):
    """
    What a chart with nothing in it renders as.

    A sentence rather than an empty axis: an empty plot frame reads as a
    broken widget and a sentence reads as an answer. This is a first-class
    case -- somebody who has just mongoimported a capture from last year sees
    it on their first visit, and an empty page would read as a broken
    install.
    """
    return Markup('<p class="chart-empty">{0}</p>').format(safe_text(message))


# --------------------------------------------------------------------------
# bars
# --------------------------------------------------------------------------
def bar_chart(buckets, caption, value_noun='sessions', name_chars=NAME_CHARS):
    """
    Horizontal bars for one panel's `buckets`, longest first.

    `buckets` is the contract's list of {'name', 'count', 'verdict'?}.
    STATS_CONTRACT section 3 guarantees `name` is a non-empty string and
    `count` a non-negative int, so this does not defend against None -- but
    it assumes nothing whatever about which characters are in the name.

    The scale is linear against the largest count and the count is printed
    beside every bar. A log scale would make the four-orders-of-magnitude
    case prettier and would also make a reader who glanced at it wrong.
    """
    buckets = list(buckets or ())
    if not buckets:
        return empty_chart('No {0} in this window.'.format(value_noun))

    counts = []
    for bucket in buckets:
        try:
            counts.append(max(0, int(bucket.get('count') or 0)))
        except (TypeError, ValueError):
            counts.append(0)
    scale = max(counts) or 1
    rows = len(buckets)
    plot_w = VIEW_W - NAME_W - NUM_W
    height = PAD_T + rows * ROW_H + PAD_B

    # The baseline. Recessive: it orients the eye and must not compete with
    # the data.
    parts = ['<line x1="{x}" y1="{y1}" x2="{x}" y2="{y2}" '
             'stroke="currentColor" stroke-opacity=".25"/>'.format(
                 x=_f(NAME_W), y1=_f(PAD_T), y2=_f(PAD_T + rows * ROW_H))]

    for index, bucket in enumerate(buckets):
        count = counts[index]
        verdict = bucket.get('verdict')
        raw_name = bucket.get('name')
        top = PAD_T + index * ROW_H
        bar_y = top + (ROW_H - BAR_H) / 2.0
        width = 0.0 if count == 0 else max(MIN_STUB, plot_w * count / scale)
        fill = ('var({0})'.format(BAND_VAR[verdict])
                if verdict in BAND_VAR else 'var(--chart-bar)')
        # <title> is the no-JavaScript hover layer: the browser shows it as a
        # tooltip, and it carries the name in full when the label was cut.
        title = safe_text('{0}: {1} {2}{3}'.format(
            bucket.get('name'), format(count, ','), value_noun,
            ' ({0})'.format(verdict) if verdict else ''))
        parts.append('<g><title>{0}</title>'.format(title))
        if width:
            parts.append('<path d="{d}" fill="{fill}"/>'.format(
                d=_bar_path(NAME_W, bar_y, width, BAR_H), fill=fill))
        parts.append(
            '<text x="{x}" y="{y}" text-anchor="end" class="lbl">{name}'
            '</text>'.format(x=_f(NAME_W - 8), y=_f(top + ROW_H / 2.0 + 4),
                             name=safe_text(raw_name, name_chars)))
        parts.append(
            '<text x="{x}" y="{y}" class="val">{n}</text>'.format(
                x=_f(NAME_W + width + 6), y=_f(top + ROW_H / 2.0 + 4),
                n=_num(count)))
        parts.append('</g>')

    # The scale, stated rather than implied. Without it a reader has no way
    # of knowing whether the longest bar is five or five million.
    parts.append(
        '<text x="{x}" y="{y}" class="axis">0</text>'
        '<text x="{x2}" y="{y}" text-anchor="end" class="axis">{max}</text>'
        .format(x=_f(NAME_W + 2), x2=_f(NAME_W + plot_w),
                y=_f(PAD_T + rows * ROW_H + 15), max=_num(scale)))

    return _svg(''.join(parts), VIEW_W, height, safe_text(caption))


def ratio_bar(parts, caption, total=None):
    """
    One bar split into shares of a stated whole.

    `parts` is a list of (label, count, verdict-or-None). Used for the
    headline, where the point is not the count but the count *over its
    denominator*: this project's own recorded finding is that the
    quantum-safe figure is 14.4% or 6.4% depending entirely on which
    denominator is chosen, so here the denominator is drawn rather than
    described.

    Segments are separated by a gap in the page background rather than by a
    stroke, which keeps two same-coloured neighbours distinguishable.
    """
    cleaned = []
    for label, count, verdict in (parts or ()):
        try:
            value = max(0, int(count or 0))
        except (TypeError, ValueError):
            value = 0
        cleaned.append((label, value, verdict))
    try:
        whole = int(total) if total is not None else sum(p[1] for p in cleaned)
    except (TypeError, ValueError):
        whole = sum(p[1] for p in cleaned)
    if whole <= 0:
        return empty_chart(
            'Nothing to divide: the denominator for this window is zero.')

    bar_y, bar_h, gap = 6.0, 22.0, 2.0
    height = bar_y + bar_h + 26.0
    body = ['<rect x="0" y="{y}" width="{w}" height="{h}" rx="3" '
            'fill="currentColor" fill-opacity=".07"/>'.format(
                y=_f(bar_y), w=_f(VIEW_W), h=_f(bar_h))]
    x = 0.0
    legend = []
    for label, count, verdict in cleaned:
        width = VIEW_W * count / float(whole)
        fill = ('var({0})'.format(BAND_VAR[verdict])
                if verdict in BAND_VAR else 'var(--chart-bar)')
        if width > gap:
            body.append(
                '<g><title>{t}</title>'
                '<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="3" '
                'fill="{fill}"/></g>'.format(
                    t=safe_text('{0}: {1} of {2}'.format(
                        label, format(count, ','), format(whole, ','))),
                    x=_f(x), y=_f(bar_y), w=_f(width - gap), h=_f(bar_h),
                    fill=fill))
        legend.append(safe_text('{0} {1} ({2:.1f}%)'.format(
            label, format(count, ','), 100.0 * count / whole)))
        x += width
    # Each label is escaped on its own and then joined with a Markup
    # separator. Escaping the joined string instead would put the separator
    # through printable_text(), which is for bytes off the wire -- and it
    # duly rewrote the middle dot as a literal "\xb7" on the page.
    separator = Markup(' · ')
    body.append(
        '<text x="0" y="{y}" class="axis">{legend}</text>'.format(
            y=_f(bar_y + bar_h + 17),
            legend=(separator.join(legend) + separator +
                    escape('of {0}'.format(format(whole, ','))))))
    return _svg(''.join(body), VIEW_W, height, safe_text(caption),
                'chart-ratio')


# --------------------------------------------------------------------------
# timeline
# --------------------------------------------------------------------------
TL_X0 = 52.0
TL_X1 = VIEW_W - 6.0
TL_Y0 = 10.0
TL_Y1 = 170.0


def _clock(epoch, bucket_seconds):
    """
    An axis label for a float epoch, in this machine's local time.

    Wrapped, because `ts` comes out of a database and a database holds
    whatever was put in it: fromtimestamp() raises ValueError, OverflowError
    or OSError for a value far outside the epoch, and an axis label is not
    worth a 500.
    """
    try:
        when = dt.datetime.fromtimestamp(float(epoch))
    except (TypeError, ValueError, OverflowError, OSError):
        return safe_text(epoch, 20)
    if bucket_seconds and bucket_seconds >= 86400:
        return escape(when.strftime('%d %b %Y'))
    return escape(when.strftime('%d %b %H:%M'))


def timeline_chart(series, bucket_seconds, caption):
    """
    Key exchanges by verdict over time, with the population they came from.

    Six bands, stacked, summing to `total`: the five verdicts with the
    best-prepared at the baseline, and then the difference between the
    verdicts and `total` as a named sixth band.

    That sixth band is the whole point. `total` is the number of *documents*
    in the bucket and `verdicts` counts the key exchanges among them, and
    the two legitimately disagree, because a resumed session performs no key
    exchange -- 744 of 1342 documents on the corpus this was built against.
    Stacking only the five under a line taken from `total` leaves a large
    unexplained gap that reads as a bug in the data; scaling the five to
    their own maximum instead answers "of the sessions that performed a key
    exchange" while looking like it answered "of the sessions", which is the
    exact confusion this project has a recorded finding about. Naming the
    difference does neither. The dashed outline stays, tracing `total`, so
    the top of the stack is visibly the denominator.

    The best-prepared band is at the baseline because a band anchored to the
    baseline is the only one whose thickness can be read accurately, and the
    band people are watching for is the post-quantum one.

    Columns, not a smoothed line. These are counts in a bucket, and a line
    between two hourly aggregates draws values at times where nothing was
    measured. The series arrives gap-filled (STATS_CONTRACT section 3) so an
    outage shows as a drop to zero rather than as a straight line across it.
    """
    series = list(series or ())
    if not series:
        return empty_chart('No traffic in this window to put on a timeline.')

    try:
        bucket_seconds = int(bucket_seconds or 0)
    except (TypeError, ValueError):
        bucket_seconds = 0

    totals, stacks = [], []
    for point in series:
        verdicts = point.get('verdicts') or {}
        stack = []
        for verdict in VERDICT_ORDER:
            try:
                value = max(0, int(verdicts.get(verdict) or 0))
                stack.append((verdict, value))
            except (TypeError, ValueError):
                stack.append((verdict, 0))
        try:
            reported = max(0, int(point.get('total') or 0))
        except (TypeError, ValueError):
            reported = 0
        classified = sum(c for _v, c in stack)
        # max() of the two, because a stack taller than the total it is drawn
        # inside would overflow the plot. That cannot happen if PR-36 is
        # right; it costs one comparison to make sure it cannot happen if it
        # is not.
        bucket_total = max(reported, classified)
        stack.append((NO_KEX, bucket_total - classified))
        stacks.append(stack)
        totals.append(bucket_total)
    scale = max(totals) or 1
    count = len(series)
    plot_w = TL_X1 - TL_X0
    plot_h = TL_Y1 - TL_Y0
    col_w = plot_w / count
    # A hair of separation between columns when there is room for it, and
    # none when a wide window has packed hundreds of buckets in -- at which
    # point the columns read as an area, which is the right reading of
    # hundreds of buckets.
    inset = min(1.2, col_w * 0.12)

    def y_of(value):
        return TL_Y1 - plot_h * value / float(scale)

    # One <path> per band rather than one <rect> per (bucket, band). An
    # all-time window on this corpus is 535 daily buckets and PR-36 caps the
    # series at 2000; six paths is a few kilobytes and 12,000 elements is
    # not.
    paths = {band: [] for band in TIMELINE_BANDS}
    outline = []
    for index, stack in enumerate(stacks):
        x = TL_X0 + index * col_w + inset
        # Never wider than its column and never narrower than half of it. A
        # fixed minimum width would make the columns overlap once 2000
        # buckets put them a third of a unit apart.
        width = max(col_w * 0.5, col_w - 2 * inset)
        base = 0
        for verdict, value in stack:
            if value:
                paths[verdict].append('M{x},{y} h{w} v{h} h-{w} Z'.format(
                    x=_f(x), y=_f(y_of(base + value)), w=_f(width),
                    h=_f(y_of(base) - y_of(base + value))))
            base += value
        top = y_of(totals[index])
        outline.append('{0}{1},{2} L{3},{2}'.format(
            'M' if index == 0 else ' L', _f(TL_X0 + index * col_w), _f(top),
            _f(TL_X0 + (index + 1) * col_w)))

    body = []
    # Gridlines first, so the data sits on top of them.
    for fraction in (0.0, 0.5, 1.0):
        y = TL_Y1 - plot_h * fraction
        body.append(
            '<line x1="{x0}" y1="{y}" x2="{x1}" y2="{y}" '
            'stroke="currentColor" stroke-opacity="{o}"/>'
            '<text x="{lx}" y="{ly}" text-anchor="end" class="axis">{v}'
            '</text>'.format(
                x0=_f(TL_X0), x1=_f(TL_X1), y=_f(y),
                o='.25' if fraction == 0 else '.1',
                lx=_f(TL_X0 - 6), ly=_f(y + 4),
                v=_num(int(round(scale * fraction)))))
    for band in TIMELINE_BANDS:
        if paths[band]:
            body.append('<path d="{d}" fill="var({var})"/>'.format(
                d=' '.join(paths[band]), var=BAND_VAR[band]))
    # `total` traced over the top of the stack. The stack now sums to it, so
    # this is a reading aid rather than a series: it makes the top edge of
    # the stack legible as the denominator even where a band is thin.
    body.append(
        '<path d="{d}" fill="none" stroke="currentColor" '
        'stroke-opacity=".55" stroke-width="1.5" stroke-dasharray="4 3"/>'
        .format(d=''.join(outline)))

    ticks = set([0, count - 1]) if count > 1 else set([0])
    if count > 4:
        ticks.add(count // 2)
    for index in sorted(ticks):
        if index == 0 and count > 1:
            anchor, x = 'start', TL_X0
        elif index == count - 1 and count > 1:
            anchor, x = 'end', TL_X1
        else:
            anchor, x = 'middle', TL_X0 + (index + 0.5) * col_w
        body.append(
            '<text x="{x}" y="{y}" text-anchor="{a}" class="axis">{t}</text>'
            .format(x=_f(x), y=_f(TL_Y1 + 16), a=anchor,
                    t=_clock(series[index].get('t'), bucket_seconds)))

    return _svg(''.join(body), VIEW_W, TL_Y1 + 24, safe_text(caption),
                'chart-timeline')


# --------------------------------------------------------------------------
# Small helpers the template uses. Pure, so they are tested with the charts.
# --------------------------------------------------------------------------
def verdict_rollup(buckets):
    """
    Sum a panel's buckets by verdict, in VERDICT_ORDER.

    Returns [(verdict, count), ...] including only verdicts that occurred: a
    roll-up listing three zeroes hides the two numbers that matter. Buckets
    with no verdict are ignored, because the panels that do not classify have
    nothing to roll up.
    """
    tally = dict((v, 0) for v in VERDICT_ORDER)
    seen = set()
    for bucket in buckets or ():
        verdict = bucket.get('verdict')
        if verdict in tally:
            try:
                tally[verdict] += max(0, int(bucket.get('count') or 0))
            except (TypeError, ValueError):
                pass
            seen.add(verdict)
    return [(v, tally[v]) for v in VERDICT_ORDER if v in seen]


def timeline_totals(series):
    """
    A timeline's band totals over the whole window, in TIMELINE_BANDS order.

    The legend under the timeline, and the only place the bands get a number
    attached -- 535 daily columns cannot each carry a label, and a table of
    535 rows under the chart would bury the eight panels below it.

    The sixth entry is the documents that performed no key exchange, which
    is `total` minus the verdicts, computed the same way the chart stacks
    it. Bands that never occurred are left out, for the same reason as in
    verdict_rollup().
    """
    tally = dict((band, 0) for band in TIMELINE_BANDS)
    for point in series or ():
        point = point or {}
        verdicts = point.get('verdicts') or {}
        classified = 0
        for verdict in VERDICT_ORDER:
            try:
                value = max(0, int(verdicts.get(verdict) or 0))
            except (TypeError, ValueError):
                value = 0
            tally[verdict] += value
            classified += value
        try:
            reported = max(0, int(point.get('total') or 0))
        except (TypeError, ValueError):
            reported = 0
        tally[NO_KEX] += max(reported, classified) - classified
    return [(band, tally[band]) for band in TIMELINE_BANDS if tally[band]]


def band_class(name):
    """
    The CSS modifier class that paints a band's swatch.

    A band name is not a class name -- "no key exchange" has spaces in it --
    so the mapping is done here rather than by string-mangling in a
    template, where a name that did not map would silently produce an
    unstyled swatch.
    """
    if name in BAND_VAR:
        return 'sw-{0}'.format(str(name).replace(' ', '-'))
    return ''


def headline_parts(rollup, no_key_exchange=0):
    """
    The headline bar's segments: (label, count, verdict) triples.

    One segment per verdict that occurred, plus one for the sessions that
    performed no key exchange at all. Both denominators end up in the same
    bar, which is the whole point of the headline: the project's recorded
    finding is that 81 hybrid key exchanges are 14.4% of the sessions that
    performed one and 6.4% of every session, and a reader who is shown only
    one of those has been told something misleading by omission.
    """
    parts = [(verdict, count, verdict) for verdict, count in (rollup or ())]
    try:
        spare = int(no_key_exchange or 0)
    except (TypeError, ValueError):
        spare = 0
    if spare > 0:
        parts.append((NO_KEX + ' (resumed)', spare, NO_KEX))
    return parts


def has_verdict(buckets):
    """True when any bucket in this panel carries a verdict."""
    for bucket in buckets or ():
        if bucket.get('verdict') in VERDICT_VAR:
            return True
    return False


def has_direction(buckets):
    """
    True when the alerts panel can say which end sent each alert.

    The contract's bucket is {name, count, verdict?} with nowhere to put a
    direction, so it can only arrive folded into the name ("handshake_failure
    (from server)") or as an extra key the panel chose to add. Both are
    accepted here. When neither is present the page says so rather than
    printing counts that quietly merge the two ends -- all 29
    handshake_failure in this project's corpus came from the server and all
    11 certificate_unknown from the client, and merging those is merging two
    different problems with two different owners.
    """
    for bucket in buckets or ():
        if bucket.get('direction'):
            return True
        name = bucket.get('name')
        if isinstance(name, str) and 'from ' in name.lower():
            return True
    return False


def find_bucket(buckets, *names):
    """First bucket whose name matches one of `names`, or None."""
    wanted = set(n.lower() for n in names)
    for bucket in buckets or ():
        name = bucket.get('name')
        if isinstance(name, str) and name.lower() in wanted:
            return bucket
    return None


def bucket_count(buckets, *names):
    """The count of the first matching bucket, or 0."""
    bucket = find_bucket(buckets, *names)
    if not bucket:
        return 0
    try:
        return max(0, int(bucket.get('count') or 0))
    except (TypeError, ValueError):
        return 0


def percent(part, whole, places=1):
    """
    A percentage, or None when there is no denominator.

    None rather than 0.0 on purpose: the template prints an em dash for None
    and must never print "0.0%" to mean "we could not work it out". The house
    rule on this page is that no percentage appears without its base beside
    it, and a percentage of nothing has no base.
    """
    try:
        whole = float(whole)
        if whole <= 0:
            return None
        return round(100.0 * float(part) / whole, places)
    except (TypeError, ValueError):
        return None


def describe_span(span):
    """
    "2023-06-26 09:45 to 2024-12-11 22:16" for an overview's `span`, or None.

    This is the sentence that stops an empty window reading as a broken
    install. STATS_CONTRACT section 3 guarantees `span` is present with null
    ends on an empty collection, which is the one case where there is nothing
    to say.
    """
    span = span or {}
    first, last = span.get('first'), span.get('last')
    if first is None or last is None:
        return None
    try:
        start = dt.datetime.fromtimestamp(float(first))
        end = dt.datetime.fromtimestamp(float(last))
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    return '{0} to {1}'.format(start.strftime('%Y-%m-%d %H:%M'),
                               end.strftime('%Y-%m-%d %H:%M'))


def span_hours(span, now=None):
    """
    How many hours back a window must reach to include the whole span.

    Rounded up and capped at the contract's 8760, so the "widen the window"
    link on an empty page lands on a window that is actually valid rather
    than on a 400. Answers 0 -- the contract's "all of time" -- when the span
    reaches back more than a year, which is what a year-old capture needs.
    """
    span = span or {}
    first = span.get('first')
    if first is None:
        return 0
    try:
        moment = (float(now) if now is not None
                  else dt.datetime.now().timestamp())
        hours = int((moment - float(first)) / 3600.0) + 1
    except (TypeError, ValueError, OverflowError):
        return 0
    if hours <= 0:
        return 1
    return hours if hours <= 8760 else 0


__all__ = ['VERDICT_ORDER', 'VERDICT_VAR', 'NO_KEX', 'TIMELINE_BANDS',
           'BAND_VAR', 'safe_text', 'empty_chart', 'bar_chart',
           'ratio_bar', 'timeline_chart', 'verdict_rollup',
           'timeline_totals', 'band_class', 'headline_parts',
           'has_verdict', 'has_direction', 'find_bucket', 'bucket_count',
           'percent', 'describe_span', 'span_hours']
