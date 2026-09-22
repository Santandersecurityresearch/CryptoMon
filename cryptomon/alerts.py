"""
What a TLS alert says, and which ones are worth chasing.

pcapscan already collects every plaintext alert it sees: `records.py` keeps
them as (level, description) pairs and `sessions.py` writes them into the
record as `tls['alerts'] = [{'level': 2, 'description': 40}]`. Two integers.
This module is the meaning behind them -- the names, which combinations are
a finding, and which are a connection closing normally.

**The finding this module exists for is one correlation.** A client offers a
post-quantum key exchange and the connection dies with a fatal
handshake_failure. Where that is a server -- or, more often, a middlebox
between the two -- that cannot cope with a ClientHello carrying a kilobyte
of ML-KEM key share, it is the most actionable thing a readiness survey
produces, because the fix is somebody else's configuration and they do not
know yet. Where it is not, it is still the shortest path to finding out,
which is why what follows reports the correlation and stops short of the
conclusion.

Measured over the whole corpus, 1260 sessions in twelve captures:

    42 sessions carry a plaintext alert, every one of them fatal
    29 handshake_failure (40), 11 certificate_unknown (46),
     2 inappropriate_fallback (86)
    35 of those 42 had offered a post-quantum group
     0 close_notify

The correlation above fires on 24 of them. Two things that number does not
say, and a report built on it must not say either:

  * **Which side sent the alert.** The session record merges both
    directions, so a handshake_failure after a post-quantum offer reads the
    same whether a middlebox refused the client's key share or the client
    refused the server's parameters. On this corpus it is the second: all
    24 are dh512.badssl.com and dh1024.badssl.com, deliberately weak test
    servers, and the post-quantum offer is incidental -- 448 of the 1260
    sessions offer one, because current browsers offer one on every
    connection. The correlation is the right thing to compute and this
    corpus does not contain the intolerance it looks for. Recording the
    direction of each alert would separate the two; see the note at the
    bottom of this docstring.

  * **close_notify never appearing is not evidence that it is rare.** It is
    sent under the negotiated keys, and pcapscan stops reading a stream at
    the first encrypted record, so every plaintext alert is by construction
    one sent *during* a handshake. The rule below therefore guards the live
    path, handshakes aborted before ChangeCipherSpec, and any decrypted
    input a later PR feeds in -- not this corpus. It is still the most
    important rule here, because getting it wrong reports every clean
    shutdown in a capture as an incident.

The two inappropriate_fallback are that same weak server at TLSv1.0: the
client retried at a lower version after the failure and RFC 7507 downgrade
protection caught it. Rare, never routine, and its own finding rather than
noise.

What would sharpen all of this: the side is known at the moment the alerts
are collected -- pcapscan's SessionBuilder has `from_client` in hand where
it copies them off the per-direction walker -- and is dropped one line
later. Carrying it into the record would turn "somebody refused" into "the
server refused", which is the difference between a finding and a lead.

Like cryptomon/analysis.py this layer is pure: it takes an iterable of
session records and returns data. It opens nothing and parses nothing.
"""
import collections

from cryptomon.analysis import HYBRID, POST_QUANTUM, classify_algorithm

# RFC 8446 section 6 kept two levels from RFC 5246 section 7.2 and then said
# the distinction is meaningless in TLS 1.3 -- every alert but close_notify
# and user_canceled is fatal whatever the byte claims. The byte is recorded
# as sent, because what a peer *said* is the observation; see severity()
# for the judgement, which does not consult it.
ALERT_LEVELS = {
    1: 'warning',
    2: 'fatal',
}

# The IANA TLS Alerts registry in full, as of RFC 8446/9147. The _RESERVED
# names are the registry's own: those code points are retired, not free, and
# a peer still sending one (SSL 3.0 era stacks do) should be named rather
# than reported as unknown.
ALERT_DESCRIPTIONS = {
    0: 'close_notify',
    10: 'unexpected_message',
    20: 'bad_record_mac',
    21: 'decryption_failed_RESERVED',
    22: 'record_overflow',
    30: 'decompression_failure_RESERVED',
    40: 'handshake_failure',
    41: 'no_certificate_RESERVED',
    42: 'bad_certificate',
    43: 'unsupported_certificate',
    44: 'certificate_revoked',
    45: 'certificate_expired',
    46: 'certificate_unknown',
    47: 'illegal_parameter',
    48: 'unknown_ca',
    49: 'access_denied',
    50: 'decode_error',
    51: 'decrypt_error',
    52: 'too_many_cids_requested',
    60: 'export_restriction_RESERVED',
    70: 'protocol_version',
    71: 'insufficient_security',
    80: 'internal_error',
    86: 'inappropriate_fallback',
    90: 'user_canceled',
    100: 'no_renegotiation_RESERVED',
    109: 'missing_extension',
    110: 'unsupported_extension',
    111: 'certificate_unobtainable_RESERVED',
    112: 'unrecognized_name',
    113: 'bad_certificate_status_response',
    114: 'bad_certificate_hash_value_RESERVED',
    115: 'unknown_psk_identity',
    116: 'certificate_required',
    120: 'no_application_protocol',
}

# The three answers to "is this a problem?".
CRYPTOGRAPHIC = 'cryptographic'
ORDINARY = 'ordinary'
SHUTDOWN = 'shutdown'

# Alerts that say the two sides could not agree on cryptography, which is
# the question this tool asks. Each is here for a reason:
#
#   40  handshake_failure      no acceptable set of parameters. The generic
#                              refusal, and what a middlebox intolerant of a
#                              large key share returns.
#   70  protocol_version       the version offered was refused -- a TLS 1.3
#                              client talking to something that will only do
#                              1.2 is a ceiling on everything above it.
#   71  insufficient_security  the peer refused *because* the parameters were
#                              too weak. The one alert that is a verdict on
#                              strength rather than on compatibility.
#   86  inappropriate_fallback downgrade protection firing (RFC 7507). Rare
#                              and never routine: something between the two
#                              retried at a lower version and was caught.
#  120  no_application_protocol the weakest member of this set, and it is
#                              here honestly: an ALPN mismatch is not a
#                              cryptographic failure. It earns its place
#                              because it is what a terminating proxy sends
#                              when it cannot forward what the client asked
#                              for, and a proxy is an interception point --
#                              which is the thing a readiness survey most
#                              needs to notice.
#
# bad_record_mac (20) and decrypt_error (51) are deliberately *not* here.
# Both are cryptographic in the literal sense, but they fire after the
# algorithms were agreed: they mean an implementation bug, a corrupt path or
# a truncated capture, not a finding about which algorithms are deployed.
CRYPTOGRAPHIC_ALERTS = frozenset({40, 70, 71, 86, 120})

# close_notify is how a connection ends. It is not an error, it is not a
# warning, and treating it as either makes every well-behaved session in the
# capture look like an incident -- which is most of them.
SHUTDOWN_ALERTS = frozenset({0})

ALERT_CLOSE_NOTIFY = 0
ALERT_HANDSHAKE_FAILURE = 40
ALERT_INAPPROPRIATE_FALLBACK = 86

# Finding kinds. The first two are separate answers, not two severities of
# one answer: a refused post-quantum offer is a deployment gap somebody can
# close this quarter, and an inappropriate_fallback is a downgrade attempt
# or a broken middlebox happening now.
PQ_HANDSHAKE_FAILURE = 'pq_handshake_failure'
INAPPROPRIATE_FALLBACK = 'inappropriate_fallback'
CRYPTOGRAPHIC_ALERT = 'cryptographic_alert'
OTHER_ALERT = 'alert'


def describe_level(level):
    """
    Name an alert level. Never raises.

    An unrecognised level keeps its number, for the same reason
    describe_codepoint() does: 'Unknown' alone cannot be told from any other
    'Unknown' afterwards, and a peer inventing a third level is itself worth
    seeing.
    """
    try:
        return ALERT_LEVELS[level]
    except (KeyError, TypeError):
        return 'Unknown ({0})'.format(level)


def describe_description(description):
    """
    Name an alert description code. Never raises.

    Decimal rather than the hex describe_codepoint() uses, because the alert
    registry is written in decimal and 'handshake_failure' is 40 everywhere
    it is discussed -- including in the record this reads from.
    """
    try:
        return ALERT_DESCRIPTIONS[description]
    except (KeyError, TypeError):
        return 'Unknown ({0})'.format(description)


def _pair(alert):
    """
    (level, description) from whichever shape of alert was handed over.

    Three are in circulation and all three are legitimate: the dict in a
    session record, the `pcapscan.records.Alert` namedtuple that produced
    it, and a bare pair from a test. Refusing two of them would only push
    the conversion into every caller.
    """
    if isinstance(alert, dict):
        return alert.get('level'), alert.get('description')
    level = getattr(alert, 'level', None)
    if level is not None or hasattr(alert, 'description'):
        return level, getattr(alert, 'description', None)
    try:
        level, description = alert
    except (TypeError, ValueError):
        return None, None
    return level, description


def severity(alert):
    """
    CRYPTOGRAPHIC, ORDINARY or SHUTDOWN for one alert.

    Decided on the description alone. The level byte is not consulted: TLS
    1.3 made it advisory (RFC 8446 section 6), and a peer that sends
    handshake_failure at level 1 has still refused the handshake.
    """
    _level, description = _pair(alert)
    if description in SHUTDOWN_ALERTS:
        return SHUTDOWN
    if description in CRYPTOGRAPHIC_ALERTS:
        return CRYPTOGRAPHIC
    return ORDINARY


def is_finding(alert):
    """
    True if this alert is worth reporting at all.

    Exactly one thing is excluded, and it is the common case: close_notify.
    """
    return severity(alert) != SHUTDOWN


def describe(alert):
    """One alert, named and judged, as plain data."""
    level, description = _pair(alert)
    return {
        'level': level,
        'level_name': describe_level(level),
        'description': description,
        'name': describe_description(description),
        'severity': severity(alert),
    }


def session_alerts(record):
    """Every alert on one session record, named and judged."""
    tls = record.get('tls') or {}
    return [describe(alert) for alert in (tls.get('alerts') or [])]


def offered_post_quantum(record):
    """
    The post-quantum and hybrid groups this client offered, in order.

    Four places in a record can name a group the client was willing to use,
    and they say different things: `proposed.groups` is the supported_groups
    list (what it would accept), `proposed.kex_group` is the key share it
    actually sent (what it spent bytes on), and `offered_kex_group` /
    `kex_group` are what survived a HelloRetryRequest. A server that refuses
    the connection outright leaves only the first two, so reading any one of
    them alone loses most of the correlation this module is for.

    Hybrid counts as offered. X25519MLKEM768 is the post-quantum key
    exchange actually deployed today, and it is the one whose size the
    intolerant middleboxes choke on.
    """
    tls = record.get('tls') or {}
    proposed = tls.get('proposed') or {}
    candidates = list(proposed.get('groups') or [])
    candidates.extend([proposed.get('kex_group'),
                       tls.get('offered_kex_group'),
                       tls.get('kex_group')])
    offered = []
    for name in candidates:
        if not name or name in offered:
            continue
        if classify_algorithm(name) in (POST_QUANTUM, HYBRID):
            offered.append(name)
    return offered


def _endpoint(record):
    """Who was being talked to -- the server side of the connection."""
    destination = (record.get('eth') or {}).get('dst') or {}
    return (destination.get('ipv4') or destination.get('ipv6'),
            destination.get('port'))


def _kind(alert, post_quantum_offered):
    if alert['description'] == ALERT_INAPPROPRIATE_FALLBACK:
        return INAPPROPRIATE_FALLBACK
    if alert['description'] == ALERT_HANDSHAKE_FAILURE \
            and post_quantum_offered:
        return PQ_HANDSHAKE_FAILURE
    if alert['severity'] == CRYPTOGRAPHIC:
        return CRYPTOGRAPHIC_ALERT
    return OTHER_ALERT


def findings(records):
    """
    Every alert worth acting on, one entry per alert, in order.

    close_notify never appears. Everything else does, tagged with a kind, so
    that a report can show the post-quantum refusals first without having to
    re-derive which alerts matter -- and without silently dropping the
    certificate_unknown that a human would still want to see.

    Each entry carries what it takes to act: the host, the address and port,
    the timestamp, the alert itself, and the post-quantum groups the client
    had offered. The offer is on *every* finding rather than only on the
    correlated ones, because "this server refused us and we were not asking
    for anything exotic" is the sentence that closes a false lead.
    """
    out = []
    for record in records:
        alerts = session_alerts(record)
        if not alerts:
            continue
        tls = record.get('tls') or {}
        offered = offered_post_quantum(record)
        address, port = _endpoint(record)
        for alert in alerts:
            if not is_finding(alert):
                continue
            out.append({
                'kind': _kind(alert, offered),
                'severity': alert['severity'],
                'hostname': tls.get('hostname'),
                'address': address,
                'port': port,
                'ts': record.get('ts'),
                'alert': alert,
                'offered_post_quantum': offered,
                'kex_group': tls.get('kex_group'),
                'tls_versions': tls.get('tls_versions'),
            })
    return out


def summarise(records):
    """
    Counts over an iterable of session records, plus the findings.

    Consumes the iterable once, like analysis.analyse(). `clean_shutdowns`
    -- sessions whose every alert was close_notify -- is reported rather
    than discarded so that the exclusion can be audited: on this corpus it
    is 0, and a reader should be able to see that from the output instead
    of having to trust that nothing was quietly dropped.
    """
    summary = {
        'sessions': 0,
        'sessions_with_alerts': 0,
        'alerts': collections.Counter(),
        'levels': collections.Counter(),
        'severity': collections.Counter(),
        'clean_shutdowns': 0,
        'post_quantum_offered_with_alert': 0,
        'findings': [],
        'kinds': collections.Counter(),
    }
    for record in records:
        summary['sessions'] += 1
        alerts = session_alerts(record)
        if not alerts:
            continue
        summary['sessions_with_alerts'] += 1
        for alert in alerts:
            summary['alerts'][alert['name']] += 1
            summary['levels'][alert['level_name']] += 1
            summary['severity'][alert['severity']] += 1
        if all(alert['severity'] == SHUTDOWN for alert in alerts):
            summary['clean_shutdowns'] += 1
        if offered_post_quantum(record):
            summary['post_quantum_offered_with_alert'] += 1
        for finding in findings([record]):
            summary['findings'].append(finding)
            summary['kinds'][finding['kind']] += 1
    return summary
