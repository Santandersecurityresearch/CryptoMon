"""
Deleting what should not be kept.

**A capture's SNI field is somebody's browsing history.** `tls.hostname` says
which sites a machine connected to and when, and a capture uploaded to
diagnose one connection carries every other connection that was happening at
the time. The same is true of the live path's collection, at much greater
volume.

That is not a reason to stop recording it -- the hostname is what makes a
report readable, and provenance is what makes a CBOM worth anything. It is a
reason to delete it on a schedule, to make the schedule visible to whoever is
uploading, and to let an operator shorten it.

Two stores, two mechanisms, and they are deliberately not the same default.

**Uploaded reports expire by default**, after `REPORT_RETENTION_HOURS` (24).
A report is a transient artefact of somebody asking a question, nobody
promised to keep it, and the upload form says so before the file is chosen
rather than afterwards.

**The live collection does not**, unless asked. `DATA_RETENTION_HOURS`
defaults to 0, meaning keep. Silently expiring a monitoring database because
a library decided that was tidy would destroy the historical series this
whole project exists to build. When it is set, it becomes a MongoDB TTL
index, which is the right tool: the server does the deleting whether or not
this service is running.

The sweep is also how a crashed analysis gets cleaned up. `uploads.py` deletes
a capture as soon as it has been parsed, but a process killed between those
two moments leaves the spooled file behind, and nothing else would ever
remove it.
"""
import asyncio
import pathlib
import time

# How long a sweep may take before it is abandoned. A directory that has
# grown large enough to matter should not hold the event loop.
SWEEP_DEADLINE_SECONDS = 30

# Suffixes the sweep owns. Anything else in the directory was put there by
# somebody else and is left alone -- a retention job that deletes files it
# does not recognise is a data-loss incident waiting for the wrong
# UPLOAD_DIR.
OWNED_SUFFIXES = ('.json', '.capture')


def sweep(directory, max_age_hours, now=None):
    """
    Delete reports and orphaned captures older than `max_age_hours`.

    Returns (deleted, bytes_freed). Never raises: this runs unattended on a
    timer, and a permissions problem on one file must not stop the next
    sweep from happening.

    `max_age_hours` of 0 or less means keep everything, and the directory is
    not even walked.
    """
    if not max_age_hours or max_age_hours <= 0:
        return 0, 0
    path = pathlib.Path(directory).expanduser()
    if not path.is_dir():
        return 0, 0

    cutoff = (now or time.time()) - max_age_hours * 3600
    deadline = time.monotonic() + SWEEP_DEADLINE_SECONDS
    deleted = freed = 0
    try:
        entries = sorted(path.iterdir())
    except OSError:
        return 0, 0
    for entry in entries:
        if time.monotonic() > deadline:
            break
        if entry.suffix not in OWNED_SUFFIXES or not entry.is_file():
            continue
        try:
            stat = entry.stat()
            if stat.st_mtime >= cutoff:
                continue
            entry.unlink()
        except OSError:
            continue
        deleted += 1
        freed += stat.st_size
    return deleted, freed


async def sweep_periodically(directory, max_age_hours, every_minutes,
                             announce=print):
    """
    Run `sweep` forever, on a timer. Cancel the task to stop it.

    Sweeps once immediately, because the most likely moment for stale files
    to exist is straight after a restart -- which is also when a crash that
    left them behind happened.
    """
    if not max_age_hours or max_age_hours <= 0:
        return
    interval = max(60, int(every_minutes) * 60)
    while True:
        deleted, freed = await asyncio.to_thread(
            sweep, directory, max_age_hours)
        if deleted:
            announce("[i] retention: removed {0} file(s), {1} KB, older "
                     "than {2}h from {3}".format(
                         deleted, freed // 1024, max_age_hours, directory))
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return


def ttl_index(hours, field='ts'):
    """
    A MongoDB TTL index for the live collection, or None to keep everything.

    The documents store `ts` as a float epoch, and MongoDB's TTL monitor only
    expires a BSON date -- so this cannot simply be pointed at the existing
    field. It expires on `expires_at`, which `retention_field()` computes,
    and a deployment that wants retention has to have been writing that field.
    Saying so is better than adding an index that silently expires nothing.
    """
    if not hours or hours <= 0:
        return None
    import pymongo
    from pymongo import IndexModel
    return IndexModel([('expires_at', pymongo.ASCENDING)],
                      name='expires_at_ttl', expireAfterSeconds=0)


def retention_field(hours, now=None):
    """
    The `expires_at` value to store on a new document, or None.

    A datetime rather than an offset, because a TTL index compares against
    the value in the document: writing the expiry date at insert time means
    changing the setting later does not retroactively rewrite what is
    already stored.
    """
    if not hours or hours <= 0:
        return None
    import datetime
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    return moment + datetime.timedelta(hours=hours)


def describe(report_hours, data_hours):
    """One sentence for the UI. Empty when nothing expires."""
    if report_hours and report_hours > 0:
        return ("Uploaded captures are deleted as soon as they are analysed, "
                "and reports are deleted after {0} hour{1}.".format(
                    report_hours, '' if report_hours == 1 else 's'))
    return ("Uploaded captures are deleted as soon as they are analysed. "
            "Reports are kept until an operator removes them.")
