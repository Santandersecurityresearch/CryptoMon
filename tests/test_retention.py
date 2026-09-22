"""
Retention: deleting what should not be kept, and saying so.

The sweep tests drive `sweep()` directly with a controlled clock. The rest
check the two things that make retention real rather than decorative: that
it is running (started by the lifespan, not left to a cron entry somebody
forgets), and that it is stated in the UI before a file is chosen rather
than afterwards.
"""
import os
import time

import pytest

# fapi.config instantiates its Settings at import time and DB_URL/DB_NAME
# are required, so they are supplied before anything imports it -- the same
# pattern as test_api_lifespan.py and test_api_security.py.
os.environ.setdefault("DB_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "cryptomon-test")

from fapi.app.retention import (OWNED_SUFFIXES, describe, retention_field,
                                sweep, sweep_periodically, ttl_index)

pytestmark = pytest.mark.smoke

HOUR = 3600


@pytest.fixture
def spool(tmp_path):
    return tmp_path


def aged(directory, name, hours_old):
    path = directory / name
    path.write_bytes(b'{}')
    when = time.time() - hours_old * HOUR
    os.utime(path, (when, when))
    return path


# --------------------------------------------------------------------------
# the sweep
# --------------------------------------------------------------------------
def test_old_reports_go_and_recent_ones_stay(spool):
    aged(spool, 'old.json', 48)
    aged(spool, 'recent.json', 1)
    deleted, freed = sweep(spool, max_age_hours=24)
    assert deleted == 1
    assert freed > 0
    assert [p.name for p in spool.iterdir()] == ['recent.json']


def test_an_orphaned_capture_is_swept_too(spool):
    """
    uploads.py deletes a capture as soon as it is parsed, but a process
    killed between those two moments leaves the spooled file behind and
    nothing else would ever remove it.
    """
    aged(spool, 'abandoned.capture', 48)
    assert sweep(spool, max_age_hours=24)[0] == 1
    assert not list(spool.iterdir())


def test_files_the_sweep_does_not_own_are_left_alone(spool):
    """
    A retention job that deletes files it does not recognise is a data-loss
    incident waiting for the wrong UPLOAD_DIR.
    """
    aged(spool, 'important.txt', 500)
    aged(spool, 'notes.md', 500)
    aged(spool, 'report.json', 500)
    assert sweep(spool, max_age_hours=1)[0] == 1
    assert sorted(p.name for p in spool.iterdir()) == ['important.txt',
                                                       'notes.md']
    assert set(OWNED_SUFFIXES) == {'.json', '.capture'}


@pytest.mark.parametrize("hours", [0, -1, None])
def test_zero_hours_means_keep_everything(spool, hours):
    aged(spool, 'ancient.json', 10000)
    assert sweep(spool, max_age_hours=hours) == (0, 0)
    assert list(spool.iterdir())


def test_a_missing_directory_is_not_an_error(tmp_path):
    assert sweep(tmp_path / 'never-created', max_age_hours=1) == (0, 0)


def test_the_sweep_never_raises(spool, monkeypatch):
    """
    It runs unattended on a timer. A permissions problem on one file must
    not stop the next sweep from happening.
    """
    aged(spool, 'locked.json', 48)

    import pathlib
    original = pathlib.Path.unlink

    def refuse(self, *args, **kwargs):
        raise PermissionError('nope')

    monkeypatch.setattr(pathlib.Path, 'unlink', refuse)
    assert sweep(spool, max_age_hours=1) == (0, 0)
    monkeypatch.setattr(pathlib.Path, 'unlink', original)


def test_the_clock_can_be_supplied(spool):
    aged(spool, 'report.json', 2)
    assert sweep(spool, max_age_hours=24, now=time.time())[0] == 0
    # ...and from far enough in the future, the same file is stale.
    assert sweep(spool, max_age_hours=24,
                 now=time.time() + 72 * HOUR)[0] == 1


# --------------------------------------------------------------------------
# the live collection is a different decision
# --------------------------------------------------------------------------
def test_the_live_collection_does_not_expire_unless_asked():
    """
    Silently expiring a monitoring database because a library decided that
    was tidy would destroy the historical series this project exists to
    build. Retention there is opt-in.
    """
    # The class default, not the loaded singleton: `Settings` requires
    # DB_URL and DB_NAME, and what is being asserted here is the default
    # rather than whatever this machine's environment says.
    from fapi.config import RetentionSettings
    default = RetentionSettings.model_fields['DATA_RETENTION_HOURS'].default
    assert default == 0
    assert ttl_index(default) is None


def test_a_ttl_index_is_built_when_it_is_asked_for():
    pytest.importorskip("pymongo")
    index = ttl_index(48)
    assert index is not None
    document = index.document
    assert document['expireAfterSeconds'] == 0
    # On `expires_at`, not `ts`: MongoDB's TTL monitor only expires a BSON
    # date, and `ts` is stored as a float epoch.
    assert 'expires_at' in dict(document['key'])


def test_the_expiry_is_written_at_insert_time():
    """
    A date in the document rather than an offset, so that changing the
    setting later does not retroactively rewrite what is already stored.
    """
    import datetime
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    assert retention_field(0, now) is None
    assert retention_field(24, now) == now + datetime.timedelta(hours=24)


# --------------------------------------------------------------------------
# saying so
# --------------------------------------------------------------------------
def test_the_policy_reads_as_a_sentence():
    assert '24 hours' in describe(24, 0)
    assert '1 hour.' in describe(1, 0)
    assert 'until an operator removes them' in describe(0, 0)
    assert 'deleted as soon as they are analysed' in describe(24, 0)


def test_the_form_states_the_policy_before_a_file_is_chosen(tmp_path,
                                                            monkeypatch):
    """
    Before, not afterwards. Somebody deciding whether to upload a capture of
    their network needs to know how long it is kept at the moment they are
    deciding.
    """
    monkeypatch.setenv('DB_URL', 'mongodb://127.0.0.1:27017')
    monkeypatch.setenv('DB_NAME', 'cryptomon_test')
    testclient = pytest.importorskip("fastapi.testclient")
    from fapi.config import settings
    monkeypatch.setattr(settings, 'UPLOAD_DIR', str(tmp_path))
    monkeypatch.setattr(settings, 'REPORT_RETENTION_HOURS', 6)

    import api
    page = testclient.TestClient(api.app).get('/analyse/').text
    assert 'reports are deleted after 6 hours' in page
    assert 'browsing' in page.lower() or 'which hosts were contacted' in page


def test_the_periodic_sweeper_actually_sweeps(spool):
    """
    The loop, not just the function it calls. It sweeps once immediately,
    because the most likely moment for stale files to exist is straight
    after a restart -- which is also when the crash that left them happened.
    """
    import asyncio

    aged(spool, 'stale.json', 48)
    said = []

    async def drive():
        task = asyncio.create_task(sweep_periodically(
            str(spool), max_age_hours=1, every_minutes=60,
            announce=said.append))
        for _ in range(100):                 # let the first sweep land
            await asyncio.sleep(0.01)
            if not list(spool.iterdir()):
                break
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(drive())
    assert not list(spool.iterdir())
    assert said and 'retention' in said[0]


def test_the_sweeper_does_nothing_when_retention_is_off(spool):
    import asyncio
    aged(spool, 'kept.json', 10000)
    asyncio.run(sweep_periodically(str(spool), max_age_hours=0,
                                   every_minutes=1))
    assert list(spool.iterdir())


def test_the_sweeper_is_started_by_the_lifespan():
    """
    In-process rather than a cron entry, so a deployment cannot end up
    serving a form that promises expiry while nothing expires anything.
    """
    import inspect
    import api
    source = inspect.getsource(api.lifespan)
    assert 'sweep_periodically' in source
    assert 'sweeper.cancel()' in source
