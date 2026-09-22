"""Backend dispatch and write accounting."""
import asyncio

import pytest

from cryptomon import CryptoMon, WRITE_STATS, DEFAULT_MAX_PENDING

# Merge gate: these need no capture fixtures and run in well under a second.
pytestmark = pytest.mark.smoke


def stub(backend):
    obj = CryptoMon.__new__(CryptoMon)
    obj.data_tag = ""
    obj.max_pending = DEFAULT_MAX_PENDING
    obj._pending = set()
    obj._warned_writes = set()
    obj.mongodb_client = obj.mongodb = obj.tinydb = obj.fapi_app = None
    obj.fapi_on = False
    obj.backend = backend
    return obj


@pytest.fixture(autouse=True)
def _clear():
    WRITE_STATS.clear()
    yield
    WRITE_STATS.clear()


def test_tinydb_backend_is_reachable():
    # Regression: __init__ used `self.mongodb = False` as its sentinel and
    # handle_data tested `is not None`, so this path raised TypeError and the
    # documented zero-infrastructure mode never ran.
    rows = []
    obj = stub("tinydb")
    obj.tinydb = type("T", (), {"insert": lambda self, d: rows.append(d)})()
    obj.handle_data({"probe": 1})
    assert len(rows) == 1
    assert "ts" in rows[0]
    assert WRITE_STATS["inserted"] == 1


def test_failed_write_is_counted():
    obj = stub("tinydb")

    def boom(self, doc):
        raise IOError("disk full")

    obj.tinydb = type("T", (), {"insert": boom})()
    obj.handle_data({"probe": 2})
    assert WRITE_STATS["failed"] == 1
    assert WRITE_STATS["failed_OSError"] == 1


def test_mongo_failure_is_retrieved_from_the_future():
    async def scenario():
        obj = stub("mongodb")

        class Collection:
            def insert_one(self, doc):
                future = asyncio.get_running_loop().create_future()
                future.set_exception(RuntimeError("auth failed"))
                return future

        obj._insert_mongo(Collection(), {"probe": 3})
        await asyncio.sleep(0)
        assert WRITE_STATS["failed"] == 1
        assert not obj._pending

    asyncio.run(scenario())


def test_backpressure_bounds_inflight_writes():
    async def scenario():
        obj = stub("mongodb")
        obj.max_pending = 5
        loop = asyncio.get_running_loop()

        class Collection:
            def insert_one(self, doc):
                return loop.create_future()      # never resolves

        for i in range(20):
            obj._insert_mongo(Collection(), {"i": i})
        assert len(obj._pending) == 5
        assert WRITE_STATS["dropped_backpressure"] == 15

    asyncio.run(scenario())


def test_missing_event_loop_is_reported_not_silent():
    obj = stub("mongodb")

    class Collection:
        def insert_one(self, doc):
            raise RuntimeError("no running event loop")

    obj._insert_mongo(Collection(), {"probe": 5})
    assert WRITE_STATS["failed"] == 1
