"""
Startup wiring: the lifespan handler and the collection indexes.

@app.on_event("startup"/"shutdown") is deprecated, and index creation needs a
moment when the collection is known and nothing is serving yet -- which is the
same moment, so the two changes belong together.
"""
import asyncio
import os

import pytest

os.environ.setdefault("DB_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "cryptomon-test")

from fapi.app.indexes import CRYPTOMON_INDEXES, ensure_indexes   # noqa: E402
from fapi.config import settings                                 # noqa: E402

# Merge gate: no database, no capture fixtures.
pytestmark = pytest.mark.smoke


class FakeCollection:
    def __init__(self, explode=None):
        self.explode = explode
        self.created = None

    async def create_indexes(self, models):
        if self.explode:
            raise self.explode
        self.created = models
        return [m.document["name"] for m in models]


def test_indexes_are_created_once():
    collection = FakeCollection()
    names = asyncio.run(ensure_indexes(collection))
    # By value rather than by identity: ensure_indexes now copies the list so
    # that it can append an optional TTL index without mutating the module
    # constant.
    assert list(collection.created) == list(CRYPTOMON_INDEXES)
    assert set(names) == {"ts_desc", "ptype_ts", "tag_ts",
                          "tls_ciphersuite", "tls_kex_group"}


def test_no_index_deletes_data_unless_retention_is_configured():
    """
    An index that expires documents is a different kind of thing from one
    that speeds up a query, and it arrives only when asked for.
    """
    collection = FakeCollection()
    asyncio.run(ensure_indexes(collection))
    assert not any(getattr(i, "document", {}).get("expireAfterSeconds")
                   is not None for i in collection.created)

    collection = FakeCollection()
    names = asyncio.run(ensure_indexes(collection, retention_hours=48))
    assert "expires_at_ttl" in set(names)


def test_index_creation_failure_does_not_stop_startup():
    # A monitoring API that refuses to start because it could not optimise
    # itself is worse than a slow one.
    collection = FakeCollection(explode=RuntimeError("not authorized"))
    assert asyncio.run(ensure_indexes(collection)) == []


def test_every_index_is_named():
    # Unnamed indexes get a generated name, which makes them awkward to drop
    # and impossible to reason about in a migration.
    for model in CRYPTOMON_INDEXES:
        assert model.document.get("name")


def test_time_bounded_queries_are_covered():
    # Every dashboard query is time-bounded, so ts must lead or follow a
    # low-cardinality prefix in at least the compound cases.
    keyed = {m.document["name"]: [k for k, _ in m.document["key"].items()]
             for m in CRYPTOMON_INDEXES}
    assert keyed["ts_desc"] == ["ts"]
    assert keyed["ptype_ts"] == ["ptype", "ts"]
    assert keyed["tag_ts"] == ["tag", "ts"]


def test_index_set_stays_small():
    # Each index costs write throughput on a collection fed at packet rate.
    assert len(CRYPTOMON_INDEXES) <= 6


def test_settings_load_under_pydantic_v2():
    assert settings.HOST == "127.0.0.1"
    assert settings.READ_ONLY is True
    assert settings.DB_NAME


def test_env_var_names_are_unprefixed():
    """
    create-service.sh writes DB_URL and DB_NAME with no prefix, so the
    settings must read them that way. Adding an env_prefix would silently
    stop every existing deployment from finding its database.
    """
    import subprocess
    import sys
    script = ("from fapi.config import settings; "
              "print(settings.READ_ONLY)")
    env = dict(os.environ, READ_ONLY="false")
    out = subprocess.run([sys.executable, "-c", script], env=env,
                         capture_output=True, text=True)
    assert out.stdout.strip() == "False", out.stderr


def test_lifespan_opens_and_closes_the_client(monkeypatch):
    import api

    closed = {"yes": False}

    class FakeClient:
        def __init__(self, url):
            self.url = url

        def __getitem__(self, name):
            return {"cryptomon": FakeCollection()}

        def close(self):
            closed["yes"] = True

    monkeypatch.setattr(api, "AsyncIOMotorClient", FakeClient)

    async def drive():
        async with api.lifespan(api.app):
            assert api.app.mongodb_client.url == settings.DB_URL
        assert closed["yes"], "client was not closed on shutdown"

    asyncio.run(drive())
