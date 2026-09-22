"""
Write access control and filter validation.

Before this, POST/PUT/DELETE took no credential on a service whose HOST
defaulted to 0.0.0.0, and both count endpoints passed caller-supplied JSON
straight into count_documents().
"""
import os

import pytest

os.environ.setdefault("DB_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "cryptomon-test")

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from fapi.app.query import QUERYABLE_FIELDS, safe_query        # noqa: E402
from fapi.app.routers import router                            # noqa: E402
from fapi.config import settings                               # noqa: E402

# Merge gate: no capture fixtures, no database.
pytestmark = pytest.mark.smoke


class FakeCollection:
    def __init__(self):
        self.seen = None

    async def count_documents(self, flt, **kw):
        self.seen = flt
        return 0

    async def find_one(self, flt):
        return None

    async def insert_one(self, doc):
        return type("R", (), {"inserted_id": "x"})()

    async def delete_one(self, flt):
        return type("R", (), {"deleted_count": 0})()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router, prefix="/data")
    app.mongodb = {"cryptomon": FakeCollection()}
    return TestClient(app, raise_server_exceptions=False), app


@pytest.fixture(autouse=True)
def _restore_settings():
    before = (settings.READ_ONLY, settings.API_KEY)
    yield
    settings.READ_ONLY, settings.API_KEY = before


RECORD = {"ptype": "server", "tls": {}, "eth": {}}


# --------------------------------------------------------------- defaults
def test_host_defaults_to_loopback():
    assert settings.HOST == "127.0.0.1", (
        "binding 0.0.0.0 by default publishes the API on every interface")


def test_read_only_is_the_default():
    assert settings.READ_ONLY is True


# ------------------------------------------------------------ write guard
@pytest.mark.parametrize("method,url", [
    ("POST", "/data/"),
    ("PUT", "/data/507f1f77bcf86cd799439011"),
    ("DELETE", "/data/507f1f77bcf86cd799439011"),
])
def test_mutating_routes_refused_when_read_only(client, method, url):
    c, _ = client
    settings.READ_ONLY = True
    r = c.request(method, url, json=RECORD)
    assert r.status_code == 403, f"{method} {url} was not refused"


@pytest.mark.parametrize("method,url", [
    ("GET", "/data/count/"),
    ("POST", "/data/count/"),
])
def test_reads_stay_open_when_read_only(client, method, url):
    c, _ = client
    settings.READ_ONLY = True
    body = {"ptype": "server"} if method == "POST" else None
    r = c.request(method, url, json=body)
    assert r.status_code == 200


def test_writes_allowed_once_opted_in(client):
    c, _ = client
    settings.READ_ONLY = False
    settings.API_KEY = ""
    r = c.delete("/data/507f1f77bcf86cd799439011")
    assert r.status_code != 403


def test_api_key_required_when_configured(client):
    c, _ = client
    settings.READ_ONLY = False
    settings.API_KEY = "s3cret"
    assert c.delete("/data/507f1f77bcf86cd799439011").status_code == 401
    assert c.delete("/data/507f1f77bcf86cd799439011",
                    headers={"X-API-Key": "wrong"}).status_code == 401
    r = c.delete("/data/507f1f77bcf86cd799439011",
                 headers={"X-API-Key": "s3cret"})
    assert r.status_code != 401


# ------------------------------------------------------- query allowlist
@pytest.mark.parametrize("payload", [
    {"$where": "sleep(5000)"},
    {"ptype": {"$ne": None}},
    {"tls.ciphersuite": {"$regex": "(a+)+$"}},
    {"ptype": ["a", "b"]},
    {"not.a.field": "x"},
    {"eth.src.ipv4": {"$gt": ""}},
])
def test_post_count_rejects_injection(client, payload):
    c, app = client
    r = c.post("/data/count/", json=payload)
    assert r.status_code == 400, f"{payload} was not rejected"
    assert app.mongodb["cryptomon"].seen is None, "filter reached Mongo"


def test_get_count_rejects_operator_in_key(client):
    # {k: v} was built from a caller-supplied key, so this was the same hole.
    c, app = client
    r = c.get("/data/count/", params={"k": "$where", "v": "sleep(5000)"})
    assert r.status_code == 400
    assert app.mongodb["cryptomon"].seen is None


def test_allowlisted_equality_passes_through(client):
    c, app = client
    r = c.post("/data/count/", json={"ptype": "server"})
    assert r.status_code == 200
    assert app.mongodb["cryptomon"].seen == {"ptype": "server"}


def test_too_many_terms_refused():
    with pytest.raises(Exception):
        safe_query({f"f{i}": 1 for i in range(64)})


def test_long_values_refused():
    with pytest.raises(Exception):
        safe_query({"tls.hostname": "a" * 1024})


def test_allowlist_covers_the_documented_example():
    # The POST /count/ docstring advertises this query; it must still work.
    assert "ptype" in QUERYABLE_FIELDS
    assert "tls.ciphersuite" in QUERYABLE_FIELDS
    assert safe_query({"ptype": "server",
                       "tls.ciphersuite": "TLS_AES_128_GCM_SHA256"})
