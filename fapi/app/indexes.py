"""
Index definitions for the cryptomon collection.

Without these every filtered count and every aggregation is a collection
scan. That is survivable on a test database and is not: monitor-NUC-dump1.json
is 723MB, and this collection grows at packet rate.

The set is deliberately small. Each index costs write throughput on a
collection fed by a line-rate capture, so the rule here is that an index
exists only where a query the API actually exposes would otherwise scan:

  * ts                    every time-bounded query, and recency ordering
  * (ptype, ts)           "client vs server over time", the dashboard's spine
  * (tag, ts)             per-capture-run views; tag is how runs are labelled
  * tls.ciphersuite       the algorithm rollups this tool exists to produce
  * tls.kex_group         the same, for key exchange -- where the PQ answer is

Everything else in QUERYABLE_FIELDS is low-cardinality or rarely filtered,
and can earn an index when a real query needs one.
"""
import pymongo
from pymongo import IndexModel

CRYPTOMON_INDEXES = [
    IndexModel([("ts", pymongo.DESCENDING)], name="ts_desc"),
    IndexModel([("ptype", pymongo.ASCENDING), ("ts", pymongo.DESCENDING)],
               name="ptype_ts"),
    IndexModel([("tag", pymongo.ASCENDING), ("ts", pymongo.DESCENDING)],
               name="tag_ts"),
    IndexModel([("tls.ciphersuite", pymongo.ASCENDING)], name="tls_ciphersuite"),
    IndexModel([("tls.kex_group", pymongo.ASCENDING)], name="tls_kex_group"),
]


async def ensure_indexes(collection, retention_hours=0):
    """
    Create any missing indexes. Idempotent, and never fatal.

    create_indexes is a no-op for an index that already exists. Building one
    does not block reads or writes on MongoDB 4.2+, but it can still fail --
    an unreachable server, or a user without the rights to create indexes --
    and a monitoring API that refuses to start because it could not optimise
    itself is worse than a slow one. Failures are reported and startup
    continues.

    `retention_hours` adds a TTL index. It is separate from the list above
    because it deletes data rather than speeding up a query, and an index
    that deletes things belongs to an explicit setting -- see
    fapi/app/retention.py.
    """
    from fapi.app.retention import ttl_index

    indexes = list(CRYPTOMON_INDEXES)
    expiry = ttl_index(retention_hours)
    if expiry is not None:
        indexes.append(expiry)
    try:
        return await collection.create_indexes(indexes)
    except Exception as exc:
        print(f"[!] could not create indexes ({type(exc).__name__}: {exc}); "
              f"the API will run but filtered queries will scan.")
        return []
