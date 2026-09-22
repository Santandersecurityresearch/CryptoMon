"""
Filter validation for the count endpoints.

Both of them handed caller-supplied JSON straight to count_documents():

    POST /data/count/   {"$where": "sleep(5000)"}
    POST /data/count/   {"ptype": {"$ne": null}}
    GET  /data/count/?k=$where&v=...

The first two are Mongo operator injection; a $regex against a collection the
size of this one (monitor-NUC-dump1.json is 723MB) is a trivial denial of
service. The GET form is the same hole reached through a query parameter,
because the filter was built as {k: v} from a caller-supplied key.

Only equality on a known field is accepted. No operators, no nested
documents, no arrays -- which is what closes both.
"""
from fastapi import HTTPException, status

from cryptomon.data import SSH_SECTIONS

MAX_TERMS = 16
MAX_VALUE_LENGTH = 256

QUERYABLE_FIELDS = frozenset(
    ["ptype", "tag", "ts", "_id",
     "eth.src.ipv4", "eth.src.port", "eth.dst.ipv4", "eth.dst.port",
     "tls.tls_versions", "tls.ciphersuite", "tls.ciphersuites",
     "tls.kex_group", "tls.groups", "tls.sigalgs", "tls.hostname"]
    # keep the SSH fields in step with the parser rather than restating them
    + [f"ssh.{section}" for section in SSH_SECTIONS]
)


def safe_query(raw):
    """
    Validate a caller-supplied filter, or raise 400.

    Returns a Mongo filter safe to pass to count_documents(). The offending
    field is named in the error; the value never is, so a payload is not
    reflected back to whoever sent it.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The filter must be a JSON object of field/value pairs.")
    if len(raw) > MAX_TERMS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"At most {MAX_TERMS} filter terms are accepted.")

    query = {}
    for field, value in raw.items():
        if not isinstance(field, str) or field not in QUERYABLE_FIELDS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field!r} is not a queryable field. "
                       f"Allowed: {', '.join(sorted(QUERYABLE_FIELDS))}")
        # A dict or list here is how $ne, $gt and $regex get smuggled in.
        if isinstance(value, (dict, list)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Only an exact value may be matched against "
                       f"{field!r}; operators are not accepted.")
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported value type for {field!r}.")
        if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Value for {field!r} exceeds {MAX_VALUE_LENGTH} "
                       f"characters.")
        query[field] = value
    return query
