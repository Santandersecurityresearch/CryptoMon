"""
Write access control for the API.

Every mutating route was open: POST /data/, PUT /data/{id} and
DELETE /data/{id} took no credential of any kind, on a service whose HOST
defaulted to 0.0.0.0. Two independent layers now stand in front of them --
read-only by default, and an optional shared key -- because either one alone
is a single setting away from an open write endpoint.
"""
import secrets

from fastapi import Header, HTTPException, status

from fapi.config import settings

READ_ONLY_DETAIL = (
    "This deployment is read-only. Set CRYPTOMON_READ_ONLY=false to enable "
    "writes, and set CRYPTOMON_API_KEY as well if the service is reachable "
    "from anywhere but localhost."
)


async def require_write_access(x_api_key: str = Header(default=None)):
    """
    Guard the mutating routes.

    Read-only is the default, so an operator has to opt in to writes rather
    than remember to opt out. When an API key is configured it is compared
    with secrets.compare_digest, which does not leak the key's prefix through
    response timing the way `==` does.
    """
    if settings.READ_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=READ_ONLY_DETAIL)
    if settings.API_KEY:
        if not x_api_key or not secrets.compare_digest(str(x_api_key),
                                                       settings.API_KEY):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid X-API-Key header is required for writes.",
                headers={"WWW-Authenticate": "X-API-Key"})
