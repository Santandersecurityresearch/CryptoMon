#!/usr/bin/python

"""
cryptomon-api.py  A FastAPI based interface for a MongoDB database,
    that is ingesting processed TLS data from a cryptomon service.

Licensed under the Apache License, Version 2.0 (the "License")
Author: Mark Carney (mark[.]carney[@]gruposantander[.]com)
"""

__author__ = "Mark Carney"
__copyright__ = "Copyright 2024, Mark Carney"
__credits__ = ["Mark Carney"]
__license__ = "GLP 3.0"
__version__ = "1.0.0"
__maintainer__ = "Mark Carney"
__email__ = "mark.carney@gruposantander.com"
__status__ = "Demonstration"


import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware
# from starlette.responses import FileResponse
# from starlette.staticfiles import StaticFiles

import uvicorn
from motor.motor_asyncio import AsyncIOMotorClient

from fapi.config import settings

from fapi.app.indexes import ensure_indexes
from fapi.app.retention import sweep_periodically
from fapi.app.dashboard import router as dashboard_routers
from fapi.app.routers import router as data_routers
from fapi.app.stats import router as stats_routers
from fapi.app.uploads import router as upload_routers


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Open the database, make sure the indexes exist, then hand over.

    Replaces the paired @app.on_event("startup"/"shutdown") handlers, which
    are deprecated: a single context manager keeps setup and the matching
    teardown in one place, and guarantees the client is closed even when
    startup raises part-way through.

    Index creation lives here because this is the only moment the collection
    is known and nothing is serving yet. It never blocks startup -- see
    fapi/app/indexes.py.

    The retention sweep is started here too, and cancelled on the way out. It
    runs in this process rather than as a cron entry so that a deployment
    cannot end up serving an upload form that promises expiry while nothing
    is expiring anything.
    """
    app.mongodb_client = AsyncIOMotorClient(settings.DB_URL)
    app.mongodb = app.mongodb_client[settings.DB_NAME]
    sweeper = asyncio.create_task(sweep_periodically(
        settings.UPLOAD_DIR, settings.REPORT_RETENTION_HOURS,
        settings.RETENTION_SWEEP_MINUTES))
    try:
        await ensure_indexes(app.mongodb["cryptomon"],
                             settings.DATA_RETENTION_HOURS)
        yield
    finally:
        sweeper.cancel()
        app.mongodb_client.close()


# root_path is what makes a subpath mount work. FastAPI puts it in the ASGI
# scope; starlette strips it before routing and puts it back in url_for, so
# the redirect after an upload (fapi/app/uploads.py) and the /docs page both
# land on the right side of the prefix. Empty by default, which is the root
# mount every existing deployment has.
#
# The reverse proxy must pass the URI *unchanged*, prefix included, and must
# NOT also be given `uvicorn --root-path` -- that flag prepends the prefix a
# second time. deploy/nginx/cryptomon.conf explains both.
app = FastAPI(lifespan=lifespan, root_path=settings.ROOT_PATH)

# Add CORS middleware if needed...
# app.add_middleware(CORSMiddleware,allow_origins="*",allow_credentials=True,allow_methods=["*"],allow_headers=["*"],)

app.include_router(data_routers, tags=["cryptomon"], prefix="/data")
# The capture upload UI. Mounted under /analyse rather than at the root so
# that PR-37's dashboard can have "/" without either of them moving.
app.include_router(upload_routers, tags=["analyse"], prefix="/analyse")
# The read-only rollups. Declared before anything that claims "/",
# because FastAPI matches in declaration order and a root mount declared
# first would swallow these -- the same defect as PR-06's "/{id}"
# swallowing "/data/count", one level up.
app.include_router(stats_routers, tags=["stats"], prefix="/stats")
# The dashboard, at the site root -- which is what the upload UI moved
# out of the way for. It reads its numbers from fapi/app/stats.py through
# an import it does inside the request handler, so a deployment without
# that module answers a 503 page saying so rather than failing to start.
# Declared last, because it claims "/".
app.include_router(dashboard_routers, tags=["dashboard"])

# load some static pages, if required. 
# app.mount("/", StaticFiles(directory="frontend/dist/"), name="ui")

if __name__ == "__main__":
    uvicorn.run("api:app",
                host=settings.HOST,
                reload=settings.DEBUG_MODE,
                port=settings.PORT,)
