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


from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware
# from starlette.responses import FileResponse
# from starlette.staticfiles import StaticFiles

import uvicorn
from motor.motor_asyncio import AsyncIOMotorClient

from fapi.config import settings

from fapi.app.routers import router as data_routers

app = FastAPI()


@app.on_event("startup")
async def startup_dbclient_and_monitor():
    app.mongodb_client = AsyncIOMotorClient(settings.DB_URL)
    app.mongodb = app.mongodb_client[settings.DB_NAME]


@app.on_event("shutdown")
async def shutdown_db_client():
    app.mongodb_client.close()

# Add CORS middleware if needed...
# app.add_middleware(CORSMiddleware,allow_origins="*",allow_credentials=True,allow_methods=["*"],allow_headers=["*"],)

app.include_router(data_routers, tags=["cryptomon"], prefix="/data")

# load some static pages, if required. 
# app.mount("/", StaticFiles(directory="frontend/dist/"), name="ui")

if __name__ == "__main__":
    uvicorn.run("api:app",
                host=settings.HOST,
                reload=settings.DEBUG_MODE,
                port=settings.PORT,)
