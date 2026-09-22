from fastapi import (APIRouter, Body, Depends, Request, HTTPException,
                     status)
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from bson.json_util import ObjectId
from bson.errors import InvalidId
from typing import Union

from .models import TLSDataModel, UpdateTLSDataModel, JSONStructure
from .query import safe_query
from .security import require_write_access

router = APIRouter()

# Applied to every route that changes stored data. Reads stay open.
WRITE_GUARD = [Depends(require_write_access)]


def object_id(id: str) -> ObjectId:
    """
    Parse a document id, answering 404 rather than 500 for a malformed one.

    ObjectId() raises InvalidId on anything that is not 24 hex characters,
    which reached the client as an unhandled 500.
    """
    try:
        return ObjectId(id)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=404, detail=f"Data {id} not found")


@router.post("/", response_description="Add new data",
             dependencies=WRITE_GUARD)
async def create_task(request: Request,
                      data: TLSDataModel = Body(...)):
    data = jsonable_encoder(data)
    new_data = await request.app.mongodb["cryptomon"].insert_one(data)
    created_data = await request.app.mongodb["cryptomon"].find_one(
        {"_id": new_data.inserted_id}
    )
    return JSONResponse(status_code=status.HTTP_201_CREATED,
                        content=created_data)


@router.get("/", response_description="List all packet captures")
async def list_data(request: Request):
    records = []
    for doc in await request.app.mongodb["cryptomon"].find().to_list(length=100):
        doc['_id'] = str(doc['_id'])
        records.append(doc)
    return records


@router.get("/count", include_in_schema=False)
@router.get("/count/", response_description="Count with search")
async def count_data(request: Request,
                     k: Union[str, None] = None,
                     v: Union[str, None] = None,):
    # count_documents() takes its filter as a required positional argument, so
    # the unfiltered call raised TypeError and surfaced as a 500. Note that {}
    # is an exact count and scans; estimated_document_count() is the cheap
    # alternative if this becomes a problem on a large collection.
    # k is caller-supplied, so {k: v} was as injectable as the POST body:
    # ?k=$where reaches count_documents as an operator.
    query = safe_query({k: v} if k and v else {})
    count = await request.app.mongodb["cryptomon"].count_documents(query)
    # A count of zero is a valid answer, not a missing resource.
    return count


@router.post("/count", include_in_schema=False)
@router.post("/count/",
             response_description="Count with search, \
                e.g.: {\"ptype\":\"server\", \
                    \"tls.ciphersuite\":\"TLS_AES_128_GCM_SHA256\"}")
async def count_data_with_param(request: Request,
                                d: JSONStructure = Body(...)):
    data = safe_query(jsonable_encoder(d))
    count = await request.app.mongodb["cryptomon"].count_documents(data)
    return count


@router.get("/{id}", response_description="Get a single capture by ID")
async def show_data(id: str, request: Request):
    if (data := await request.app.mongodb["cryptomon"].find_one({"_id": object_id(id)})) is not None:
        data['_id'] = str(data['_id'])
        return data
    raise HTTPException(status_code=404, detail=f"Data {id} not found")


@router.put("/{id}", response_description="Update TLS Data trace",
            dependencies=WRITE_GUARD)
async def update_task(id: str, request: Request,
                      data: UpdateTLSDataModel = Body(...)):
    data = {k: v for k, v in data.dict().items() if v is not None}
    if len(data) >= 1:
        update_result = await request.app.mongodb["cryptomon"].update_one(
            {"_id": object_id(id)}, {"$set": data}
        )
        if update_result.modified_count == 1:
            if (
                updated_data := await request.app.mongodb["cryptomon"].find_one({"_id": object_id(id)})
            ) is not None:
                return updated_data
    if (
        existing_data := await request.app.mongodb["cryptomon"].find_one({"_id": object_id(id)})
    ) is not None:
        return existing_data
    raise HTTPException(status_code=404, detail=f"Data {id} not found")


@router.delete("/{id}", response_description="Delete TLS Data trace",
               dependencies=WRITE_GUARD)
async def delete_data(id: str, request: Request):
    delete_result = await request.app.mongodb["cryptomon"].delete_one({"_id": object_id(id)})
    if delete_result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)
    raise HTTPException(status_code=404, detail=f"Data {id} not found")
