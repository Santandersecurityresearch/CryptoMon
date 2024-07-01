from fastapi import APIRouter, Body, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from bson.json_util import ObjectId
from typing import Union

from .models import TLSDataModel, UpdateTLSDataModel, JSONStructure

router = APIRouter()


@router.post("/", response_description="Add new data")
async def create_task(request: Request, data: TLSDataModel = Body(...)):
    data = jsonable_encoder(data)
    new_data = await request.app.mongodb["cryptomon"].insert_one(data)
    created_data = await request.app.mongodb["cryptomon"].find_one(
        {"_id": new_data.inserted_id}
    )
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_data)


@router.get("/", response_description="List all packet captures")
async def list_data(request: Request):
    records = []
    for doc in await request.app.mongodb["cryptomon"].find().to_list(length=100):
        doc['_id'] = str(doc['_id'])
        records.append(doc)
    return records


@router.get("/{id}", response_description="Get a single capture by ID")
async def show_data(id: str, request: Request):
    if (data := await request.app.mongodb["cryptomon"].find_one({"_id": ObjectId(id)})) is not None:
        data['_id'] = str(data['_id'])
        return data
    raise HTTPException(status_code=404, detail=f"Data {id} not found")


@router.put("/{id}", response_description="Update TLS Data trace")
async def update_task(id: str, request: Request, data: UpdateTLSDataModel = Body(...)):
    data = {k: v for k, v in data.dict().items() if v is not None}
    if len(data) >= 1:
        update_result = await request.app.mongodb["cryptomon"].update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if update_result.modified_count == 1:
            if (
                updated_data := await request.app.mongodb["cryptomon"].find_one({"_id": ObjectId(id)})
            ) is not None:
                return updated_data
    if (
        existing_data := await request.app.mongodb["cryptomon"].find_one({"_id": ObjectId(id)})
    ) is not None:
        return existing_data
    raise HTTPException(status_code=404, detail=f"Data {id} not found")


@router.delete("/{id}", response_description="Delete TLS Data trace")
async def delete_data(id: str, request: Request):
    delete_result = await request.app.mongodb["cryptomon"].delete_one({"_id": ObjectId(id)})
    if delete_result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)
    raise HTTPException(status_code=404, detail=f"Data {id} not found")


@router.get("/count/", response_description="Count with search")
async def count_data(request: Request, k: Union[str, None] = None, v: Union[str, None] = None):
    if not k or not v:
        data = await request.app.mongodb["cryptomon"].count_documents()
    else:
        data = await request.app.mongodb["cryptomon"].count_documents({k: v})
    if data:
        return data
    raise HTTPException(status_code=404, detail="Data count not possible")

@router.post("/count/", response_description="Count with search, e.g.: {\"ptype\":\"server\", \"tls.ciphersuite\":\"TLS_AES_128_GCM_SHA256\"}")
async def count_data_with_param(request: Request, 
                                d: JSONStructure = Body(...)):
    data = jsonable_encoder(d)
    count = await request.app.mongodb["cryptomon"].count_documents(data)
    if count:
        return count
    raise HTTPException(status_code=404, detail="Data count not possible")