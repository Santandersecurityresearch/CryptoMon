import uuid
from typing import List, Optional, Union, Any, Dict, AnyStr, List
from pydantic import BaseModel, Field


# JSON is really just arrays and objects that look like this...
JSONStructure = Union[List[Any], Dict[AnyStr, Any]]


class IPModel(BaseModel):
    ipv4: str = "0.0.0.0"
    port: int = 80


class EthModel(BaseModel):
    # Annotated as IPModel, not dict: these default to IPModel instances, and
    # a mutable default must come from a factory rather than one shared
    # instance built at class-definition time.
    src: IPModel = Field(default_factory=IPModel)
    dst: IPModel = Field(default_factory=IPModel)


class TLSDataModel(BaseModel):
    # `str` with a uuid.uuid4 factory declared one type and produced another;
    # stringify in the factory so the value matches the annotation.
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    ptype: Optional[str] = Field(...)
    eth: EthModel = Field(default_factory=EthModel)
    tls: Optional[dict] = Field(...)

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
                "ptype": 'server',
                "eth": {"src": {"ipv4": '172.64.155.119', "port": 443},
                        "dst": {"ipv4": '192.168.64.5', "port": 33789}},
                "tls": {
                    "tls_versions": 'TLSv1.2',
                    "ciphersuite": 'TLS_AES_128_GCM_SHA256',
                    "kex_group": 'x25519'
                }
            }
        }


class UpdateTLSDataModel(BaseModel):
    # Every field is optional: update_task() builds its $set from whichever
    # fields are not None, so requiring all of them made that filtering dead
    # code and blocked partial updates outright.
    ptype: Optional[str] = None
    eth: Optional[EthModel] = None
    tls: Optional[dict] = None
    
    class Config:
        schema_extra = {
            "example":   {
                "ptype": 'server',
                "eth": {"src": {"ipv4": '172.64.155.119', "port": 443},
                        "dst": {"ipv4": '192.168.64.5', "port": 33789}},
                "tls": {
                    "tls_versions": 'TLSv1.2',
                    "ciphersuite": 'TLS_AES_128_GCM_SHA256',
                    "kex_group": 'x25519'
                }
            }
        }
