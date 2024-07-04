import uuid
from typing import List, Optional, Union, Any, Dict, AnyStr, List
from pydantic import BaseModel, Field


# JSON is really just arrays and objects that look like this...
JSONStructure = Union[List[Any], Dict[AnyStr, Any]]


class IPModel(BaseModel):
    ipv4: str = "0.0.0.0"
    port: int = 80


class EthModel(BaseModel):
    src: dict = IPModel() 
    dst: dict = IPModel()


class TLSDataModel(BaseModel):
    id: str = Field(default_factory=uuid.uuid4, alias="_id")
    ptype: Optional[str] = Field(...)
    eth: str = EthModel()  # packet type
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
    ptype: Optional[str] = Field(...)
    eth: str = EthModel()  # packet type
    tls: dict = Field(...)
    
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
