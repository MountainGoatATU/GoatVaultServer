import uuid
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

#
# DATABASE MODEL
#


class VaultModel(BaseModel):
    """
    Container for a single vault record.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")

    # Encryption fields
    salt: bytes = Field(..., min_length=16, max_length=64)
    encrypted_blob: bytes = Field(...)
    nonce: bytes = Field(..., min_length=16, max_length=64)
    auth_tag: bytes = Field(..., min_length=16, max_length=64)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )


#
# REQUEST MODELS
#


class VaultCreateRequest(BaseModel):
    """
    Request model for creating a new vault.
    """

    id: uuid.UUID = Field(default=..., alias="_id")
    salt: bytes = Field(..., min_length=16, max_length=64)
    encrypted_blob: bytes = Field(...)
    nonce: bytes = Field(..., min_length=16, max_length=64)
    auth_tag: bytes = Field(..., min_length=16, max_length=64)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "3f68b9b1-9b38-4f1d-a8e3-8d6a6fbc72d9",
                "salt": "cmFuZG9tc2FsdA==",
                "encrypted_blob": "ZW5jcnlwdGVkZGF0YQ==",
                "nonce": "cmFuZG9tbm9uY2U=",
                "auth_tag": "YXV0aHRhZwYXV0aHRhZw==",
            }
        }
    )


class VaultUpdateRequest(BaseModel):
    """
    Request model for updating a vault.
    """

    salt: bytes | None = Field(None, min_length=16, max_length=64)
    encrypted_blob: bytes | None = None
    nonce: bytes | None = Field(None, min_length=16, max_length=64)
    auth_tag: bytes | None = Field(None, min_length=16, max_length=64)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "encrypted_blob": "bmV3ZW5jcnlwdGVkZGF0YQ==",
            }
        }
    )


#
# RESPONSE MODELS
#


class VaultResponse(BaseModel):
    """
    Response model for vault data.
    """

    id: uuid.UUID = Field(..., alias="_id")
    salt: bytes
    encrypted_blob: bytes
    nonce: bytes
    auth_tag: bytes

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "salt": "cmFuZG9tc2FsdA==",
                "encrypted_blob": "ZW5jcnlwdGVkZGF0YQ==",
                "nonce": "cmFuZG9tbm9uY2U=",
                "auth_tag": "YXV0aHRhZwYXV0aHRhZw==",
            }
        },
    )
