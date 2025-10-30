from datetime import UTC, datetime
from typing import ClassVar
import uuid

from pydantic import BaseModel, ConfigDict, Field


#
# DATABASE MODEL
#


class VaultModel(BaseModel):
    """
    Container for a single vault record.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")
    user_id: uuid.UUID = Field(...)
    name: str = Field(..., min_length=1, max_length=50)

    # Encryption fields
    salt: bytes = Field(..., min_length=16, max_length=64)
    encrypted_blob: bytes = Field(...)
    nonce: bytes = Field(..., min_length=16, max_length=64)
    auth_tag: bytes = Field(..., min_length=16, max_length=64)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

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

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")
    name: str = Field(..., min_length=1, max_length=50)
    salt: bytes = Field(..., min_length=16, max_length=64)
    encrypted_blob: bytes = Field(...)
    nonce: bytes = Field(..., min_length=16, max_length=64)
    auth_tag: bytes = Field(..., min_length=16, max_length=64)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "3f68b9b1-9b38-4f1d-a8e3-8d6a6fbc72d9",
                "name": "My Passwords",
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

    name: str | None = Field(None, min_length=1, max_length=50)
    salt: bytes | None = Field(None, min_length=16, max_length=64)
    encrypted_blob: bytes | None = None
    nonce: bytes | None = Field(None, min_length=16, max_length=64)
    auth_tag: bytes | None = Field(None, min_length=16, max_length=64)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Updated Vault Name",
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
    user_id: uuid.UUID
    name: str
    salt: bytes
    encrypted_blob: bytes
    nonce: bytes
    auth_tag: bytes
    created_at: datetime
    updated_at: datetime

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "user_id": "a1b1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "name": "My Passwords",
                "salt": "cmFuZG9tc2FsdA==",
                "encrypted_blob": "ZW5jcnlwdGVkZGF0YQ==",
                "nonce": "cmFuZG9tbm9uY2U=",
                "auth_tag": "YXV0aHRhZwYXV0aHRhZw==",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
            }
        },
    )


class VaultCollection(BaseModel):
    """
    A container holding a list of `VaultModel` instances
    """

    vaults: list[VaultModel]
