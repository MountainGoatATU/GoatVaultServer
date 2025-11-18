import uuid
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.vault_model import VaultModel

#
# DATABASE MODEL
#


class UserModel(BaseModel):
    """
    Container for a single user record.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")
    email: EmailStr = Field(..., max_length=254)

    # Encryption fields
    salt: bytes = Field(..., min_length=16, max_length=64)
    password_hash: bytes = Field(..., min_length=16, max_length=128)

    # Multi-factor authentication
    mfa_enabled: bool = Field(default=False)
    mfa_secret: str | None = Field(default=None)

    data: VaultModel = Field(...)

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


class UserCreateRequest(BaseModel):
    """
    Request model for creating a new user.
    """

    email: EmailStr = Field(..., max_length=254)
    salt: bytes = Field(..., min_length=16, max_length=64)
    password_hash: bytes = Field(..., min_length=16, max_length=128)
    data: VaultModel = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "salt": "cmFuZG9tc2FsdGJ5dGVz",
                "password_hash": "aGFzaGVkcGFzc3dvcmRieXRlcw==",
                "data": {
                    "_id": "3f68b9b1-9b38-4f1d-a8e3-8d6a6fbc72d9",
                    "salt": "cmFuZG9tc2FsdA==",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YQ==",
                    "nonce": "cmFuZG9tbm9uY2U=",
                    "auth_tag": "YXV0aHRhZwYXV0aHRhZw==",
                },
            }
        }
    )


class UserUpdateRequest(BaseModel):
    """
    Request model for updating a user.
    All fields are optional - only provided fields will be updated.
    """

    email: EmailStr | None = Field(None, max_length=254)
    salt: bytes | None = Field(None, min_length=16, max_length=64)
    password_hash: bytes | None = Field(None, min_length=16, max_length=128)
    data: VaultModel | None = None
    mfa_enabled: bool | None = None
    mfa_secret: str | None = None

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "newemail@example.com",
                "mfa_enabled": True,
                "data": {
                    "_id": "3f68b9b1-9b38-4f1d-a8e3-8d6a6fbc72d9",
                    "salt": "cmFuZG9tc2FsdA==",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YQ==",
                    "nonce": "cmFuZG9tbm9uY2U=",
                    "auth_tag": "YXV0aHRhZwYXV0aHRhZw==",
                },
            }
        }
    )


#
# RESPONSE MODEL
#


class UserResponse(BaseModel):
    """
    Response model for user data.
    """

    id: uuid.UUID = Field(..., alias="_id")
    email: EmailStr
    salt: bytes
    password_hash: bytes
    data: VaultModel
    mfa_enabled: bool
    mfa_secret: str | None

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "email": "user@example.com",
                "salt": "cmFuZG9tc2FsdGJ5dGVz",
                "password_hash": "aGFzaGVkcGFzc3dvcmRieXRlcw==",
                "data": {
                    "_id": "3f68b9b1-9b38-4f1d-a8e3-8d6a6fbc72d9",
                    "salt": "cmFuZG9tc2FsdA==",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YQ==",
                    "nonce": "cmFuZG9tbm9uY2U=",
                    "auth_tag": "YXV0aHRhZwYXV0aHRhZw==",
                },
                "mfa_enabled": False,
                "mfa_secret": None,
            }
        },
    )


class UserCollection(BaseModel):
    """
    A container holding a list of `UserModel` instances
    """

    users: list[UserModel]
