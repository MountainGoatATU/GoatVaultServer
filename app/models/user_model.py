import uuid
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import ConfigDict, EmailStr, Field

from app.models.base import Base64BytesModel
from app.models.vault_model import VaultModel


class UserModel(Base64BytesModel):
    """Container for a single user record."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")
    email: EmailStr = Field(..., max_length=254)
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    auth_verifier: bytes = Field(..., min_length=16, max_length=128)

    mfa_enabled: bool = Field(default=False)
    mfa_secret: str | None = Field(default=None)

    vault: VaultModel = Field(...)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )


class UserCreateRequest(Base64BytesModel):
    """Request model for creating a new user."""

    email: EmailStr = Field(..., max_length=254)
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    auth_verifier: bytes = Field(..., min_length=16, max_length=128)
    vault: VaultModel = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "auth_salt": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "auth_verifier": "aGFzaGVkcGFzc3dvcmRieXRlczEyMzQ1Njc4OTA=",
                "email": "user@example.com",
                "vault": {
                    "auth_tag": "YXV0aHRhZzEyMzQ1Njc4OTBhYmNkZWY=",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YTEyMzQ1Njc4OTA=",
                    "nonce": "cmFuZG9tbm9uY2UxMjM0NTY3ODkw",
                    "vault_salt": "cmFuZG9tc2FsdDEyMzQ1Njc4OTBhYg==",
                },
            },
        },
    )


class UserUpdateRequest(Base64BytesModel):
    """Request model for updating a user.
    All fields are optional - only provided fields will be updated.
    """

    email: EmailStr | None = Field(None, max_length=254)
    auth_salt: bytes | None = Field(None, min_length=16, max_length=64)
    auth_verifier: bytes | None = Field(None, min_length=16, max_length=128)
    mfa_enabled: bool | None = None
    mfa_secret: str | None = None
    vault: VaultModel | None = None

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "newemail@example.com",
                "mfa_enabled": True,
                "vault": {
                    "auth_tag": "YXV0aHRhZzEyMzQ1Njc4OTBhYmNkZWY=",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YTEyMzQ1Njc4OTA=",
                    "nonce": "cmFuZG9tbm9uY2UxMjM0NTY3ODkw",
                    "vault_salt": "cmFuZG9tc2FsdDEyMzQ1Njc4OTBhYg==",
                },
            },
        },
    )


class UserResponse(Base64BytesModel):
    """Response model for user data."""

    id: uuid.UUID = Field(..., alias="_id")
    email: EmailStr
    auth_salt: bytes
    mfa_enabled: bool
    vault: VaultModel

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "auth_salt": "cmFuZG9tc2FsdGJ5dGVz",
                "email": "user@example.com",
                "mfa_enabled": False,
                "vault": {
                    "auth_tag": "YXV0aHRhZzEyMzQ1Njc4OTBhYmNkZWY=",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YTEyMzQ1Njc4OTA=",
                    "nonce": "cmFuZG9tbm9uY2UxMjM0NTY3ODkw",
                    "vault_salt": "cmFuZG9tc2FsdDEyMzQ1Njc4OTBhYg==",
                },
            },
        },
    )
