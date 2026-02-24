import uuid
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import ConfigDict, EmailStr, Field

from app.models.base import BASE_CONFIG, Base64BytesModel
from app.models.vault_model import VaultModel


class UserModel(Base64BytesModel):
    """Container for a single user record."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")
    email: EmailStr = Field(..., max_length=254)
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    auth_verifier: bytes = Field(..., min_length=16, max_length=128)

    mfa_enabled: bool = Field(default=False)
    mfa_secret: str | None = Field(default=None)

    shamir_enabled: bool = Field(default=False)
    email_verified: bool = Field(default=False)

    vault_salt: bytes | None = Field(None, min_length=16, max_length=64)
    vault: VaultModel = Field(...)

    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
    )


class UserCreateRequest(Base64BytesModel):
    """Request model for creating a new user."""

    email: EmailStr = Field(..., max_length=254)
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    auth_verifier: bytes = Field(..., min_length=16, max_length=128)

    vault_salt: bytes | None = Field(None, min_length=16, max_length=64)
    vault: VaultModel = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "authSalt": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "authVerifier": "aGFzaGVkcGFzc3dvcmRieXRlczEyMzQ1Njc4OTA=",
                "email": "user@example.com",
                "vaultSalt": "cmFuZG9tc2FsdDEyMzQ1Njc4OTBhYg==",
                "vault": {
                    "authTag": "YXV0aHRhZzEyMzQ1Njc4OTBhYmNkZWY=",
                    "encryptedBlob": "ZW5jcnlwdGVkZGF0YTEyMzQ1Njc4OTA=",
                    "nonce": "cmFuZG9tbm9uY2UxMjM0NTY3ODkw",
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

    shamir_enabled: bool | None = None

    vault_salt: bytes | None = Field(None, min_length=16, max_length=64)
    vault: VaultModel | None = None

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "email": "newemail@example.com",
                "authSalt": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "authVerifier": "aGFzaGVkcGFzc3dvcmRieXRlczEyMzQ1Njc4OTA=",
                "mfaEnabled": True,
                "mfaSecret": "cmFuZG9tc2FsdGJ5dGVz",
                "shamirEnabled": True,
                "vaultSalt": "cmFuZG9tc2FsdDEyMzQ1Njc4OTBhYg==",
                "vault": {
                    "authTag": "YXV0aHRhZzEyMzQ1Njc4OTBhYmNkZWY=",
                    "encryptedBlob": "ZW5jcnlwdGVkZGF0YTEyMzQ1Njc4OTA=",
                    "nonce": "cmFuZG9tbm9uY2UxMjM0NTY3ODkw",
                },
            },
        },
    )


class UserResponse(Base64BytesModel):
    """Response model for user data."""

    id: uuid.UUID = Field(..., alias="_id")
    email: EmailStr
    auth_salt: bytes
    auth_verifier: bytes

    mfa_enabled: bool
    mfa_secret: str | None

    shamir_enabled: bool
    email_verified: bool

    vault_salt: bytes
    vault: VaultModel

    created_at_utc: datetime
    updated_at_utc: datetime

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "authSalt": "cmFuZG9tc2FsdGJ5dGVz",
                "authVerifier": "aGFzaGVkcGFzc3dvcmRieXRlczEyMzQ1Njc4OTA=",
                "email": "user@example.com",
                "mfaEnabled": False,
                "mfaSecret": "cmFuZG9tc2FsdGJ5dGVz",
                "shamirEnabled": False,
                "emailVerified": True,
                "vaultSalt": "cmFuZG9tc2FsdDEyMzQ1Njc4OTBhYg==",
                "vault": {
                    "authTag": "YXV0aHRhZzEyMzQ1Njc4OTBhYmNkZWY=",
                    "encryptedBlob": "ZW5jcnlwdGVkZGF0YTEyMzQ1Njc4OTA=",
                    "nonce": "cmFuZG9tbm9uY2UxMjM0NTY3ODkw",
                },
                "createdAtUtc": "2024-01-15T10:30:00Z",
                "updatedAtUtc": "2024-01-15T14:45:00Z",
            },
        },
    )
