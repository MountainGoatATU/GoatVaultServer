import uuid
from typing import ClassVar
from uuid import UUID

from pydantic import ConfigDict, EmailStr, Field

from app.models.base import Base64BytesModel
from app.models.vault_model import VaultModel


class AuthRegisterResponse(Base64BytesModel):
    """Response model for registration."""

    id: uuid.UUID = Field(..., alias="_id")
    email: EmailStr

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {"_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742", "email": "user@example.com"}
        },
    )


class AuthInitRequest(Base64BytesModel):
    """Request model for initializing authentication."""

    email: EmailStr = Field(..., description="Email address of the user")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={"example": {"email": "user@example.com"}},
    )


class AuthInitResponse(Base64BytesModel):
    """Response model for initializing authentication."""

    id: uuid.UUID = Field(..., alias="_id")
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    vault: VaultModel = Field(...)
    mfa_enabled: bool = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "auth_salt": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "mfa_enabled": "false",
                "vault": {
                    "auth_tag": "YXV0aHRhZzEyMzQ1Njc4OTBhYmNkZWY=",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YTEyMzQ1Njc4OTA=",
                    "nonce": "cmFuZG9tbm9uY2UxMjM0NTY3ODkw",
                    "vault_salt": "cmFuZG9tc2FsdDEyMzQ1Njc4OTBhYg==",
                },
            },
        },
    )


class AuthRequest(Base64BytesModel):
    """Request model for generating JWT token."""

    id: UUID = Field(..., description="UUID of the user requesting a token", alias="_id")
    auth_verifier: bytes = Field(
        ...,
        min_length=16,
        max_length=128,
        description="Verifier for authentication",
    )
    mfa_secret: str | None = Field(
        None,
        min_length=6,
        max_length=6,
        description="Multi-factor authentication code",
    )

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "auth_verifier": "aGFzaGVkcGFzc3dvcmRieXRlczEyMzQ1Njc4OTA=",
            },
        },
    )


class AuthResponse(Base64BytesModel):
    """Response model for the generated JWT token."""

    access_token: str = Field(..., description="Generated JWT token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY",
                "token_type": "bearer",
            },
        },
    )
