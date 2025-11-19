import uuid
from typing import ClassVar
from uuid import UUID

from pydantic import ConfigDict, EmailStr, Field

from app.models.base import Base64BytesModel
from app.models.vault_model import VaultModel


class AuthInitRequest(Base64BytesModel):
    """Request model for initializing authentication."""

    email: EmailStr = Field(..., description="Email address of the user")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={"example": {"email": "user@example.com"}},
    )


class AuthInitResponse(Base64BytesModel):
    """Response model for initializing authentication."""

    user_id: uuid.UUID = Field(...)
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    vault: VaultModel = Field(...)
    mfa_enabled: bool = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "auth_salt": "cmFuZG9tc2FsdGJ5dGVz",
                "vault": {
                    "vault_salt": "cmFuZG9tc2FsdA==",
                    "encrypted_blob": "ZW5jcnlwdGVkZGF0YQ==",
                    "nonce": "cmFuZG9tbm9uY2U=",
                    "auth_tag": "YXV0aHRhZwYXV0aHRhZw==",
                },
                "mfa_enabled": "false",
            },
        },
    )


class AuthRequest(Base64BytesModel):
    """Request model for generating JWT token."""

    user_id: UUID = Field(..., description="UUID of the user requesting a token")
    auth_verifier: bytes = Field(
        ..., min_length=16, max_length=128, description="Verifier for authentication",
    )
    mfa_secret: str | None = Field(
        None, min_length=6, max_length=6, description="Multi-factor authentication code",
    )

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "auth_verifier": "aGFzaGVkcGFzc3dvcmRieXRlcw==",
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
