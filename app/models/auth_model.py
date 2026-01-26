import uuid
from typing import ClassVar
from uuid import UUID

from pydantic import ConfigDict, EmailStr, Field

from app.models.base import Base64BytesModel


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
    mfa_enabled: bool = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "auth_salt": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "mfa_enabled": False,
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
    mfa_code: str | None = Field(
        None,
        description="6-digit multi-factor authentication code (required if MFA enabled)",
        min_length=6,
        max_length=6,
        pattern="^[0-9]{6}$",
    )

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "auth_verifier": "aGFzaGVkcGFzc3dvcmRieXRlczEyMzQ1Njc4OTA=",
                "mfa_code": "123456",
            },
        },
    )


class AuthResponse(Base64BytesModel):
    """Response model for the generated JWT token."""

    access_token: str = Field(..., description="Generated JWT token")
    refresh_token: str | None = Field(None, description="Refresh token (if issued)")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY",
                "token_type": "bearer",
            },
        },
    )


class AuthRefreshResponse(Base64BytesModel):
    """Response model for refresh endpoint"""

    access_token: str = Field(..., description="New access JWT token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
    refresh_token: str = Field(..., description="New refresh token (raw string)")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiI...",
                "token_type": "bearer",
                "refresh_token": "qwerty_refresh_token_example",
            },
        },
    )


class AuthLogoutResponse(Base64BytesModel):
    """Response model for logout/revoke endpoint."""

    status: str = Field(default="ok", description="Operation status")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={"example": {"status": "ok"}},
    )
