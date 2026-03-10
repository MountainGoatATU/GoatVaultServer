import uuid
from datetime import datetime
from typing import ClassVar
from uuid import UUID

from pydantic import ConfigDict, EmailStr, Field

from app.models import Argon2Parameters
from app.models.base_model import Base64BytesModel
from app.models.config import BASE_CONFIG
from app.models.vault_model import Vault


class AuthRegisterRequest(Base64BytesModel):
    """Request model for creating a new user."""

    email: EmailStr = Field(..., max_length=254)
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    auth_verifier: bytes = Field(..., min_length=16, max_length=128)

    mfa_enabled: bool = Field(default=False)
    mfa_secret: str | None = Field(None, min_length=16, max_length=128)
    shamir_enabled: bool = Field(default=False)

    vault_salt: bytes | None = Field(None, min_length=16, max_length=64)
    vault: Vault = Field(...)

    argon2_parameters: Argon2Parameters = Field(...)

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
                "argon2Parameters": {
                    "timeCost": 3,
                    "memoryCost": 65536,
                    "lanes": 4,
                    "threads": 4,
                    "hashLength": 32,
                },
            },
        },
    )


class AuthRegisterResponse(Base64BytesModel):
    """Response model for registration."""

    id: uuid.UUID = Field(..., alias="_id")
    email: EmailStr
    created_at_utc: datetime

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "email": "user@example.com",
                "createdAtUtc": "2024-01-15T10:30:00Z",
            }
        },
    )


class AuthInitRequest(Base64BytesModel):
    """Request model for initializing authentication."""

    email: EmailStr = Field(..., description="Email address of the user")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={"example": {"email": "user@example.com"}},
    )


class AuthInitResponse(Base64BytesModel):
    """Response model for initializing authentication."""

    id: uuid.UUID = Field(..., alias="_id")
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    nonce: bytes = Field(..., min_length=32, max_length=32)
    mfa_enabled: bool = Field(...)
    shamir_enabled: bool = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "authSalt": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "nonce": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "mfaEnabled": False,
                "shamirEnabled": False,
            },
        },
    )


class AuthVerifyRequest(Base64BytesModel):
    """Request model for generating JWT token."""

    id: UUID = Field(..., description="UUID of the user requesting a token", alias="_id")
    proof: bytes = Field(
        ...,
        min_length=32,
        max_length=32,
        description="HMAC-SHA256 proof of auth_verifier + nonce",
    )
    mfa_code: str | None = Field(
        None,
        description="6-digit multi-factor authentication code (required if MFA enabled)",
        min_length=6,
        max_length=6,
        pattern="^[0-9]{6}$",
    )

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "proof": "aGFzaGVkcGFzc3dvcmRieXRlczEyMzQ1Njc4OTA=",
                "mfaCode": "123456",
            },
        },
    )


class AuthVerifyResponse(Base64BytesModel):
    """Response model for the generated JWT token."""

    access_token: str = Field(..., description="Generated JWT token")
    refresh_token: str | None = Field(None, description="Refresh token (if issued)")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY",
                "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY",
                "tokenType": "bearer",
            },
        },
    )


class AuthRefreshRequest(Base64BytesModel):
    """Request model for refresh endpoint."""

    refresh_token: str = Field(..., description="Raw refresh token presented by client")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY"
            },
        },
    )


class AuthRefreshResponse(Base64BytesModel):
    """Response model for refresh endpoint"""

    access_token: str = Field(..., description="New access JWT token")
    refresh_token: str = Field(..., description="New refresh token (raw string)")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY",
                "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZjdkMzQxZS04NWJlLTRlNTQtYThjNi1lNWZkNjg1YzQ3NDIiLCJpc3MiOiJHb2F0VmF1bHRTZXJ2ZXIiLCJleHAiOjE3NjM1NzE2NzksImlhdCI6MTc2MzU2ODA3OX0.L1tjbF4DyeAKMcmOEX45U0uqIaCX6L8Ku7gdrEQmZlY",
                "tokenType": "bearer",
            },
        },
    )


class AuthLogoutResponse(Base64BytesModel):
    """Response model for logout/revoke endpoint."""

    status: str = Field(default="ok", description="Operation status")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={"example": {"status": "ok"}},
    )
