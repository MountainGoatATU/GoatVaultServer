import uuid
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.models.vault_model import VaultModel


class AuthInitRequest(BaseModel):
    """Request model for initializing authentication."""

    email: EmailStr = Field(..., description="Email address of the user")


class AuthInitResponse(BaseModel):
    """Response model for initializing authentication."""

    user_id: uuid.UUID = Field(...)
    auth_salt: bytes = Field(..., min_length=16, max_length=64)
    vault: VaultModel = Field(...)
    mfa_enabled: bool = Field(default=False)


class AuthRequest(BaseModel):
    """Request model for generating JWT token."""

    user_id: UUID = Field(..., description="UUID of the user requesting a token")
    auth_verifier: bytes = Field(
        ..., min_length=16, max_length=128, description="Verifier for authentication"
    )
    mfa_secret: str | None = Field(
        ..., min_length=6, max_length=6, description="Multi-factor authentication code"
    )


class AuthResponse(BaseModel):
    """Response model for the generated JWT token."""

    access_token: str = Field(..., description="Generated JWT token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
