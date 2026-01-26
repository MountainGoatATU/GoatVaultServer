from datetime import datetime
from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TokenPayload(BaseModel):
    """Model representing the decoded JWT payload."""

    sub: UUID = Field(..., description="Subject - the user UUID")
    iss: str = Field(..., description="Issuer")
    exp: datetime = Field(..., description="Expiration time (UTC)")
    iat: datetime = Field(..., description="Issued at (UTC)")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "example": {
                "sub": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "iss": "GoatVaultServer",
                "exp": "2030-01-01T00:00:00Z",
                "iat": "2029-12-31T12:00:00Z",
            }
        }
    )

    def __contains__(self, key: str) -> bool:
        return key in self.model_dump()


class RefreshTokenModel(BaseModel):
    """Representation of a stored refresh token (DB record)."""

    id: UUID = Field(..., alias="_id", description="DB id for the refresh token")
    user_id: UUID = Field(..., description="User this refresh token belongs to")
    token_hash: str = Field(..., description="SHA256 (or other) hash of the raw token")
    created_at: datetime = Field(..., description="When this refresh token was created")
    expires_at: datetime = Field(..., description="When this refresh token expires")
    revoked: bool = Field(False, description="Whether the refresh token has been revoked")

    model_config: ClassVar[ConfigDict] = ConfigDict(populate_by_name=True)
