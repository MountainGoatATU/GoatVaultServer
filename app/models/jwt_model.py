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
