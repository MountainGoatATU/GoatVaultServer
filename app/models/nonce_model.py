import uuid
from datetime import datetime
from typing import ClassVar
from uuid import UUID

from pydantic import ConfigDict, Field

from app.models.base_model import Base64BytesModel
from app.models.config import BASE_CONFIG


class NonceModel(Base64BytesModel):
    """Model for nonce."""

    id: UUID = Field(default_factory=uuid.uuid4, alias="_id")
    user_id: UUID
    nonce: bytes = Field(..., min_length=32, max_length=32)
    created_at_utc: datetime = Field(..., description="Creation time (UTC)")
    expires_at_utc: datetime = Field(..., description="Expiration time (UTC)")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "_id": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "userId": "af7d341e-85be-4e54-a8c6-e5fd685c4742",
                "nonce": "cmFuZG9tc2FsdGJ5dGVzMTIzNDU2",
                "createdAtUtc": "2024-01-15T10:30:00Z",
                "expiresAtUtc": "2024-01-15T11:30:00Z",
            }
        },
    )
