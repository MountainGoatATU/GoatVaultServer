from datetime import UTC, datetime
from typing import ClassVar
import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserModel(BaseModel):
    """
    Container for a single user record.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")
    email: EmailStr = Field(..., max_length=254)

    # Encryption fields
    salt: str = Field(..., min_length=16, max_length=64)
    password_hash: str = Field(..., min_length=16, max_length=128)

    # Multi-factor authentication
    mfa_enabled: bool = Field(default=False)
    mfa_secret: str | None = Field(default=None)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "email": "user@example.com",
                "salt": "saltsaltsaltsalt",
                "password_hash": "hashhashhashhash",
                "mfa_enabled": False,
                "mfa_secret": None,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
            }
        },
    )


class UserCollection(BaseModel):
    """
    A container holding a list of `UserModel` instances
    """

    users: list[UserModel]
