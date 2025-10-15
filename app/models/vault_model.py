from datetime import UTC, datetime
from typing import ClassVar
import uuid

from pydantic import BaseModel, ConfigDict, Field


class VaultModel(BaseModel):
    """
    Container for a single vault record.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, alias="_id")
    user_id: uuid.UUID = Field(...)
    name: str = Field(..., min_length=1, max_length=50)

    # Encryption fields
    salt: bytes = Field(..., min_length=16, max_length=64)
    encrypted_blob: bytes = Field(...)
    nonce: bytes = Field(..., min_length=16, max_length=64)
    auth_tag: bytes = Field(..., min_length=16, max_length=64)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "user_id": "b1c1f27a-cc59-4d2b-ae74-7b3b0e33a61a",
                "name": "My Vault",
                "salt": "736f6d652d73616c742d62797465732d68657265",
                "encrypted_blob": "656e637279707465642d646174612d68657265",
                "nonce": "6e6f6e63652d62797465732d68657265",
                "auth_tag": "617574682d7461672d62797465732d68657265",
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
            }
        },
    )


class VaultCollection(BaseModel):
    """
    A container holding a list of `VaultModel` instances
    """

    vaults: list[VaultModel]
