from datetime import UTC, datetime
from typing import Annotated, ClassVar, TypeAlias

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

PyObjectId: TypeAlias = Annotated[str, BeforeValidator(str)]


class VaultModel(BaseModel):
    """
    Container for a single vault record.
    """

    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    user_id: PyObjectId = Field(...)
    name: str = Field(..., min_length=1, max_length=50)

    # Encryption fields
    salt: str = Field(..., min_length=16, max_length=64)
    encrypted_blob: str = Field(...)
    nonce: str = Field(..., min_length=16, max_length=32)
    auth_tag: str = Field(..., min_length=16, max_length=32)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "_id": "64b8f0f0f0f0f0f0f0f0f0f0",
                "user_id": "64b8f0f0f0f0f0f0f0f0f0f0",
                "name": "My Vault",
                "salt": "saltsaltsaltsalt",
                "encrypted_blob": "encrypted_blob",
                "nonce": "noncenoncenoncenonce",
                "auth_tag": "auth_tag_auth_tag",
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
