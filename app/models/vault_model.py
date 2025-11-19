from typing import ClassVar

from pydantic import ConfigDict, Field

from app.models.base import Base64BytesModel


class VaultModel(Base64BytesModel):
    """
    Object representing a user's vault.
    """

    vault_salt: bytes = Field(..., min_length=16, max_length=64)
    encrypted_blob: bytes = Field(...)
    nonce: bytes = Field(..., min_length=16, max_length=64)
    auth_tag: bytes = Field(..., min_length=16, max_length=64)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )
