from typing import ClassVar

from pydantic import ConfigDict, Field

from app.models.base_model import Base64BytesModel
from app.models.config import BASE_CONFIG


class Vault(Base64BytesModel):
    """Object representing a user's vault."""

    encrypted_blob: bytes = Field(...)
    nonce: bytes = Field(..., min_length=12, max_length=64)
    auth_tag: bytes = Field(..., min_length=16, max_length=64)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
    )
