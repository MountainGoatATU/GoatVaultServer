from typing import ClassVar

from pydantic import ConfigDict, Field

from app.models.base_model import BASE_CONFIG, Base64BytesModel


class Argon2Parameters(Base64BytesModel):
    """Object representing a user's Argon2 parameters."""

    time_cost: int = Field(...)
    memory_cost: int = Field(...)
    lanes: int = Field(...)
    threads: int = Field(...)
    hash_length: int = Field(...)

    model_config: ClassVar[ConfigDict] = ConfigDict(
        **BASE_CONFIG,
        json_schema_extra={
            "example": {
                "timeCost": 3,
                "memoryCost": 65536,
                "lanes": 4,
                "threads": 4,
                "hashLength": 32,
            }
        },
    )
