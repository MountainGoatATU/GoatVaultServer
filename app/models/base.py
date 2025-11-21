import base64
from typing import Any

from pydantic import BaseModel, field_serializer, field_validator


class Base64BytesModel(BaseModel):
    """Base model that automatically handles base64 encoding/decoding for bytes fields.

    - On input: Decodes base64 strings to bytes
    - On output: Encodes bytes to base64 strings
    """

    @field_validator("*", mode="before")
    @classmethod
    def decode_base64_bytes(cls, v: Any, info) -> Any:
        """Decode base64 string to bytes for any bytes field.

        This validator runs before Pydantic's type validation, so it converts
        base64-encoded strings to bytes before the field type check.
        """
        if info.field_name in cls.model_fields:
            field_info = cls.model_fields[info.field_name]
            annotation: str = str(field_info.annotation)
            if "bytes" in annotation and isinstance(v, str):
                try:
                    return base64.b64decode(v)
                except Exception:
                    pass
        return v

    @field_serializer("*", when_used="json")
    def serialize_bytes_fields(self, value: Any, _info) -> Any:
        """Serialize bytes fields to base64 strings for JSON output."""
        if isinstance(value, bytes):
            return base64.b64encode(value).decode("utf-8")
        return value
