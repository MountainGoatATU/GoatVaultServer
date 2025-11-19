import base64
from typing import Any

from pydantic import BaseModel, field_validator, model_serializer


class Base64BytesModel(BaseModel):
    """
    Base model that automatically handles base64 encoding/decoding for bytes fields.

    - On input: Decodes base64 strings to bytes
    - On output: Encodes bytes to base64 strings
    """

    @field_validator("*", mode="before")
    @classmethod
    def decode_base64_bytes(cls, v: Any, info) -> Any:
        """
        Decode base64 string to bytes for any bytes field.

        This validator runs before Pydantic's type validation, so it converts
        base64-encoded strings to bytes before the field type check.
        """
        # Only process if the field type is bytes and the value is a string
        if info.field_name in cls.model_fields:
            field_info = cls.model_fields[info.field_name]
            # Check if the annotation is bytes or Optional[bytes]
            annotation = str(field_info.annotation)
            if "bytes" in annotation and isinstance(v, str):
                try:
                    return base64.b64decode(v)
                except Exception:
                    # If decoding fails, let Pydantic handle the error
                    pass
        return v

    @model_serializer(mode="wrap")
    def serialize_with_base64(self, serializer: Any) -> dict[str, Any]:
        """
        Serialize the model, encoding all bytes fields as base64 strings.

        This makes the API responses JSON-compatible since raw bytes
        cannot be directly serialized to JSON.
        """
        data = serializer(self)

        # Encode all bytes fields to base64
        for field_name, field_value in data.items():
            if isinstance(field_value, bytes):
                data[field_name] = base64.b64encode(field_value).decode("utf-8")

        return data
