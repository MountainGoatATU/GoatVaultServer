import pytest
from pydantic import Field, ValidationError

from app.models.base_model import Base64BytesModel

########################################################################
# Test Model
########################################################################


class Base64TestModel(Base64BytesModel):
    """Test model for base64 decoding."""

    data: bytes = Field(...)


########################################################################
# Base64 Bytes Model Tests
########################################################################


def test_base64_decode_invalid_base64() -> None:
    """Test that invalid base64 strings raise ValidationError."""
    with pytest.raises(ValidationError):
        Base64TestModel(data="not-valid-base64!!!")  # type: ignore[arg-type]


def test_base64_decode_valid_base64() -> None:
    """Test that valid base64 strings are decoded correctly."""
    valid_model = Base64TestModel(data="aGVsbG8=")  # type: ignore[arg-type]
    assert valid_model.data == b"hello"
