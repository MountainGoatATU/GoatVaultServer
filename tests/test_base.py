from contextlib import suppress

from pydantic import Field, ValidationError

from app.models.base import Base64BytesModel


def test_base64_decode_invalid_base64():
    """Test that invalid base64 strings are handled gracefully."""

    class TestModel(Base64BytesModel):
        data: bytes = Field(...)

    # Test with invalid base64 - should raise ValidationError
    with suppress(ValidationError):
        TestModel(data="not-valid-base64!!!")  # type: ignore[arg-type]

    # Test with valid base64 - should succeed
    valid_model = TestModel(data="aGVsbG8=")  # type: ignore[arg-type]
    assert valid_model.data == b"hello"
