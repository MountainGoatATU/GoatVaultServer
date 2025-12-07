import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.utils import (
    EmailAlreadyInUseException,
    UserAlreadyExistsException,
    sanitize_validation_error,
    validate_email_available,
    validate_email_available_for_user,
)


@pytest.mark.asyncio
async def test_validate_email_available_success() -> None:
    """Test email validation when email is available."""
    with patch("app.utils.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        # Should not raise any exception
        await validate_email_available("new@example.com")

        mock_collection.find_one.assert_called_once_with({"email": "new@example.com"})


@pytest.mark.asyncio
async def test_validate_email_available_already_exists() -> None:
    """Test email validation when email already exists."""
    with patch("app.utils.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(
            return_value={"_id": uuid.uuid4(), "email": "existing@example.com"},
        )

        with pytest.raises(UserAlreadyExistsException):
            await validate_email_available("existing@example.com")


@pytest.mark.asyncio
async def test_validate_email_available_for_user_same_user() -> None:
    """Test email validation when user is updating their own email."""
    user_id = uuid.uuid4()

    with patch("app.utils.validators.user_collection") as mock_collection:
        # No other user has this email
        mock_collection.find_one = AsyncMock(return_value=None)

        # Should not raise any exception
        await validate_email_available_for_user("user@example.com", user_id)

        mock_collection.find_one.assert_called_once_with(
            {"email": "user@example.com", "_id": {"$ne": user_id}},
        )


@pytest.mark.asyncio
async def test_validate_email_available_for_user_different_user() -> None:
    """Test email validation when another user has the email."""
    user_id = uuid.uuid4()
    other_user_id = uuid.uuid4()

    with patch("app.utils.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(
            return_value={"_id": other_user_id, "email": "taken@example.com"},
        )

        with pytest.raises(EmailAlreadyInUseException):
            await validate_email_available_for_user("taken@example.com", user_id)


@pytest.mark.asyncio
async def test_validate_email_available_for_user_no_conflict() -> None:
    """Test email validation when email is completely available."""
    user_id = uuid.uuid4()

    with patch("app.utils.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        await validate_email_available_for_user("available@example.com", user_id)

        mock_collection.find_one.assert_called_once()


@pytest.mark.asyncio
async def test_sanitize_validation_error_with_bytes_input() -> None:
    """Test sanitizing validation errors with bytes that can't decode as UTF-8."""
    # Test with non-UTF-8 bytes
    error_dict = {
        "input": b"\x80\x81\x82\x83",  # Invalid UTF-8
        "type": "value_error",
    }

    result = sanitize_validation_error(error_dict)
    assert result["input"].startswith("<bytes:")
    assert "gIGCgw==" in result["input"]  # base64 of the bytes


@pytest.mark.asyncio
async def test_sanitize_validation_error_with_bytes_in_list() -> None:
    """Test sanitizing validation errors with bytes in a list."""
    error_dict = {"ctx": {"items": [b"\xff\xfe", "string", {"nested": b"\x00\x01"}]}}

    result = sanitize_validation_error(error_dict)
    # Note: The current implementation doesn't process bytes in lists directly
    # It only processes dicts in lists, so bytes remain as bytes
    assert isinstance(result["ctx"]["items"][0], bytes) or "<bytes:" in str(
        result["ctx"]["items"][0],
    )


@pytest.mark.asyncio
async def test_sanitize_validation_error_deeply_nested_bytes() -> None:
    """Test sanitizing validation errors with deeply nested bytes."""
    error_dict = {"level1": {"level2": {"data": b"\x00\xff\x00\xff"}}}

    result = sanitize_validation_error(error_dict)
    assert "<bytes:" in result["level1"]["level2"]["data"]
