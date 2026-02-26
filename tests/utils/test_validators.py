import uuid
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from app.exceptions import EmailAlreadyInUseException, UserAlreadyExistsException
from app.utils import (
    sanitize_validation_error,
    validate_email_available,
)

########################################################################
# Helper Functions
########################################################################


def configure_mock_find_one(mock_request, return_value=None):
    """Helper to configure the mock database's `find_one` method."""
    mock_request.app.state.db["users"].find_one = AsyncMock(return_value=return_value)


########################################################################
# Email Validation Tests
#######################################################################


@pytest.mark.asyncio
async def test_validate_email_available_success(mock_request) -> None:
    """Test email validation when email is available."""
    configure_mock_find_one(mock_request, return_value=None)

    # Should not raise any exception
    await validate_email_available(mock_request, "new@example.com")

    mock_request.app.state.db["users"].find_one.assert_called_once_with(
        {"email": "new@example.com"}
    )


@pytest.mark.asyncio
async def test_validate_email_available_already_exists(mock_request) -> None:
    """Test email validation when email already exists."""
    configure_mock_find_one(
        mock_request,
        return_value={"_id": uuid.uuid4(), "email": "existing@example.com"},
    )

    with pytest.raises(UserAlreadyExistsException):
        await validate_email_available(mock_request, "existing@example.com")


@pytest.mark.asyncio
async def test_validate_email_available_same_user(mock_request) -> None:
    """Test email validation when user is updating their own email."""
    user_id: UUID = uuid.uuid4()
    configure_mock_find_one(mock_request, return_value=None)

    # Should not raise any exception
    await validate_email_available(mock_request, "user@example.com", user_id)

    mock_request.app.state.db["users"].find_one.assert_called_once_with(
        {"email": "user@example.com", "_id": {"$ne": user_id}},
    )


@pytest.mark.asyncio
async def test_validate_email_available_different_user(mock_request) -> None:
    """Test email validation when another user has the email."""
    user_id: UUID = uuid.uuid4()
    other_user_id: UUID = uuid.uuid4()

    configure_mock_find_one(
        mock_request,
        return_value={"_id": other_user_id, "email": "taken@example.com"},
    )

    with pytest.raises(EmailAlreadyInUseException):
        await validate_email_available(mock_request, "taken@example.com", user_id)


@pytest.mark.asyncio
async def test_validate_email_available_no_conflict(mock_request) -> None:
    """Test email validation when email is completely available."""
    user_id: UUID = uuid.uuid4()
    configure_mock_find_one(mock_request, return_value=None)

    await validate_email_available(mock_request, "available@example.com", user_id)

    mock_request.app.state.db["users"].find_one.assert_called_once()


########################################################################
# Validation Error Sanitization Tests
########################################################################


@pytest.mark.asyncio
async def test_sanitize_validation_error_with_bytes_input() -> None:
    """Test sanitizing validation errors with bytes that can't decode as UTF-8."""
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
    assert isinstance(result["ctx"]["items"][0], bytes) or "<bytes:" in str(
        result["ctx"]["items"][0],
    )


@pytest.mark.asyncio
async def test_sanitize_validation_error_deeply_nested_bytes() -> None:
    """Test sanitizing validation errors with deeply nested bytes."""
    error_dict = {"level1": {"level2": {"data": b"\x00\xff\x00\xff"}}}

    result = sanitize_validation_error(error_dict)
    assert "<bytes:" in result["level1"]["level2"]["data"]
