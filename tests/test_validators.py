import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.exceptions import EmailAlreadyInUseException, UserAlreadyExistsException
from app.validators import validate_email_available, validate_email_available_for_user


@pytest.mark.asyncio
async def test_validate_email_available_success():
    """Test email validation when email is available."""
    with patch("app.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)
        
        # Should not raise any exception
        await validate_email_available("new@example.com")
        
        mock_collection.find_one.assert_called_once_with({"email": "new@example.com"})


@pytest.mark.asyncio
async def test_validate_email_available_already_exists():
    """Test email validation when email already exists."""
    with patch("app.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(
            return_value={"_id": uuid.uuid4(), "email": "existing@example.com"}
        )
        
        with pytest.raises(UserAlreadyExistsException):
            await validate_email_available("existing@example.com")


@pytest.mark.asyncio
async def test_validate_email_available_for_user_same_user():
    """Test email validation when user is updating their own email."""
    user_id = uuid.uuid4()
    
    with patch("app.validators.user_collection") as mock_collection:
        # No other user has this email
        mock_collection.find_one = AsyncMock(return_value=None)
        
        # Should not raise any exception
        await validate_email_available_for_user("user@example.com", user_id)
        
        mock_collection.find_one.assert_called_once_with(
            {"email": "user@example.com", "_id": {"$ne": user_id}}
        )


@pytest.mark.asyncio
async def test_validate_email_available_for_user_different_user():
    """Test email validation when another user has the email."""
    user_id = uuid.uuid4()
    other_user_id = uuid.uuid4()
    
    with patch("app.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(
            return_value={"_id": other_user_id, "email": "taken@example.com"}
        )
        
        with pytest.raises(EmailAlreadyInUseException):
            await validate_email_available_for_user("taken@example.com", user_id)


@pytest.mark.asyncio
async def test_validate_email_available_for_user_no_conflict():
    """Test email validation when email is completely available."""
    user_id = uuid.uuid4()
    
    with patch("app.validators.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)
        
        await validate_email_available_for_user("available@example.com", user_id)
        
        mock_collection.find_one.assert_called_once()
