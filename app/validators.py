from uuid import UUID

from app.database import user_collection
from app.exceptions import (
    EmailAlreadyInUseException,
    UserAlreadyExistsException,
)


async def validate_email_available(email: str) -> None:
    """
    Validate that an email is not already registered.

    Raises:
        UserAlreadyExistsException: If email is already in use.
    """
    existing = await user_collection.find_one({"email": email})
    if existing:
        raise UserAlreadyExistsException()


async def validate_email_available_for_user(email: str, user_id: UUID) -> None:
    """
    Validate that an email is available for a specific user to use.

    Allows the user to keep their own email, but prevents using
    another user's email.

    Raises:
        EmailAlreadyInUseException: If email is in use by another user.
    """
    existing = await user_collection.find_one({"email": email, "_id": {"$ne": user_id}})
    if existing:
        raise EmailAlreadyInUseException()
