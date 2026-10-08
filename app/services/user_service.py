import logging
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request

from app.exceptions import ForbiddenException, NoFieldsToUpdateException
from app.models import TokenPayload, UserResponse, UserUpdateRequest
from app.repositories import UserRepository
from app.utils import validate_email_available, verify_access_token, verify_user_access
from app.utils.crypto import encrypt_mfa_secret
from app.utils.time import get_now

_logger = logging.getLogger(__name__)

########################################################################
# Get User by ID
########################################################################


async def get_user_by_id(
    user_id: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_repo: UserRepository,
) -> UserResponse:
    """Get a user by ID and verify access."""
    _logger.info(f"Fetching user: {user_id}")
    verify_user_access(token_payload, user_id)

    user = await user_repo.find_by_id(user_id)
    if user is None:
        _logger.info(f"User not found with ID: {user_id}")
        raise ForbiddenException
    return UserResponse(**user.model_dump())


########################################################################
# Update User by ID
########################################################################


async def update_user_by_id(
    user_id: UUID,
    request: Request,
    user_data: UserUpdateRequest,
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_repo: UserRepository,
) -> UserResponse:
    """Update a user's information by ID."""
    _logger.info(f"Update requested for user with ID: {user_id}")
    verify_user_access(token_payload, user_id)

    changes: dict = user_data.model_dump(exclude_unset=True)
    if not changes:
        _logger.info(f"No fields to update for user with ID: {user_id}")
        raise NoFieldsToUpdateException

    # Check email uniqueness if email is updated
    if "email" in changes:
        await validate_email_available(request, changes["email"], user_id)

    # Encrypt MFA secret if provided
    mfa_secret_plain: str | None = changes.pop("mfa_secret", None)
    if mfa_secret_plain:
        changes["mfa_secret"] = encrypt_mfa_secret(mfa_secret_plain)
        changes["mfa_enabled"] = True

    changes["updated_at_utc"] = get_now()

    updated = await user_repo.update_profile(user_id, changes)
    if updated is None:
        _logger.info(f"User not found with ID: {user_id}")
        raise ForbiddenException

    _logger.info(f"User updated with ID: {user_id}")
    return UserResponse(**updated.model_dump())


########################################################################
# Delete User by ID
########################################################################


async def delete_user_by_id(
    user_id: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_repo: UserRepository,
) -> None:
    """Delete a user by ID."""
    _logger.info(f"Requested deletion for user with ID: {user_id}")
    verify_user_access(token_payload, user_id)

    deleted = await user_repo.delete(user_id)
    if not deleted:
        _logger.info(f"User not found with ID: {user_id}")
        raise ForbiddenException
    _logger.info(f"User deleted with ID: {user_id}")
    return None
