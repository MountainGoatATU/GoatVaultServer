import logging
from typing import Annotated
from uuid import UUID

from fastapi import Body, Depends, Request
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.results import DeleteResult, UpdateResult

from app.database import get_user_collection
from app.exceptions import ForbiddenException, NoFieldsToUpdateException, UserUpdateFailedException
from app.models import TokenPayload, User, UserResponse, UserUpdateRequest
from app.utils import (
    validate_email_available_for_user,
    verify_access_token,
    verify_user_access,
)
from app.utils.time import get_now

logger = logging.getLogger(__name__)

########################################################################
# Get User by ID
########################################################################


async def get_user_by_id(
    user_id: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> UserResponse:
    """Get a user by ID and verify access."""
    logger.info(f"Fetching user: {user_id}")

    verify_user_access(token_payload, user_id)

    user: User | None = await user_collection.find_one({"_id": user_id})

    logger.info(f"User data: {user}")

    if user is None:
        logging.info(f"User not found with ID: {user_id}")
        raise ForbiddenException

    return UserResponse(**user)


########################################################################
# Update User by ID
########################################################################


async def update_user_by_id(
    user_id: UUID,
    request: Request,
    user_data: Annotated[UserUpdateRequest, Body()],
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> UserResponse:
    """Update a user's information by ID."""
    logger.info(f"Update requested for user with ID: {user_id}")
    verify_user_access(token_payload, user_id)

    update_data: dict | None = user_data.model_dump(
        exclude_unset=True, by_alias=True, mode="python"
    )
    if not update_data:
        logger.info(f"No fields to update for user with ID: {user_id}")
        raise NoFieldsToUpdateException

    if "email" in update_data:
        await validate_email_available_for_user(update_data["email"], user_id, request)

    update_data["updatedAtUtc"] = get_now()

    result: UpdateResult = await user_collection.update_one({"_id": user_id}, {"$set": update_data})

    if result.matched_count == 0:
        logger.info(f"User not found with ID: {user_id}")
        raise ForbiddenException

    updated_user_obj: User | None = await user_collection.find_one({"_id": user_id})
    if updated_user_obj is None:
        logger.info(f"Update failed for user with ID: {user_id}")
        raise UserUpdateFailedException

    logger.info(f"User updated with ID: {user_id}")
    return UserResponse(**updated_user_obj)


########################################################################
# Delete User by ID
########################################################################


async def delete_user_by_id(
    user_id: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> None:
    """Delete a user by ID."""
    logger.info(f"Requested deletion for user with ID: {user_id}")
    verify_user_access(token_payload, user_id)

    result: DeleteResult = await user_collection.delete_one({"_id": user_id})

    if result.deleted_count == 0:
        logger.info(f"User not found with ID: {user_id}")
        raise ForbiddenException

    logger.info(f"User deleted with ID: {user_id}")
    return None
