import logging
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Request, status
from motor.motor_asyncio import AsyncIOMotorCollection

from app.database import get_user_collection
from app.models import (
    TokenPayload,
    UserModel,
    UserResponse,
    UserUpdateRequest,
)
from app.utils import (
    ForbiddenException,
    NoFieldsToUpdateException,
    UserUpdateFailedException,
    validate_email_available_for_user,
    verify_token,
    verify_user_access,
)

logger = logging.getLogger(__name__)

user_router: APIRouter = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(verify_token)],
)


@user_router.get(
    "/{userId}",
    response_description="Get a single user",
    status_code=status.HTTP_200_OK,
)
async def get_user(
    userId: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> UserResponse:
    """Get the record for a specific user, looked up by `id`."""
    logger.info(f"Getting user: {userId}")
    verify_user_access(token_payload, userId)

    user: UserModel | None = await user_collection.find_one({"_id": userId})

    logging.info(f"User data: {user}")

    if user is None:
        logger.info(f"User not found with ID: {userId}")
        raise ForbiddenException

    logger.info(f"User found with ID: {userId}")
    return UserResponse(**user)


@user_router.patch(
    "/{userId}",
    response_description="Update a user",
    status_code=status.HTTP_200_OK,
)
async def update_user(
    userId: UUID,
    request: Request,
    user_data: Annotated[UserUpdateRequest, Body()],
    token_payload: Annotated[TokenPayload, Depends(verify_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> UserResponse:
    """Update the record for a specific user, looked up by `userId`."""
    logger.info(f"Update requested for user with ID: {userId}")
    verify_user_access(token_payload, userId)

    update_data: dict | None = user_data.model_dump(
        exclude_unset=True, by_alias=True, mode="python"
    )
    if not update_data:
        logger.info(f"No fields to update for user with ID: {userId}")
        raise NoFieldsToUpdateException

    if "email" in update_data:
        await validate_email_available_for_user(update_data["email"], userId, request)

    update_data["updatedAtUtc"] = datetime.now(UTC)

    result = await user_collection.update_one({"_id": userId}, {"$set": update_data})

    if result.matched_count == 0:
        logger.info(f"User not found with ID: {userId}")
        raise ForbiddenException

    updated_user_obj: UserModel | None = await user_collection.find_one({"_id": userId})
    if updated_user_obj is None:
        logger.info(f"Update failed for user with ID: {userId}")
        raise UserUpdateFailedException

    logger.info(f"User updated with ID: {userId}")
    return UserResponse(**updated_user_obj)


@user_router.delete(
    "/{userId}",
    response_description="Delete a user",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_user(
    userId: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> None:
    """Delete the record for a specific user, looked up by `userId`."""
    logger.info(f"Requested deletion for user with ID: {userId}")
    verify_user_access(token_payload, userId)

    result = await user_collection.delete_one({"_id": userId})

    if result.deleted_count == 0:
        logger.info(f"User not found with ID: {userId}")
        raise ForbiddenException

    logger.info(f"User deleted with ID: {userId}")
    return None
