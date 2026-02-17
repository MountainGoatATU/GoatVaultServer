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
    NoFieldsToUpdateException,
    UserNotFoundException,
    UserUpdateFailedException,
    validate_email_available_for_user,
    verify_token,
    verify_user_access,
)

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
    verify_user_access(token_payload, userId)

    user: UserModel | None = await user_collection.find_one({"_id": userId})
    if user is None:
        raise UserNotFoundException

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
    verify_user_access(token_payload, userId)

    update_data: UserModel | None = user_data.model_dump(exclude_unset=True, mode="python")
    if not update_data:
        raise NoFieldsToUpdateException

    if "email" in update_data:
        await validate_email_available_for_user(update_data["email"], userId, request)

    update_data["updated_at"] = datetime.now(UTC)

    result = await user_collection.update_one({"_id": userId}, {"$set": update_data})

    if result.matched_count == 0:
        raise UserNotFoundException

    updated_user_obj: UserModel | None = await user_collection.find_one({"_id": userId})
    if updated_user_obj is None:
        raise UserUpdateFailedException

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
    verify_user_access(token_payload, userId)

    result = await user_collection.delete_one({"_id": userId})

    if result.deleted_count == 0:
        raise UserNotFoundException

    return None
