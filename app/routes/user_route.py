from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, status
from pymongo.results import DeleteResult, UpdateResult

from app.auth import verify_token
from app.database import user_collection, vault_collection
from app.exceptions import (
    NoFieldsToUpdateException,
    UserNotFoundException,
    UserUpdateFailedException,
)
from app.models.user_model import (
    UserModel,
    UserResponse,
    UserUpdateRequest,
)
from app.validators import validate_email_available_for_user

user_router: APIRouter = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(verify_token)],
)


@user_router.get(
    "/{userId}",
    response_description="Get a single user",
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def get_user(userId: UUID) -> UserResponse:
    """Get the record for a specific user, looked up by `id`."""
    user = await user_collection.find_one({"_id": userId})
    if user is None:
        raise UserNotFoundException(userId)

    return UserResponse(**user)


@user_router.patch(
    "/{userId}",
    response_description="Update a user",
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_user(
    userId: UUID,
    user_data: Annotated[UserUpdateRequest, Body()],
) -> UserResponse:
    """Update the record for a specific user, looked up by `userId`."""
    update_data = user_data.model_dump(exclude_unset=True, mode="python")
    if not update_data:
        raise NoFieldsToUpdateException

    if "email" in update_data:
        await validate_email_available_for_user(update_data["email"], userId)

    update_data["updated_at"] = datetime.now(UTC)

    result: UpdateResult = await user_collection.update_one({"_id": userId}, {"$set": update_data})

    if result.matched_count == 0:
        raise UserNotFoundException(userId)

    updated_user_obj = await user_collection.find_one({"_id": userId})
    if updated_user_obj is None:
        raise UserUpdateFailedException

    return UserResponse(**updated_user_obj)


@user_router.delete(
    "/{userId}",
    response_description="Delete a user",
    response_model_by_alias=False,
)
async def delete_user(userId: UUID) -> UserModel:
    """Delete the record for a specific user, looked up by `userId`."""
    _: DeleteResult = await vault_collection.delete_many({"user_id": userId})

    deleted_user = await user_collection.find_one_and_delete({"_id": userId})
    if deleted_user is None:
        raise UserNotFoundException(userId)

    return UserModel(**deleted_user)
