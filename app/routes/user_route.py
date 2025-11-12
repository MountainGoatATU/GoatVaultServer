from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, status
from pymongo.results import DeleteResult, InsertOneResult, UpdateResult

from app.auth import verify_token
from app.database import user_collection, vault_collection
from app.exceptions import (
    NoFieldsToUpdateException,
    UserCreationFailedException,
    UserNotFoundException,
    UserUpdateFailedException,
)
from app.models.user_model import (
    UserCreateRequest,
    UserModel,
    UserResponse,
    UserUpdateRequest,
)
from app.validators import validate_email_available, validate_email_available_for_user

user_router: APIRouter = APIRouter(
    prefix="/users", tags=["users"], dependencies=[Depends(verify_token)]
)


@user_router.get(
    "/{userId}",
    response_description="Get a single user",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def get_user(userId: UUID) -> UserResponse:
    """
    Get the record for a specific user, looked up by `id`.
    """
    user = await user_collection.find_one({"_id": userId})
    if user is None:
        raise UserNotFoundException(userId)

    return UserResponse(**user)


@user_router.post(
    "/",
    response_description="Add new user",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    response_model_by_alias=False,
)
async def create_user(user_data: Annotated[UserCreateRequest, Body()]) -> UserResponse:
    """
    Insert a new user record.

    A unique `userId` will be created and provided in the response.
    """
    await validate_email_available(user_data.email)

    new_user = UserModel(
        email=user_data.email,
        salt=user_data.salt,
        password_hash=user_data.password_hash,
    )

    new_user_dict = new_user.model_dump(by_alias=True, mode="python")
    created_user: InsertOneResult = await user_collection.insert_one(new_user_dict)
    created_user_obj = await user_collection.find_one({"_id": created_user.inserted_id})

    if created_user_obj is None:
        raise UserCreationFailedException()

    return UserResponse(**created_user_obj)


@user_router.patch(
    "/{userId}",
    response_description="Update a user",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_user(
    userId: UUID, user_data: Annotated[UserUpdateRequest, Body()]
) -> UserResponse:
    """
    Update the record for a specific user, looked up by `userId`.
    """
    update_data = user_data.model_dump(exclude_unset=True, mode="python")
    if not update_data:
        raise NoFieldsToUpdateException()

    if "email" in update_data:
        await validate_email_available_for_user(update_data["email"], userId)

    update_data["updated_at"] = datetime.now(UTC)

    result: UpdateResult = await user_collection.update_one({"_id": userId}, {"$set": update_data})

    if result.matched_count == 0:
        raise UserNotFoundException(userId)

    updated_user_obj = await user_collection.find_one({"_id": userId})
    if updated_user_obj is None:
        raise UserUpdateFailedException()

    return UserResponse(**updated_user_obj)


@user_router.delete(
    "/{userId}",
    response_description="Delete a user",
    response_model=UserModel,
    response_model_by_alias=False,
)
async def delete_user(userId: UUID) -> UserModel:
    """
    Delete the record for a specific user, looked up by `userId`.
    """

    _: DeleteResult = await vault_collection.delete_many({"user_id": userId})

    deleted_user = await user_collection.find_one_and_delete({"_id": userId})
    if deleted_user is None:
        raise UserNotFoundException(userId)

    return UserModel(**deleted_user)
