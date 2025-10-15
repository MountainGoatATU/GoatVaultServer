from datetime import UTC, datetime
from uuid import UUID
from fastapi import APIRouter, Body, HTTPException, status
from pymongo.results import InsertOneResult, UpdateResult

from app.models.user_model import (
    UserModel,
    UserCreateRequest,
    UserUpdateRequest,
    UserResponse,
)

from app.routes.vault_route import vault_router

user_router = APIRouter(prefix="/users", tags=["users"])
user_router.include_router(vault_router)


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
    from app.database import user_collection

    user = await user_collection.find_one({"_id": userId})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {userId} not found",
        )

    return UserResponse(**user)


@user_router.post(
    "/",
    response_description="Add new user",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    response_model_by_alias=False,
)
async def create_user(user_data: UserCreateRequest = Body(...)) -> UserResponse:
    """
    Insert a new user record.

    A unique `userId` will be created and provided in the response.
    """
    from app.database import user_collection

    existing_user = await user_collection.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    new_user = UserModel(
        email=user_data.email,
        salt=user_data.salt,
        password_hash=user_data.password_hash,
    )

    new_user_dict = new_user.model_dump(by_alias=True, mode="python")
    created_user: InsertOneResult = await user_collection.insert_one(new_user_dict)
    created_user_obj = await user_collection.find_one({"_id": created_user.inserted_id})

    if created_user_obj is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )

    return UserResponse(**created_user_obj)


@user_router.patch(
    "/{userId}",
    response_description="Update a user",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_user(
    userId: UUID, user_data: UserUpdateRequest = Body(...)
) -> UserResponse:
    """
    Update the record for a specific user, looked up by `userId`.
    """
    from app.database import user_collection

    update_data = user_data.model_dump(exclude_unset=True, mode="python")
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )

    update_data["updated_at"] = datetime.now(UTC)

    if "email" in update_data:
        existing = await user_collection.find_one(
            {"email": update_data["email"], "_id": {"$ne": userId}}
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use",
            )

    result: UpdateResult = await user_collection.update_one(
        {"_id": userId}, {"$set": update_data}
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {userId} not found",
        )

    updated_user_obj = await user_collection.find_one({"_id": userId})
    if updated_user_obj is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve updated user",
        )

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
    from app.database import user_collection

    deleted_user = await user_collection.find_one_and_delete({"_id": userId})
    if deleted_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {userId} not found",
        )

    return UserModel(**deleted_user)
