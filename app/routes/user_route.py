from fastapi import APIRouter, Body, HTTPException, status
from fastapi.encoders import jsonable_encoder
from pymongo.results import InsertOneResult

from app.models.user_model import UserCollection, UserModel

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/",
    response_description="List all users",
    response_model=UserCollection,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def list_users() -> UserCollection:
    """
    List all users in the database.
    """
    from app.database import user_collection

    user_list = await user_collection.find().to_list()
    return UserCollection(users=user_list)


@router.get(
    "/{id}",
    response_description="Get a single user",
    response_model=UserModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def get_user(id: str) -> UserModel:
    """
    Get the record for a specific user, looked up by `id`.
    """
    from app.database import user_collection

    user = await user_collection.find_one({"_id": id})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {id} not found",
        )

    return UserModel(**user)


@router.post(
    "/",
    response_description="Add new user",
    response_model=UserModel,
    status_code=status.HTTP_201_CREATED,
    response_model_by_alias=False,
)
async def create_user(user: UserModel = Body(...)) -> UserModel:
    """
    Insert a new user record.

    A unique `id` will be created and provided in the response.
    """
    from app.database import user_collection

    new_user = jsonable_encoder(user)
    created_user: InsertOneResult = await user_collection.insert_one(new_user)
    created_user_obj = await user_collection.find_one({"_id": created_user.inserted_id})

    if created_user_obj is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )

    return UserModel(**created_user_obj)


@router.put(
    "/{id}",
    response_description="Update a user",
    response_model=UserModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_user(id: str, user: UserModel = Body(...)) -> UserModel:
    """
    Update the record for a specific user, looked up by `id`.
    """
    from app.database import user_collection

    updated_user = jsonable_encoder(user)
    await user_collection.update_one({"_id": id}, {"$set": updated_user})

    updated_user_obj = await user_collection.find_one({"_id": id})
    if updated_user_obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {id} not found",
        )

    return UserModel(**updated_user_obj)


@router.delete(
    "/{id}",
    response_description="Delete a user",
    response_model=UserModel,
    response_model_by_alias=False,
)
async def delete_user(id: str) -> UserModel:
    """
    Delete the record for a specific user, looked up by `id`.
    """
    from app.database import user_collection

    deleted_user = await user_collection.find_one_and_delete({"_id": id})
    if deleted_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {id} not found",
        )

    return UserModel(**deleted_user)
