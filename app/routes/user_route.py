from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Request, status
from motor.motor_asyncio import AsyncIOMotorCollection

from app.database import get_user_collection
from app.models import (
    TokenPayload,
    UserResponse,
    UserUpdateRequest,
)
from app.services import delete_user_by_id, get_user_by_id, update_user_by_id
from app.utils import verify_access_token

user_router: APIRouter = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(verify_access_token)],
)


########################################################################
# GET /v1/users/{userId}
########################################################################


@user_router.get(
    "/{userId}",
    response_description="Get a single user",
    status_code=status.HTTP_200_OK,
)
async def get_user(
    userId: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> UserResponse:
    """Get the record for a specific user, looked up by `id`."""
    return await get_user_by_id(userId, token_payload, user_collection)


########################################################################
# PATCH /v1/users/{userId}
########################################################################


@user_router.patch(
    "/{userId}",
    response_description="Update a user",
    status_code=status.HTTP_200_OK,
)
async def update_user(
    userId: UUID,
    request: Request,
    user_data: Annotated[UserUpdateRequest, Body()],
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> UserResponse:
    """Update the record for a specific user, looked up by `userId`."""
    return await update_user_by_id(userId, request, user_data, token_payload, user_collection)


########################################################################
# DELETE /v1/users/{userId}
########################################################################


@user_router.delete(
    "/{userId}",
    response_description="Delete a user",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_user(
    userId: UUID,
    token_payload: Annotated[TokenPayload, Depends(verify_access_token)],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> None:
    """Delete the record for a specific user, looked up by `userId`."""
    return await delete_user_by_id(userId, token_payload, user_collection)
