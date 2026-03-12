from uuid import UUID

from fastapi import APIRouter, Request, status

user_router: APIRouter = APIRouter(prefix="/users", tags=["users"], dependencies=[])


########################################################################
# GET /v1/users/{user_id}
########################################################################


@user_router.get(
    "/{user_id}", response_description="Get a single user", status_code=status.HTTP_200_OK
)
async def get_user(user_id: UUID):
    """Get the record for a specific user, looked up by `id`."""
    ...


########################################################################
# PATCH /v1/users/{userId}
########################################################################


@user_router.patch(
    "/{userId}", response_description="Update a user", status_code=status.HTTP_200_OK
)
async def update_user(userId: UUID, request: Request):
    """Update the record for a specific user, looked up by `userId`."""
    ...


########################################################################
# DELETE /v1/users/{userId}
########################################################################


@user_router.delete(
    "/{userId}", response_description="Delete a user", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_user(userId: UUID) -> None:
    """Delete the record for a specific user, looked up by `userId`."""
    ...
