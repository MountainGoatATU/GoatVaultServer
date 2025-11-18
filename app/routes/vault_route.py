import uuid
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, status
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult

from app.auth import verify_token
from app.database import user_collection, vault_collection
from app.exceptions import (
    NoFieldsToUpdateException,
    UserNotFoundException,
    VaultCreationFailedException,
)
from app.models.vault_model import (
    VaultCreateRequest,
    VaultModel,
    VaultResponse,
    VaultUpdateRequest,
)

vault_router: APIRouter = APIRouter(
    prefix="/vaults", tags=["Vaults"], dependencies=[Depends(verify_token)]
)


@vault_router.get(
    "/",
    response_description="Get a single vault",
    response_model=VaultResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def get_vault(userId: UUID) -> VaultResponse:
    """
    Get the record for a specific vault, looked up by `user_id`.
    """
    vault = await vault_collection.find_one({"user_id": userId})

    if vault is None:
        raise UserNotFoundException(userId)

    return VaultResponse(**vault)


@vault_router.post(
    "/",
    response_description="Add new vault",
    response_model=VaultResponse,
    status_code=status.HTTP_201_CREATED,
    response_model_by_alias=False,
)
async def create_vault(vault_data: Annotated[VaultCreateRequest, Body()]) -> VaultResponse:
    """
    Insert a new vault record.
    """
    vault_id = vault_data.id or uuid.uuid4()  # Generate a new UUID if not provided
    user_id = vault_data.user_id
    user = await user_collection.find_one({"_id": user_id})

    if user is None:
        raise UserNotFoundException(user_id)

    new_vault = VaultModel(
        _id=vault_id,
        user_id=user_id,
        name=vault_data.name,
        salt=vault_data.salt,
        encrypted_blob=vault_data.data,
        nonce=vault_data.nonce,
        auth_tag=vault_data.auth_tag,
    )

    new_vault_dict = new_vault.model_dump(by_alias=True, mode="python")

    try:
        created_vault: InsertOneResult = await vault_collection.insert_one(new_vault_dict)
    except KeyError as err:
        raise VaultCreationFailedException() from err  # Duplicate key or other insertion error

    created_vault_obj = await vault_collection.find_one({"_id": created_vault.inserted_id})

    if created_vault_obj is None:
        raise VaultCreationFailedException()

    return VaultResponse(**created_vault_obj)


@vault_router.patch(
    path="/",
    response_description="Update a vault",
    response_model=VaultResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_vault(userId: UUID, vault_data: VaultUpdateRequest) -> VaultResponse:
    """
    Update the record for a specific vault, looked up by `id`.
    """
    update_data = vault_data.model_dump(exclude_unset=True, mode="python")

    if not update_data:
        raise NoFieldsToUpdateException()

    update_data["updated_at"] = datetime.now(UTC)

    updated_vault = await vault_collection.find_one_and_update(
        {"user_id": userId},
        {"$set": update_data},
        return_document=ReturnDocument.AFTER,
    )

    if updated_vault is None:
        raise UserNotFoundException(userId)

    return VaultResponse(**updated_vault)


@vault_router.delete(
    "/",
    response_description="Delete a vault",
    response_model=VaultResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def delete_vault(userId: UUID) -> VaultResponse:
    """
    Delete the record for a specific vault, looked up by `id`.
    """
    deleted_vault = await vault_collection.find_one_and_delete({"user_id": userId})

    if deleted_vault is None:
        raise UserNotFoundException(userId)

    return VaultResponse(**deleted_vault)
