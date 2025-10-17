from datetime import UTC, datetime
from uuid import UUID
from fastapi import APIRouter, Body, HTTPException, status
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult

from app.models.vault_model import (
    VaultModel,
    VaultCreateRequest,
    VaultUpdateRequest,
    VaultResponse,
    VaultCollection,
)

from app.database import vault_collection, user_collection


vault_router = APIRouter(prefix="/{userId}/vaults")


@vault_router.get(
    "/",
    response_description="List all vaults for a user.",
    response_model=VaultCollection,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def list_vaults(userId: UUID) -> VaultCollection:
    """
    List all vaults for a specific user.
    """
    vault_list = await vault_collection.find({"user_id": userId}).to_list(1000)
    return VaultCollection(vaults=vault_list)


@vault_router.get(
    "/{vaultId}",
    response_description="Get a single vault",
    response_model=VaultResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def get_vault(userId: UUID, vaultId: UUID) -> VaultResponse:
    """
    Get the record for a specific vault, looked up by `id`.
    """
    vault = await vault_collection.find_one({"_id": vaultId, "user_id": userId})

    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {vaultId} not found",
        )

    return VaultResponse(**vault)


@vault_router.post(
    "/",
    response_description="Add new vault",
    response_model=VaultResponse,
    status_code=status.HTTP_201_CREATED,
    response_model_by_alias=False,
)
async def create_vault(
    userId: UUID, vault_data: VaultCreateRequest = Body(...)
) -> VaultResponse:
    """
    Insert a new vault record.
    """
    user = await user_collection.find_one({"_id": userId})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {userId} not found",
        )

    new_vault = VaultModel(
        user_id=userId,
        name=vault_data.name,
        salt=vault_data.salt,
        encrypted_blob=vault_data.encrypted_blob,
        nonce=vault_data.nonce,
        auth_tag=vault_data.auth_tag,
    )

    new_vault_dict = new_vault.model_dump(by_alias=True, mode="python")
    created_vault: InsertOneResult = await vault_collection.insert_one(new_vault_dict)
    created_vault_obj = await vault_collection.find_one(
        {"_id": created_vault.inserted_id}
    )

    if created_vault_obj is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create vault",
        )

    return VaultResponse(**created_vault_obj)


@vault_router.patch(
    path="/{vaultId}",
    response_description="Update a vault",
    response_model=VaultResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_vault(
    userId: UUID, vaultId: UUID, vault_data: VaultUpdateRequest
) -> VaultResponse:
    """
    Update the record for a specific vault, looked up by `id`.
    """
    update_data = vault_data.model_dump(exclude_unset=True, mode="python")

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )

    update_data["updated_at"] = datetime.now(UTC)

    updated_vault = await vault_collection.find_one_and_update(
        {"_id": vaultId, "user_id": userId},
        {"$set": update_data},
        return_document=ReturnDocument.AFTER,
    )

    if updated_vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {vaultId} not found",
        )

    return VaultResponse(**updated_vault)


@vault_router.delete(
    "/{vaultId}",
    response_description="Delete a vault",
    response_model=VaultResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def delete_vault(userId: UUID, vaultId: UUID) -> VaultResponse:
    """
    Delete the record for a specific vault, looked up by `id`.
    """
    deleted_vault = await vault_collection.find_one_and_delete(
        {"_id": vaultId, "user_id": userId}
    )

    if deleted_vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {vaultId} not found",
        )

    return VaultResponse(**deleted_vault)
