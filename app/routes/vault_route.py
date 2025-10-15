from uuid import UUID
from fastapi import APIRouter, Body, HTTPException, status
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult

from app.models.vault_model import VaultCollection, VaultModel


vault_router = APIRouter(prefix="/{userId}/vaults")


@vault_router.get(
    "/",
    response_description="List all vaults",
    response_model=VaultCollection,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def list_vaults(userId: UUID) -> VaultCollection:
    """
    List all vaults in the database.

    The response is unpaginated and limited to 1000 results.
    """
    from app.database import vault_collection

    vault_list = await vault_collection.find({"user_id": userId}).to_list(1000)
    return VaultCollection(vaults=vault_list)


@vault_router.get(
    "/{vaultId}",
    response_description="Get a single vault",
    response_model=VaultModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def get_vault(userId: UUID, vaultId: UUID) -> VaultModel:
    """
    Get the record for a specific vault, looked up by `id`.
    """
    from app.database import vault_collection

    vault = await vault_collection.find_one({"_id": vaultId, "user_id": userId})

    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {id} not found",
        )

    return VaultModel(**vault)


@vault_router.post(
    "/",
    response_description="Add new vault",
    response_model=VaultModel,
    status_code=status.HTTP_201_CREATED,
    response_model_by_alias=False,
)
async def create_vault(userId: UUID, vault: VaultModel = Body(...)) -> VaultModel:
    """
    Insert a new vault record.

    A unique `id` will be created and provided in the response.
    """
    from app.database import vault_collection

    new_vault = vault.model_dump(by_alias=True, mode="python")
    new_vault["user_id"] = userId

    created_vault: InsertOneResult = await vault_collection.insert_one(new_vault)
    created_vault_obj = await vault_collection.find_one(
        {"_id": created_vault.inserted_id}
    )

    if created_vault_obj is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create vault",
        )

    return VaultModel(**created_vault_obj)


@vault_router.put(
    path="/{vaultId}",
    response_description="Update a vault",
    response_model=VaultModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_vault(userId: UUID, vaultId: UUID, vault: VaultModel) -> VaultModel:
    """
    Update the record for a specific vault, looked up by `id`.
    """
    from app.database import vault_collection

    updated_vault = await vault_collection.find_one_and_update(
        {"_id": vaultId, "user_id": userId},
        {"$set": vault.model_dump(by_alias=True, mode="python")},
        return_document=ReturnDocument.AFTER,
    )

    if updated_vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {vaultId} not found",
        )

    return VaultModel(**updated_vault)


@vault_router.delete(
    "/{vaultId}",
    response_description="Delete a vault",
    response_model=VaultModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def delete_vault(userId: UUID, vaultId: UUID) -> VaultModel:
    """
    Delete the record for a specific vault, looked up by `id`.
    """
    from app.database import vault_collection

    deleted_vault = await vault_collection.find_one_and_delete(
        {"_id": vaultId, "user_id": userId}
    )

    if deleted_vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {vaultId} not found",
        )

    return VaultModel(**deleted_vault)
