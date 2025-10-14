from fastapi import APIRouter, Body, HTTPException, status
from fastapi.encoders import jsonable_encoder
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult

from app.models.vault_model import VaultCollection, VaultModel


router = APIRouter(prefix="/vaults", tags=["vaults"])


@router.get(
    "/",
    response_description="List all vaults",
    response_model=VaultCollection,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def list_vaults() -> VaultCollection:
    """
    List all vaults in the database.

    The response is unpaginated and limited to 1000 results.
    """
    from app.database import vault_collection

    vault_list = await vault_collection.find().to_list(1000)
    return VaultCollection(vaults=vault_list)


@router.get(
    "/{id}",
    response_description="Get a single vault",
    response_model=VaultModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def get_vault(id: str) -> VaultModel:
    """
    Get the record for a specific vault, looked up by `id`.
    """
    from app.database import vault_collection

    vault = await vault_collection.find_one({"_id": id})

    if vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {id} not found",
        )

    return VaultModel(**vault)


@router.post(
    "/",
    response_description="Add new vault",
    response_model=VaultModel,
    status_code=status.HTTP_201_CREATED,
    response_model_by_alias=False,
)
async def create_vault(vault: VaultModel = Body(...)) -> VaultModel:
    """
    Insert a new vault record.

    A unique `id` will be created and provided in the response.
    """
    from app.database import vault_collection

    new_vault = jsonable_encoder(vault)
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


@router.put(
    path="/{id}",
    response_description="Update a vault",
    response_model=VaultModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def update_vault(id: str, vault: VaultModel) -> VaultModel:
    """
    Update the record for a specific vault, looked up by `id`.
    """
    from app.database import vault_collection

    updated_vault = await vault_collection.find_one_and_update(
        {"_id": id},
        {"$set": jsonable_encoder(vault)},
        return_document=ReturnDocument.AFTER,
    )

    if updated_vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {id} not found",
        )

    return VaultModel(**updated_vault)


@router.delete(
    "/{id}",
    response_description="Delete a vault",
    response_model=VaultModel,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=False,
)
async def delete_vault(id: str) -> VaultModel:
    """
    Delete the record for a specific vault, looked up by `id`.
    """
    from app.database import vault_collection

    deleted_vault = await vault_collection.find_one_and_delete({"_id": id})

    if deleted_vault is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {id} not found",
        )

    return VaultModel(**deleted_vault)
