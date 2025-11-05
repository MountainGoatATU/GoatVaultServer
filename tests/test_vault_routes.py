import base64
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status


@pytest.mark.asyncio
async def test_list_vaults_success(async_client, sample_user_id, sample_vault_id):
    """Test successfully listing all vaults for a user."""
    mock_vaults = [
        {
            "_id": sample_vault_id,
            "user_id": sample_user_id,
            "name": "Vault 1",
            "salt": b"salt123456789012",  # 16 bytes
            "encrypted_blob": b"blob1234567890123456",
            "nonce": b"nonce12345678901",  # 16 bytes
            "auth_tag": b"tag1234567890123",  # 16 bytes
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        },
        {
            "_id": uuid.uuid4(),
            "user_id": sample_user_id,
            "name": "Vault 2",
            "salt": b"salt223456789012",  # 16 bytes
            "encrypted_blob": b"blob2234567890123456",
            "nonce": b"nonce22345678901",  # 16 bytes
            "auth_tag": b"tag2234567890123",  # 16 bytes
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        },
    ]

    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_cursor = MagicMock()
        mock_cursor.to_list = AsyncMock(return_value=mock_vaults)
        mock_collection.find = MagicMock(return_value=mock_cursor)

        response = await async_client.get(f"/v1/users/{sample_user_id}/vaults/")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "vaults" in data
        assert len(data["vaults"]) == 2


@pytest.mark.asyncio
async def test_list_vaults_empty(async_client, sample_user_id):
    """Test listing vaults when user has none."""
    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_cursor = MagicMock()
        mock_cursor.to_list = AsyncMock(return_value=[])
        mock_collection.find = MagicMock(return_value=mock_cursor)

        response = await async_client.get(f"/v1/users/{sample_user_id}/vaults/")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["vaults"] == []


@pytest.mark.asyncio
async def test_get_vault_success(async_client, sample_user_id, sample_vault_id):
    """Test successfully retrieving a specific vault."""
    mock_vault = {
        "_id": sample_vault_id,
        "user_id": sample_user_id,
        "name": "My Vault",
        "salt": b"salt123456789012",  # 16 bytes
        "encrypted_blob": b"encrypted_blob_data",
        "nonce": b"nonce12345678901",  # 16 bytes
        "auth_tag": b"tag1234567890123",  # 16 bytes
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_vault)

        response = await async_client.get(
            f"/v1/users/{sample_user_id}/vaults/{sample_vault_id}"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "My Vault"
        assert data["user_id"] == str(sample_user_id)


@pytest.mark.asyncio
async def test_get_vault_not_found(async_client, sample_user_id, sample_vault_id):
    """Test retrieving a non-existent vault."""
    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client.get(
            f"/v1/users/{sample_user_id}/vaults/{sample_vault_id}"
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_get_vault_wrong_user(async_client, sample_user_id):
    """Test that users can't access other users' vaults."""
    vault_id = uuid.uuid4()

    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        # Vault exists but belongs to different user
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client.get(
            f"/v1/users/{sample_user_id}/vaults/{vault_id}"
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_create_vault_success(async_client, sample_user_id, sample_vault_data):
    """Test successfully creating a new vault."""
    new_vault_id = uuid.uuid4()
    created_vault = {
        "_id": new_vault_id,
        "user_id": sample_user_id,
        "name": sample_vault_data["name"],
        "salt": b"vault_salt_123456",  # 16 bytes
        "encrypted_blob": b"encrypted_data_blob",
        "nonce": b"random_nonce_1234",  # 16 bytes
        "auth_tag": b"auth_tag_12345678",  # 16 bytes
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("app.routes.vault_route.vault_collection") as mock_vault_col,
        patch("app.routes.vault_route.user_collection") as mock_user_col,
    ):
        # User exists
        mock_user_col.find_one = AsyncMock(
            return_value={"_id": sample_user_id, "email": "test@example.com"}
        )

        # Vault creation
        mock_result = MagicMock()
        mock_result.inserted_id = new_vault_id
        mock_vault_col.insert_one = AsyncMock(return_value=mock_result)
        mock_vault_col.find_one = AsyncMock(return_value=created_vault)

        response = await async_client.post(
            f"/v1/users/{sample_user_id}/vaults/", json=sample_vault_data
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == sample_vault_data["name"]
        assert data["user_id"] == str(sample_user_id)


@pytest.mark.asyncio
async def test_create_vault_user_not_found(
    async_client, sample_user_id, sample_vault_data
):
    """Test creating a vault for non-existent user."""
    with patch("app.routes.vault_route.user_collection") as mock_user_col:
        mock_user_col.find_one = AsyncMock(return_value=None)

        response = await async_client.post(
            f"/v1/users/{sample_user_id}/vaults/", json=sample_vault_data
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_update_vault_success(async_client, sample_user_id, sample_vault_id):
    """Test successfully updating a vault."""
    update_data = {"name": "Updated Vault Name"}
    updated_vault = {
        "_id": sample_vault_id,
        "user_id": sample_user_id,
        "name": "Updated Vault Name",
        "salt": b"salt123456789012",  # 16 bytes
        "encrypted_blob": b"encrypted_blob_data",
        "nonce": b"nonce12345678901",  # 16 bytes
        "auth_tag": b"tag1234567890123",  # 16 bytes
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_collection.find_one_and_update = AsyncMock(return_value=updated_vault)

        response = await async_client.patch(
            f"/v1/users/{sample_user_id}/vaults/{sample_vault_id}", json=update_data
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "Updated Vault Name"


@pytest.mark.asyncio
async def test_update_vault_not_found(async_client, sample_user_id, sample_vault_id):
    """Test updating a non-existent vault."""
    update_data = {"name": "Updated Name"}

    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_collection.find_one_and_update = AsyncMock(return_value=None)

        response = await async_client.patch(
            f"/v1/users/{sample_user_id}/vaults/{sample_vault_id}", json=update_data
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_update_vault_no_fields(async_client, sample_user_id, sample_vault_id):
    """Test updating a vault with no fields."""
    response = await async_client.patch(
        f"/v1/users/{sample_user_id}/vaults/{sample_vault_id}", json={}
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delete_vault_success(async_client, sample_user_id, sample_vault_id):
    """Test successfully deleting a vault."""
    deleted_vault = {
        "_id": sample_vault_id,
        "user_id": sample_user_id,
        "name": "Deleted Vault",
        "salt": b"salt123456789012",  # 16 bytes
        "encrypted_blob": b"encrypted_blob_data",
        "nonce": b"nonce12345678901",  # 16 bytes
        "auth_tag": b"tag1234567890123",  # 16 bytes
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_collection.find_one_and_delete = AsyncMock(return_value=deleted_vault)

        response = await async_client.delete(
            f"/v1/users/{sample_user_id}/vaults/{sample_vault_id}"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["user_id"] == str(sample_user_id)
        assert data["name"] == "Deleted Vault"


@pytest.mark.asyncio
async def test_delete_vault_not_found(async_client, sample_user_id, sample_vault_id):
    """Test deleting a non-existent vault."""
    with patch("app.routes.vault_route.vault_collection") as mock_collection:
        mock_collection.find_one_and_delete = AsyncMock(return_value=None)

        response = await async_client.delete(
            f"/v1/users/{sample_user_id}/vaults/{sample_vault_id}"
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_create_vault_with_custom_id(async_client, sample_user_id):
    """Test creating a vault with a custom ID."""
    custom_id = uuid.uuid4()
    vault_data = {
        "_id": str(custom_id),
        "name": "Custom ID Vault",
        "salt": base64.b64encode(b"salt123456789012").decode(
            "utf-8"
        ),  # 16 bytes encoded
        "encrypted_blob": base64.b64encode(b"encrypted_blob_data").decode("utf-8"),
        "nonce": base64.b64encode(b"nonce12345678901").decode(
            "utf-8"
        ),  # 16 bytes encoded
        "auth_tag": base64.b64encode(b"authtag123456789").decode(
            "utf-8"
        ),  # 16 bytes encoded
    }

    created_vault = {
        "_id": custom_id,
        "user_id": sample_user_id,
        "name": vault_data["name"],
        "salt": b"salt123456789012",
        "encrypted_blob": b"encrypted_blob_data",
        "nonce": b"nonce12345678901",
        "auth_tag": b"authtag123456789",
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("app.routes.vault_route.vault_collection") as mock_vault_col,
        patch("app.routes.vault_route.user_collection") as mock_user_col,
    ):
        mock_user_col.find_one = AsyncMock(
            return_value={"_id": sample_user_id, "email": "test@example.com"}
        )

        mock_result = MagicMock()
        mock_result.inserted_id = custom_id
        mock_vault_col.insert_one = AsyncMock(return_value=mock_result)
        mock_vault_col.find_one = AsyncMock(return_value=created_vault)

        response = await async_client.post(
            f"/v1/users/{sample_user_id}/vaults/", json=vault_data
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == "Custom ID Vault"
