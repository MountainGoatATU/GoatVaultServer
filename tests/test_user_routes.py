import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status


@pytest.mark.asyncio
async def test_get_user_success(async_client, sample_user_id):
    """Test successfully retrieving a user."""
    mock_user = {
        "_id": sample_user_id,
        "email": "test@example.com",
        "salt": b"salt1234567890ab",  # 16 bytes
        "password_hash": b"hash1234567890ab",  # 16 bytes
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with patch("app.routes.user_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client.get(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == str(sample_user_id)
        assert data["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_not_found(async_client, sample_user_id):
    """Test retrieving a non-existent user."""
    with patch("app.routes.user_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client.get(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_user_success(async_client, sample_user_data):
    """Test successfully creating a new user."""
    new_user_id = uuid.uuid4()
    created_user = {
        "_id": new_user_id,
        "email": sample_user_data["email"],
        "salt": b"salt1234567890ab",  # 16 bytes
        "password_hash": b"hash1234567890ab",  # 16 bytes
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("app.routes.user_route.user_collection") as mock_collection,
        patch("app.routes.user_route.validate_email_available", new=AsyncMock()),
    ):
        mock_result = MagicMock()
        mock_result.inserted_id = new_user_id
        mock_collection.insert_one = AsyncMock(return_value=mock_result)
        mock_collection.find_one = AsyncMock(return_value=created_user)

        response = await async_client.post("/v1/users/", json=sample_user_data)

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["email"] == sample_user_data["email"]
        assert "id" in data


@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, sample_user_data):
    """Test creating a user with an email that already exists."""
    with patch("app.routes.user_route.validate_email_available") as mock_validate:
        from app.exceptions import UserAlreadyExistsException

        mock_validate.side_effect = UserAlreadyExistsException()

        response = await async_client.post("/v1/users/", json=sample_user_data)

        assert response.status_code == status.HTTP_409_CONFLICT


@pytest.mark.asyncio
async def test_update_user_success(async_client, sample_user_id):
    """Test successfully updating a user."""
    update_data = {"email": "newemail@example.com"}
    updated_user = {
        "_id": sample_user_id,
        "email": "newemail@example.com",
        "salt": b"salt1234567890ab",  # 16 bytes
        "password_hash": b"hash1234567890ab",  # 16 bytes
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("app.routes.user_route.user_collection") as mock_collection,
        patch(
            "app.routes.user_route.validate_email_available_for_user", new=AsyncMock()
        ),
    ):
        mock_result = MagicMock()
        mock_result.matched_count = 1
        mock_collection.update_one = AsyncMock(return_value=mock_result)
        mock_collection.find_one = AsyncMock(return_value=updated_user)

        response = await async_client.patch(
            f"/v1/users/{sample_user_id}", json=update_data
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "newemail@example.com"


@pytest.mark.asyncio
async def test_update_user_not_found(async_client, sample_user_id):
    """Test updating a non-existent user."""
    update_data = {"email": "newemail@example.com"}

    with (
        patch("app.routes.user_route.user_collection") as mock_collection,
        patch(
            "app.routes.user_route.validate_email_available_for_user", new=AsyncMock()
        ),
    ):
        mock_result = MagicMock()
        mock_result.matched_count = 0
        mock_collection.update_one = AsyncMock(return_value=mock_result)

        response = await async_client.patch(
            f"/v1/users/{sample_user_id}", json=update_data
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_update_user_no_fields(async_client, sample_user_id):
    """Test updating a user with no fields."""
    with patch("app.routes.user_route.user_collection"):
        response = await async_client.patch(f"/v1/users/{sample_user_id}", json={})

        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delete_user_success(async_client, sample_user_id):
    """Test successfully deleting a user."""
    deleted_user = {
        "_id": sample_user_id,
        "email": "test@example.com",
        "salt": b"salt1234567890ab",  # 16 bytes
        "password_hash": b"hash1234567890ab",  # 16 bytes
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("app.routes.user_route.user_collection") as mock_user_col,
        patch("app.routes.user_route.vault_collection") as mock_vault_col,
    ):
        mock_user_col.find_one_and_delete = AsyncMock(return_value=deleted_user)
        mock_vault_col.delete_many = AsyncMock()

        response = await async_client.delete(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == str(sample_user_id)

        # Verify vaults were deleted
        mock_vault_col.delete_many.assert_called_once_with({"user_id": sample_user_id})


@pytest.mark.asyncio
async def test_delete_user_not_found(async_client, sample_user_id):
    """Test deleting a non-existent user."""
    with (
        patch("app.routes.user_route.user_collection") as mock_user_col,
        patch("app.routes.user_route.vault_collection") as mock_vault_col,
    ):
        mock_user_col.find_one_and_delete = AsyncMock(return_value=None)
        mock_vault_col.delete_many = AsyncMock()

        response = await async_client.delete(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_api_key_required(async_client):
    """Test that endpoints require API key."""
    # Create client without API key
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client_no_auth:
        response = await client_no_auth.get(f"/v1/users/{uuid.uuid4()}")
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_invalid_api_key(invalid_api_key):
    """Test that invalid API key is rejected."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"X-API-Key": invalid_api_key},
    ) as client:
        response = await client.get(f"/v1/users/{uuid.uuid4()}")
        assert response.status_code == status.HTTP_403_FORBIDDEN
