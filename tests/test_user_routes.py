import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status

from app.database import get_user_collection
from app.main import app
from app.utils.validators import validate_email_available_for_user


@pytest.mark.asyncio
async def test_get_user_success(async_client, mock_user) -> None:
    """Test successfully retrieving a user."""

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client.get(f"/v1/users/{mock_user['_id']}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["_id"] == str(mock_user["_id"])
        assert data["email"] == "test@example.com"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_get_user_not_found(async_client, sample_user_id) -> None:
    """Test retrieving a non-existent user."""

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=None)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client.get(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_update_user_success(async_client, sample_user_id, mock_vault_object) -> None:
    """Test successfully updating a user."""
    update_data = {"email": "newemail@example.com"}
    updated_user = {
        "_id": sample_user_id,
        "email": "newemail@example.com",
        "auth_salt": b"salt1234567890ab",  # 16 bytes
        "auth_verifier": b"authverifier1234567890ab",  # 24 bytes
        "mfa_enabled": False,
        "mfa_secret": None,
        "vault": mock_vault_object,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock_result = MagicMock()
        mock_result.matched_count = 1
        mock.update_one = AsyncMock(return_value=mock_result)
        mock.find_one = AsyncMock(return_value=updated_user)
        return mock

    async def mock_validate_email(email: str, user_id, request):
        pass  # Email is available for this user

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[validate_email_available_for_user] = mock_validate_email
    try:
        response = await async_client.patch(f"/v1/users/{sample_user_id}", json=update_data)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "newemail@example.com"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_update_user_not_found(async_client, sample_user_id) -> None:
    """Test updating a non-existent user."""
    update_data = {"email": "newemail@example.com"}

    def override_get_user_collection():
        mock = AsyncMock()
        mock_result = MagicMock()
        mock_result.matched_count = 0
        mock.update_one = AsyncMock(return_value=mock_result)
        return mock

    async def mock_validate_email(email: str, user_id, request):
        pass  # Email is available for this user

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[validate_email_available_for_user] = mock_validate_email
    try:
        response = await async_client.patch(f"/v1/users/{sample_user_id}", json=update_data)

        assert response.status_code == status.HTTP_404_NOT_FOUND
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_update_user_no_fields(async_client, sample_user_id) -> None:
    """Test updating a user with no fields."""
    response = await async_client.patch(f"/v1/users/{sample_user_id}", json={})
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delete_user_success(async_client, mock_user) -> None:
    """Test successfully deleting a user."""

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one_and_delete = AsyncMock(return_value=mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client.delete(f"/v1/users/{mock_user['_id']}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["_id"] == str(mock_user["_id"])
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_delete_user_not_found(async_client, sample_user_id) -> None:
    """Test deleting a non-existent user."""

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one_and_delete = AsyncMock(return_value=None)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client.delete(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_bearer_token_required(async_client_no_auth) -> None:
    """Test that endpoints require Bearer token."""
    response = await async_client_no_auth.get(f"/v1/users/{uuid.uuid4()}")
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_update_user_retrieval_failure(async_client, sample_user_id) -> None:
    """Test user update when retrieval after update fails."""
    update_data = {"email": "newemail@example.com"}

    def override_get_user_collection():
        mock = AsyncMock()
        mock_result = MagicMock()
        mock_result.matched_count = 1
        mock.update_one = AsyncMock(return_value=mock_result)
        mock.find_one = AsyncMock(return_value=None)  # Fails to retrieve
        return mock

    async def mock_validate_email(email: str, user_id, request):
        pass  # Email is available for this user

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[validate_email_available_for_user] = mock_validate_email
    try:
        response = await async_client.patch(f"/v1/users/{sample_user_id}", json=update_data)

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Failed to update user" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()
