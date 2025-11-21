import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status


@pytest.mark.asyncio
async def test_get_user_success(async_client, mock_user) -> None:
    """Test successfully retrieving a user."""
    with patch("app.routes.user_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client.get(f"/v1/users/{mock_user['_id']}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == str(mock_user["_id"])
        assert data["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_not_found(async_client, sample_user_id) -> None:
    """Test retrieving a non-existent user."""
    with patch("app.routes.user_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client.get(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()


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

    with (
        patch("app.routes.user_route.user_collection") as mock_collection,
        patch("app.routes.user_route.validate_email_available_for_user", new=AsyncMock()),
    ):
        mock_result = MagicMock()
        mock_result.matched_count = 1
        mock_collection.update_one = AsyncMock(return_value=mock_result)
        mock_collection.find_one = AsyncMock(return_value=updated_user)

        response = await async_client.patch(f"/v1/users/{sample_user_id}", json=update_data)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "newemail@example.com"


@pytest.mark.asyncio
async def test_update_user_not_found(async_client, sample_user_id) -> None:
    """Test updating a non-existent user."""
    update_data = {"email": "newemail@example.com"}

    with (
        patch("app.routes.user_route.user_collection") as mock_collection,
        patch("app.routes.user_route.validate_email_available_for_user", new=AsyncMock()),
    ):
        mock_result = MagicMock()
        mock_result.matched_count = 0
        mock_collection.update_one = AsyncMock(return_value=mock_result)

        response = await async_client.patch(f"/v1/users/{sample_user_id}", json=update_data)

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_update_user_no_fields(async_client, sample_user_id) -> None:
    """Test updating a user with no fields."""
    with patch("app.routes.user_route.user_collection"):
        response = await async_client.patch(f"/v1/users/{sample_user_id}", json={})

        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delete_user_success(async_client, mock_user) -> None:
    """Test successfully deleting a user."""
    with (
        patch("app.routes.user_route.user_collection") as mock_user_col,
    ):
        mock_user_col.find_one_and_delete = AsyncMock(return_value=mock_user)

        response = await async_client.delete(f"/v1/users/{mock_user['_id']}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == str(mock_user["_id"])


@pytest.mark.asyncio
async def test_delete_user_not_found(async_client, sample_user_id) -> None:
    """Test deleting a non-existent user."""
    with (
        patch("app.routes.user_route.user_collection") as mock_user_col,
    ):
        mock_user_col.find_one_and_delete = AsyncMock(return_value=None)

        response = await async_client.delete(f"/v1/users/{sample_user_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_bearer_token_required(async_client_no_auth) -> None:
    """Test that endpoints require Bearer token."""
    response = await async_client_no_auth.get(f"/v1/users/{uuid.uuid4()}")
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_invalid_bearer_token(invalid_token) -> None:
    """Test that invalid Bearer token is rejected."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {invalid_token}"},
    ) as client:
        response = await client.get(f"/v1/users/{uuid.uuid4()}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_expired_bearer_token(expired_token) -> None:
    """Test that expired Bearer token is rejected."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {expired_token}"},
    ) as client:
        response = await client.get(f"/v1/users/{uuid.uuid4()}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_wrong_issuer_token(wrong_issuer_token) -> None:
    """Test that token with wrong issuer is rejected."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {wrong_issuer_token}"},
    ) as client:
        response = await client.get(f"/v1/users/{uuid.uuid4()}")
        assert response.status_code == status.HTTP_403_FORBIDDEN
