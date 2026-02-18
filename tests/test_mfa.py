import base64
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status

from app.database import get_user_collection
from app.main import app
from app.utils import verify_mfa


# Test verify_mfa utility function
@pytest.mark.asyncio
async def test_verify_mfa_valid_code(mfa_secret, valid_mfa_code) -> None:
    """Test MFA verification with valid code."""
    result = verify_mfa(valid_mfa_code, mfa_secret)
    assert result is True


@pytest.mark.asyncio
async def test_verify_mfa_invalid_code(mfa_secret) -> None:
    """Test MFA verification with invalid code."""
    result = verify_mfa("000000", mfa_secret)
    assert result is False


@pytest.mark.asyncio
async def test_verify_mfa_none_code(mfa_secret) -> None:
    """Test MFA verification with None code."""
    result = verify_mfa(None, mfa_secret)
    assert result is False


@pytest.mark.asyncio
async def test_verify_mfa_none_secret(valid_mfa_code) -> None:
    """Test MFA verification with None secret."""
    result = verify_mfa(valid_mfa_code, None)
    assert result is False


@pytest.mark.asyncio
async def test_verify_mfa_both_none() -> None:
    """Test MFA verification with both None."""
    result = verify_mfa(None, None)
    assert result is False


@pytest.mark.asyncio
async def test_verify_mfa_invalid_secret(valid_mfa_code) -> None:
    """Test MFA verification with invalid secret format."""
    result = verify_mfa(valid_mfa_code, "invalid-secret")
    assert result is False


@pytest.mark.asyncio
async def test_verify_mfa_wrong_code_length(mfa_secret) -> None:
    """Test MFA verification with wrong code length."""
    result = verify_mfa("12345", mfa_secret)  # Too short
    assert result is False

    result = verify_mfa("1234567", mfa_secret)  # Too long
    assert result is False


# Test auth init with MFA enabled
@pytest.mark.asyncio
async def test_init_with_mfa_enabled(async_client_no_auth, mock_user_with_mfa) -> None:
    """Test init endpoint returns MFA status when MFA is enabled."""
    init_request = {"email": "mfa@example.com"}

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "_id" in data
        assert data["_id"] == str(mock_user_with_mfa["_id"])
        assert "authSalt" in data
        assert "mfaEnabled" in data
        assert data["mfaEnabled"] is True
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_init_with_mfa_disabled(async_client_no_auth, mock_user) -> None:
    """Test init endpoint returns MFA status when MFA is disabled."""
    init_request = {"email": "test@example.com"}

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["mfaEnabled"] is False
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_with_mfa_wrong_format(async_client_no_auth, mock_user_with_mfa) -> None:
    """Test verification with MFA code in wrong format."""
    verify_request = {
        "_id": str(mock_user_with_mfa["_id"]),
        "authVerifier": base64.b64encode(mock_user_with_mfa["authVerifier"]).decode("utf-8"),
        "mfaCode": "12345",  # Too short
    }

    response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

    # Should fail validation before reaching the endpoint
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_user_update_enable_mfa(async_client, mock_user, mfa_secret) -> None:
    """Test enabling MFA via user update endpoint."""
    update_data = {
        "mfaEnabled": True,
        "mfaSecret": mfa_secret,
    }

    updated_user = mock_user.copy()
    updated_user.update(update_data)

    def override_get_user_collection():
        mock = AsyncMock()
        # Mock the update operation
        mock_result = MagicMock()
        mock_result.matched_count = 1
        mock_result.modified_count = 1
        mock.update_one = AsyncMock(return_value=mock_result)
        mock.find_one = AsyncMock(return_value=updated_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client.patch(f"/v1/users/{mock_user['_id']}", json=update_data)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["mfaEnabled"] is True
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_user_update_disable_mfa(async_client, mock_user_with_mfa) -> None:
    """Test disabling MFA via user update endpoint."""
    update_data = {
        "mfaEnabled": False,
        "mfaSecret": None,
    }

    updated_user = mock_user_with_mfa.copy()
    updated_user.update(update_data)

    def override_get_user_collection():
        mock = AsyncMock()
        mock_result = MagicMock()
        mock_result.matched_count = 1
        mock_result.modified_count = 1
        mock.update_one = AsyncMock(return_value=mock_result)
        mock.find_one = AsyncMock(return_value=updated_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client.patch(
            f"/v1/users/{mock_user_with_mfa['_id']}", json=update_data
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["mfaEnabled"] is False
    finally:
        app.dependency_overrides.clear()
