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
        assert "auth_salt" in data
        assert "mfa_enabled" in data
        assert data["mfa_enabled"] is True
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
        assert data["mfa_enabled"] is False
    finally:
        app.dependency_overrides.clear()


# Test auth verify with MFA
@pytest.mark.asyncio
async def test_verify_with_mfa_success(
    async_client_no_auth, mock_user_with_mfa, valid_mfa_code
) -> None:
    """Test successful verification with valid MFA code."""
    verify_request = {
        "_id": str(mock_user_with_mfa["_id"]),
        "auth_verifier": base64.b64encode(mock_user_with_mfa["auth_verifier"]).decode("utf-8"),
        "mfa_code": valid_mfa_code,
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        assert len(data["access_token"]) > 0
        assert data["token_type"] == "bearer"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_with_mfa_missing_code(async_client_no_auth, mock_user_with_mfa) -> None:
    """Test verification fails when MFA code is required but not provided."""
    verify_request = {
        "_id": str(mock_user_with_mfa["_id"]),
        "auth_verifier": base64.b64encode(mock_user_with_mfa["auth_verifier"]).decode("utf-8"),
        # mfa_code is intentionally missing
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "MFA code is required" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_with_mfa_invalid_code(async_client_no_auth, mock_user_with_mfa) -> None:
    """Test verification fails when MFA code is invalid."""
    verify_request = {
        "_id": str(mock_user_with_mfa["_id"]),
        "auth_verifier": base64.b64encode(mock_user_with_mfa["auth_verifier"]).decode("utf-8"),
        "mfa_code": "000000",  # Invalid code
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid MFA code" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_with_mfa_wrong_format(async_client_no_auth, mock_user_with_mfa) -> None:
    """Test verification with MFA code in wrong format."""
    verify_request = {
        "_id": str(mock_user_with_mfa["_id"]),
        "auth_verifier": base64.b64encode(mock_user_with_mfa["auth_verifier"]).decode("utf-8"),
        "mfa_code": "12345",  # Too short
    }

    response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

    # Should fail validation before reaching the endpoint
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_verify_without_mfa_when_not_enabled(async_client_no_auth, mock_user) -> None:
    """Test verification succeeds without MFA code when MFA is not enabled."""
    verify_request = {
        "_id": str(mock_user["_id"]),
        "auth_verifier": base64.b64encode(mock_user["auth_verifier"]).decode("utf-8"),
        # No mfa_code provided, and it's not required
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_with_mfa_code_when_not_enabled(
    async_client_no_auth, mock_user, valid_mfa_code
) -> None:
    """Test providing MFA code when MFA is not enabled (should still succeed)."""
    verify_request = {
        "_id": str(mock_user["_id"]),
        "auth_verifier": base64.b64encode(mock_user["auth_verifier"]).decode("utf-8"),
        "mfa_code": valid_mfa_code,  # Provided but not required
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
    finally:
        app.dependency_overrides.clear()


# Test full MFA auth flow
@pytest.mark.asyncio
async def test_full_mfa_auth_flow(async_client_no_auth, mock_user_with_mfa, valid_mfa_code) -> None:
    """Test complete auth flow with MFA: init -> verify with MFA code."""
    # Step 1: Init
    init_request = {"email": "mfa@example.com"}

    def override_get_user_collection_init():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection_init
    try:
        init_response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

        assert init_response.status_code == status.HTTP_200_OK
        init_data = init_response.json()
        assert init_data["mfa_enabled"] is True
        user_id = init_data["_id"]
    finally:
        app.dependency_overrides.clear()

    # Step 2: Verify with MFA code
    verify_request = {
        "_id": user_id,
        "auth_verifier": base64.b64encode(mock_user_with_mfa["auth_verifier"]).decode("utf-8"),
        "mfa_code": valid_mfa_code,
    }

    def override_get_user_collection_verify():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection_verify
    try:
        verify_response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert verify_response.status_code == status.HTTP_200_OK
        verify_data = verify_response.json()
        assert "access_token" in verify_data
        assert verify_data["token_type"] == "bearer"
    finally:
        app.dependency_overrides.clear()

    # Step 3: Use token to access protected endpoint
    token = verify_data["access_token"]

    def override_get_user_collection_access():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection_access
    try:
        user_response = await async_client_no_auth.get(
            f"/v1/users/{user_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert user_response.status_code == status.HTTP_200_OK
        user_data = user_response.json()
        assert user_data["_id"] == user_id
        assert user_data["mfa_enabled"] is True
    finally:
        app.dependency_overrides.clear()


# Test MFA edge cases
@pytest.mark.asyncio
async def test_verify_mfa_with_expired_code(async_client_no_auth, mock_user_with_mfa) -> None:
    """Test that old/expired MFA codes don't work."""
    verify_request = {
        "_id": str(mock_user_with_mfa["_id"]),
        "auth_verifier": base64.b64encode(mock_user_with_mfa["auth_verifier"]).decode("utf-8"),
        "mfa_code": "123456",  # Random invalid code
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid MFA code" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_mfa_with_invalid_verifier_and_valid_mfa(
    async_client_no_auth, mock_user_with_mfa, valid_mfa_code
) -> None:
    """Test that invalid auth_verifier fails even with valid MFA code."""
    verify_request = {
        "_id": str(mock_user_with_mfa["_id"]),
        "auth_verifier": base64.b64encode(b"wrongverifier1234567890ab").decode("utf-8"),
        "mfa_code": valid_mfa_code,  # Valid MFA code but wrong verifier
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user_with_mfa)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        # Should fail on auth_verifier check before MFA check
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid auth verifier" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_user_update_enable_mfa(async_client, mock_user, mfa_secret) -> None:
    """Test enabling MFA via user update endpoint."""
    update_data = {
        "mfa_enabled": True,
        "mfa_secret": mfa_secret,
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
        assert data["mfa_enabled"] is True
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_user_update_disable_mfa(async_client, mock_user_with_mfa) -> None:
    """Test disabling MFA via user update endpoint."""
    update_data = {
        "mfa_enabled": False,
        "mfa_secret": None,
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
        assert data["mfa_enabled"] is False
    finally:
        app.dependency_overrides.clear()
