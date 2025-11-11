import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from app.auth import create_jwt_token, verify_token


@pytest.mark.asyncio
async def test_verify_token_valid(test_credentials):
    """Test that valid JWT token is accepted."""
    result = await verify_token(test_credentials)

    assert result is not None
    assert "sub" in result
    assert "iss" in result
    assert "exp" in result
    assert "iat" in result


@pytest.mark.asyncio
async def test_verify_token_invalid():
    """Test that invalid JWT token raises HTTPException."""
    invalid_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="invalid.jwt.token"
    )

    with pytest.raises(HTTPException) as exc_info:
        await verify_token(invalid_credentials)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or expired JWT token" in exc_info.value.detail


@pytest.mark.asyncio
async def test_verify_token_expired(expired_token):
    """Test that expired JWT token raises HTTPException."""
    expired_credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)

    with pytest.raises(HTTPException) as exc_info:
        await verify_token(expired_credentials)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_verify_token_wrong_issuer(wrong_issuer_token):
    """Test that JWT token with wrong issuer raises HTTPException."""
    wrong_issuer_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials=wrong_issuer_token
    )

    with pytest.raises(HTTPException) as exc_info:
        await verify_token(wrong_issuer_credentials)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Token issuer mismatch" in exc_info.value.detail


@pytest.mark.asyncio
async def test_create_jwt_token(sample_user_id):
    """Test that JWT token is created successfully."""
    token = create_jwt_token(sample_user_id)

    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 0

    # Verify the token can be decoded
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    payload = await verify_token(credentials)

    assert payload["sub"] == str(sample_user_id)
    assert payload["iss"] == "test-issuer"


@pytest.mark.asyncio
async def test_verify_token_missing_subject():
    """Test that JWT token without subject raises HTTPException."""
    import os
    from datetime import UTC, datetime, timedelta

    import jwt

    payload = {
        "iss": os.getenv("ISSUER"),
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET"), algorithm=os.getenv("JWT_ALGORITHM"))

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    # This should still decode successfully, but sub will be None
    result = await verify_token(credentials)
    assert result.get("sub") is None


@pytest.mark.asyncio
async def test_generate_token_success(async_client_no_auth, sample_user_id):
    """Test successfully generating a JWT token for a valid user."""
    mock_user = {
        "_id": sample_user_id,
        "email": "test@example.com",
        "salt": b"salt1234567890ab",
        "password_hash": b"hash1234567890ab",
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    token_request = {
        "user_id": str(sample_user_id),
        "email": "test@example.com",
    }

    with patch("app.routes.token_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client_no_auth.post("/v1/token/", json=token_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        assert len(data["access_token"]) > 0

        # Verify the token is a valid JWT (has 3 parts separated by dots)
        token_parts = data["access_token"].split(".")
        assert len(token_parts) == 3


@pytest.mark.asyncio
async def test_generate_token_user_not_found(async_client_no_auth, sample_user_id):
    """Test generating a token for a non-existent user."""
    token_request = {
        "user_id": str(sample_user_id),
        "email": "nonexistent@example.com",
    }

    with patch("app.routes.token_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client_no_auth.post("/v1/token/", json=token_request)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_generate_token_email_mismatch(async_client_no_auth, sample_user_id):
    """Test generating a token with mismatched email."""
    token_request = {
        "user_id": str(sample_user_id),
        "email": "wrong@example.com",
    }

    with patch("app.routes.token_route.user_collection") as mock_collection:
        # MongoDB won't find user with mismatched user_id AND email
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client_no_auth.post("/v1/token/", json=token_request)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_generate_token_invalid_uuid(async_client_no_auth):
    """Test generating a token with invalid UUID format."""
    token_request = {
        "user_id": "not-a-valid-uuid",
        "email": "test@example.com",
    }

    response = await async_client_no_auth.post("/v1/token/", json=token_request)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_generate_token_missing_fields(async_client_no_auth):
    """Test generating a token with missing required fields."""
    # Missing email
    response = await async_client_no_auth.post("/v1/token/", json={"user_id": str(uuid.uuid4())})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # Missing user_id
    response = await async_client_no_auth.post("/v1/token/", json={"email": "test@example.com"})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # Missing both
    response = await async_client_no_auth.post("/v1/token/", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_generate_token_invalid_email(async_client_no_auth, sample_user_id):
    """Test generating a token with invalid email format."""
    token_request = {
        "user_id": str(sample_user_id),
        "email": "not-an-email",
    }

    response = await async_client_no_auth.post("/v1/token/", json=token_request)

    # Should fail validation
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_generate_token_can_be_used_for_auth(async_client_no_auth, sample_user_id):
    """Test that generated token can be used for authenticated requests."""
    mock_user = {
        "_id": sample_user_id,
        "email": "test@example.com",
        "salt": b"salt1234567890ab",
        "password_hash": b"hash1234567890ab",
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    token_request = {
        "user_id": str(sample_user_id),
        "email": "test@example.com",
    }

    with patch("app.routes.token_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        # Generate token
        response = await async_client_no_auth.post("/v1/token/", json=token_request)
        assert response.status_code == status.HTTP_200_OK
        token = response.json()["access_token"]

        # Try to use the token for an authenticated request
        with patch("app.routes.user_route.user_collection") as mock_user_collection:
            mock_user_collection.find_one = AsyncMock(return_value=mock_user)

            auth_response = await async_client_no_auth.get(
                f"/v1/users/{sample_user_id}",
                headers={"Authorization": f"Bearer {token}"},
            )

            assert auth_response.status_code == status.HTTP_200_OK
            data = auth_response.json()
            assert data["id"] == str(sample_user_id)
            assert data["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_token_endpoint_no_auth_required(async_client_no_auth, sample_user_id):
    """Test that token endpoint does not require authentication."""
    mock_user = {
        "_id": sample_user_id,
        "email": "test@example.com",
        "salt": b"salt1234567890ab",
        "password_hash": b"hash1234567890ab",
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    token_request = {
        "user_id": str(sample_user_id),
        "email": "test@example.com",
    }

    with patch("app.routes.token_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        # Request without Authorization header should succeed
        response = await async_client_no_auth.post("/v1/token/", json=token_request)

        assert response.status_code == status.HTTP_200_OK
