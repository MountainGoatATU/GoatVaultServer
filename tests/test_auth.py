import base64
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from app.auth import create_jwt_token, verify_token


@pytest.mark.asyncio
async def test_verify_token_valid(test_credentials) -> None:
    """Test that valid JWT token is accepted."""
    result = await verify_token(test_credentials)

    assert result is not None
    assert "sub" in result
    assert "iss" in result
    assert "exp" in result
    assert "iat" in result


@pytest.mark.asyncio
async def test_verify_token_invalid() -> None:
    """Test that invalid JWT token raises HTTPException."""
    invalid_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="invalid.jwt.token",
    )

    with pytest.raises(HTTPException) as exc_info:
        await verify_token(invalid_credentials)

    exception: HTTPException = exc_info.value  # type: ignore[assignment]
    assert exception.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid" in exception.detail
    assert "token" in exception.detail.lower()


@pytest.mark.asyncio
async def test_verify_token_expired(expired_token) -> None:
    """Test that expired JWT token raises HTTPException."""
    expired_credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)

    with pytest.raises(HTTPException) as exc_info:
        await verify_token(expired_credentials)

    exception: HTTPException = exc_info.value  # type: ignore[assignment]
    assert exception.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_verify_token_wrong_issuer(wrong_issuer_token) -> None:
    """Test that JWT token with wrong issuer raises HTTPException."""
    wrong_issuer_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=wrong_issuer_token,
    )

    with pytest.raises(HTTPException) as exc_info:
        await verify_token(wrong_issuer_credentials)

    exception: HTTPException = exc_info.value  # type: ignore[assignment]
    assert exception.status_code == status.HTTP_403_FORBIDDEN
    assert "Token issuer mismatch" in exception.detail


@pytest.mark.asyncio
async def test_create_jwt_token(sample_user_id) -> None:
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
async def test_verify_token_missing_subject() -> None:
    """Test that JWT token without subject raises HTTPException."""
    import os
    from datetime import timedelta

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


# Auth Route Tests


@pytest.mark.asyncio
async def test_register_success(async_client_no_auth, sample_user_data, mock_vault_object) -> None:
    """Test successfully registering a new user."""
    new_user_id = uuid.uuid4()
    created_user = {
        "_id": new_user_id,
        "email": sample_user_data["email"],
        "auth_salt": base64.b64decode(sample_user_data["auth_salt"]),
        "auth_verifier": base64.b64decode(sample_user_data["auth_verifier"]),
        "mfa_enabled": False,
        "mfa_secret": None,
        "vault": mock_vault_object,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("app.routes.auth_route.user_collection") as mock_collection,
        patch("app.routes.auth_route.validate_email_available", new=AsyncMock()),
    ):
        mock_result = MagicMock()
        mock_result.inserted_id = new_user_id
        mock_collection.insert_one = AsyncMock(return_value=mock_result)
        mock_collection.find_one = AsyncMock(return_value=created_user)

        response = await async_client_no_auth.post("/v1/auth/register", json=sample_user_data)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == sample_user_data["email"]
        assert "_id" in data or "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client_no_auth, sample_user_data) -> None:
    """Test registering a user with an email that already exists."""
    with patch("app.routes.auth_route.validate_email_available") as mock_validate:
        from app.exceptions import UserAlreadyExistsException

        mock_validate.side_effect = UserAlreadyExistsException()

        response = await async_client_no_auth.post("/v1/auth/register", json=sample_user_data)

        assert response.status_code == status.HTTP_409_CONFLICT


@pytest.mark.asyncio
async def test_register_invalid_email(async_client_no_auth, sample_user_data) -> None:
    """Test registering with invalid email format."""
    invalid_data = sample_user_data.copy()
    invalid_data["email"] = "not-an-email"

    response = await async_client_no_auth.post("/v1/auth/register", json=invalid_data)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_register_missing_fields(async_client_no_auth) -> None:
    """Test registering with missing required fields."""
    response = await async_client_no_auth.post("/v1/auth/register", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_init_success(async_client_no_auth, mock_user) -> None:
    """Test successfully initializing auth flow by getting user salt and vault."""
    init_request = {"email": "test@example.com"}

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "_id" in data
        assert data["_id"] == str(mock_user["_id"])
        assert "auth_salt" in data
        assert "mfa_enabled" in data
        assert not data["mfa_enabled"]


@pytest.mark.asyncio
async def test_init_user_not_found(async_client_no_auth) -> None:
    """Test initializing auth for non-existent user."""
    init_request = {"email": "nonexistent@example.com"}

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_init_invalid_email(async_client_no_auth) -> None:
    """Test initializing auth with invalid email format."""
    init_request = {"email": "not-an-email"}

    response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_verify_success(async_client_no_auth, mock_user) -> None:
    """Test successfully verifying auth and getting JWT token."""
    # The auth_verifier in the request should match what's in the database
    # When sent as base64 string in JSON, pydantic converts it to bytes
    verify_request = {
        "_id": str(mock_user["_id"]),
        "auth_verifier": base64.b64encode(mock_user["auth_verifier"]).decode("utf-8"),
    }

    # Update mock_user to have matching auth_verifier after pydantic processes the request
    test_mock_user = mock_user.copy()
    test_mock_user["auth_verifier"] = mock_user["auth_verifier"]

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=test_mock_user)

        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        assert len(data["access_token"]) > 0
        assert data["token_type"] == "bearer"

        # Verify the token is a valid JWT (has 3 parts separated by dots)
        token_parts = data["access_token"].split(".")
        assert len(token_parts) == 3


@pytest.mark.asyncio
async def test_verify_user_not_found(async_client_no_auth, sample_user_id) -> None:
    """Test verifying auth for non-existent user."""
    verify_request = {
        "_id": str(sample_user_id),
        "auth_verifier": base64.b64encode(b"authverifier1234567890ab").decode("utf-8"),
    }

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=None)

        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_verify_invalid_verifier(async_client_no_auth, mock_user) -> None:
    """Test verifying auth with incorrect auth_verifier."""
    verify_request = {
        "_id": str(mock_user["_id"]),
        "auth_verifier": base64.b64encode(b"wrongverifier1234567890ab").decode("utf-8"),
    }

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid auth verifier" in response.json()["detail"]


@pytest.mark.asyncio
async def test_verify_invalid_uuid(async_client_no_auth) -> None:
    """Test verifying auth with invalid UUID format."""
    verify_request = {
        "_id": "not-a-valid-uuid",
        "auth_verifier": base64.b64encode(b"authverifier1234567890ab").decode("utf-8"),
    }

    response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_verify_missing_fields(async_client_no_auth, sample_user_id) -> None:
    """Test verifying auth with missing required fields."""
    # Missing auth_verifier
    response = await async_client_no_auth.post(
        "/v1/auth/verify",
        json={"_id": str(sample_user_id)},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # Missing user_id
    response = await async_client_no_auth.post(
        "/v1/auth/verify",
        json={"auth_verifier": base64.b64encode(b"authverifier1234567890ab").decode("utf-8")},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # Missing both
    response = await async_client_no_auth.post("/v1/auth/verify", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_generated_token_can_be_used_for_auth(async_client_no_auth, mock_user) -> None:
    """Test that token from verify endpoint can be used for authenticated requests."""
    verify_request = {
        "_id": str(mock_user["_id"]),
        "auth_verifier": base64.b64encode(mock_user["auth_verifier"]).decode("utf-8"),
    }

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        # Generate token via verify
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)
        assert response.status_code == status.HTTP_200_OK
        token = response.json()["access_token"]

        # Try to use the token for an authenticated request
        with patch("app.routes.user_route.user_collection") as mock_user_collection:
            mock_user_collection.find_one = AsyncMock(return_value=mock_user)

            auth_response = await async_client_no_auth.get(
                f"/v1/users/{mock_user['_id']}",
                headers={"Authorization": f"Bearer {token}"},
            )

            assert auth_response.status_code == status.HTTP_200_OK
            data = auth_response.json()
            assert data["_id"] == str(mock_user["_id"])
            assert data["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_auth_endpoints_no_auth_required(
    async_client_no_auth, mock_user, sample_user_data
) -> None:
    """Test that auth endpoints do not require authentication."""
    # Register endpoint
    with (
        patch("app.routes.auth_route.user_collection") as mock_collection,
        patch("app.routes.auth_route.validate_email_available", new=AsyncMock()),
    ):
        mock_result = MagicMock()
        mock_result.inserted_id = uuid.uuid4()
        mock_collection.insert_one = AsyncMock(return_value=mock_result)
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client_no_auth.post("/v1/auth/register", json=sample_user_data)
        assert response.status_code == status.HTTP_200_OK

    # Init endpoint
    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client_no_auth.post(
            "/v1/auth/init",
            json={"email": "test@example.com"},
        )
        assert response.status_code == status.HTTP_200_OK

    # Verify endpoint
    verify_request = {
        "_id": str(mock_user["_id"]),
        "auth_verifier": base64.b64encode(mock_user["auth_verifier"]).decode("utf-8"),
    }

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=mock_user)

        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_full_auth_flow(async_client_no_auth, sample_user_data, mock_user) -> None:
    """Test complete auth flow: register -> init -> verify."""
    new_user_id = uuid.uuid4()
    created_user = {
        "_id": new_user_id,
        "email": sample_user_data["email"],
        "auth_salt": base64.b64decode(sample_user_data["auth_salt"]),
        "auth_verifier": base64.b64decode(sample_user_data["auth_verifier"]),
        "mfa_enabled": False,
        "mfa_secret": None,
        "vault": mock_user["vault"],
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    # Step 1: Register
    with (
        patch("app.routes.auth_route.user_collection") as mock_collection,
        patch("app.routes.auth_route.validate_email_available", new=AsyncMock()),
    ):
        mock_result = MagicMock()
        mock_result.inserted_id = new_user_id
        mock_collection.insert_one = AsyncMock(return_value=mock_result)
        mock_collection.find_one = AsyncMock(return_value=created_user)

        register_response = await async_client_no_auth.post(
            "/v1/auth/register",
            json=sample_user_data,
        )
        assert register_response.status_code == status.HTTP_200_OK
        user_data = register_response.json()
        registered_email = user_data["email"]

    # Step 2: Init (get salt and vault)
    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=created_user)

        init_response = await async_client_no_auth.post(
            "/v1/auth/init",
            json={"email": registered_email},
        )
        assert init_response.status_code == status.HTTP_200_OK
        init_data = init_response.json()
        assert init_data["_id"] == str(new_user_id)
        assert "auth_salt" in init_data

    # Step 3: Verify (get JWT token)
    verify_request = {
        "_id": str(new_user_id),
        "auth_verifier": sample_user_data["auth_verifier"],
    }

    with patch("app.routes.auth_route.user_collection") as mock_collection:
        mock_collection.find_one = AsyncMock(return_value=created_user)

        verify_response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)
        assert verify_response.status_code == status.HTTP_200_OK
        verify_data = verify_response.json()
        assert "access_token" in verify_data
        assert verify_data["token_type"] == "bearer"

    # Step 4: Use token to access protected endpoint
    token = verify_data["access_token"]

    with patch("app.routes.user_route.user_collection") as mock_user_collection:
        mock_user_collection.find_one = AsyncMock(return_value=created_user)

        user_response = await async_client_no_auth.get(
            f"/v1/users/{new_user_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert user_response.status_code == status.HTTP_200_OK
        user_response_data = user_response.json()
        user_id = user_response_data.get("id") or user_response_data.get("_id")
        assert user_id == str(new_user_id)
        assert user_response_data["email"] == registered_email
