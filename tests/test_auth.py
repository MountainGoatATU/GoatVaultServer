import base64
import hmac
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status

from app.database import get_nonce_collection, get_user_collection
from app.main import app
from app.utils import validate_email_available

########################################################################
# Register Tests
########################################################################


@pytest.mark.asyncio
async def test_register_success(
    async_client_no_auth, sample_register_payload, mock_vault_object
) -> None:
    """Test successfully registering a new user."""
    new_user_id = uuid.uuid4()
    created_user = {
        "_id": new_user_id,
        "email": sample_register_payload["email"],
        "authSalt": base64.b64decode(sample_register_payload["authSalt"]),
        "authVerifier": base64.b64decode(sample_register_payload["authVerifier"]),
        "mfaEnabled": False,
        "mfaSecret": None,
        "shamirEnabled": False,
        "emailVerified": False,
        "vaultSalt": base64.b64decode(sample_register_payload["vaultSalt"]),
        "vault": mock_vault_object,
        "createdAtUtc": datetime.now(UTC),
        "updatedAtUtc": datetime.now(UTC),
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock_result = MagicMock()
        mock_result.inserted_id = new_user_id
        mock.insert_one = AsyncMock(return_value=mock_result)
        mock.find_one = AsyncMock(return_value=created_user)
        return mock

    async def mock_validate_email(email: str, request):
        pass  # Email is available

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[validate_email_available] = mock_validate_email
    try:
        response = await async_client_no_auth.post(
            "/v1/auth/register", json=sample_register_payload
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["email"] == sample_register_payload["email"]
        assert "_id" in data or "id" in data
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_duplicate_email(
    async_client_no_auth, sample_register_payload, mock_user
) -> None:
    """Test registering a user with an email that already exists."""

    # Configure app.state.db mock to return existing user for validator
    mock_collection = AsyncMock()
    mock_collection.find_one = AsyncMock(return_value=mock_user)

    # Update the mock_database fixture's collection for this test
    app.state.db.__getitem__.return_value = mock_collection

    response = await async_client_no_auth.post("/v1/auth/register", json=sample_register_payload)

    assert response.status_code == status.HTTP_409_CONFLICT


@pytest.mark.asyncio
async def test_register_invalid_email(async_client_no_auth, sample_register_payload) -> None:
    """Test registering with invalid email format."""
    invalid_data = sample_register_payload.copy()
    invalid_data["email"] = "not-an-email"

    response = await async_client_no_auth.post("/v1/auth/register", json=invalid_data)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_register_missing_fields(async_client_no_auth) -> None:
    """Test registering with missing required fields."""
    response = await async_client_no_auth.post("/v1/auth/register", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_register_creation_failure(async_client_no_auth, sample_register_payload):
    """Test user registration when database insert fails."""

    def override_get_user_collection():
        mock = AsyncMock()
        # Mock successful insert but failed retrieval
        mock_result = MagicMock()
        mock_result.inserted_id = uuid.uuid4()
        mock.insert_one = AsyncMock(return_value=mock_result)
        mock.find_one = AsyncMock(return_value=None)  # Fails to find created user
        return mock

    async def mock_validate_email(email: str, request):
        pass  # Email is available

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[validate_email_available] = mock_validate_email
    try:
        response = await async_client_no_auth.post(
            "/v1/auth/register", json=sample_register_payload
        )

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Failed to create user" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


########################################################################
# Init Tests
########################################################################


@pytest.mark.asyncio
async def test_init_success(async_client_no_auth, mock_user) -> None:
    """Test successfully initializing auth flow by getting user salt and vault."""
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
        assert data["_id"] == str(mock_user["_id"])
        assert "authSalt" in data
        assert "mfaEnabled" in data
    finally:
        app.dependency_overrides.clear()
        assert not data["mfaEnabled"]


@pytest.mark.asyncio
async def test_init_user_not_found(async_client_no_auth) -> None:
    """Test initializing auth for non-existent user."""
    init_request = {"email": "nonexistent@example.com"}

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=None)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "authSalt" in data
        assert "nonce" in data
        assert data["mfaEnabled"] is False

    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_init_invalid_email(async_client_no_auth) -> None:
    """Test initializing auth with invalid email format."""
    init_request = {"email": "not-an-email"}

    response = await async_client_no_auth.post("/v1/auth/init", json=init_request)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


########################################################################
# Verify Tests
########################################################################


@pytest.mark.asyncio
async def test_verify_success(async_client_no_auth, mock_user) -> None:
    """Test successfully verifying auth and getting JWT token."""
    # Mock nonce and compute proof
    nonce = b"random_nonce_12345"
    proof = hmac.new(key=mock_user["authVerifier"], msg=nonce, digestmod=sha256).digest()

    verify_request = {
        "_id": str(mock_user["_id"]),
        "proof": base64.b64encode(proof).decode("utf-8"),
    }

    # Update mock_user to have matching auth_verifier after pydantic processes the request
    test_mock_user = mock_user.copy()
    test_mock_user["authVerifier"] = mock_user["authVerifier"]
    test_mock_user["emailVerified"] = True

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=test_mock_user)
        return mock

    def override_get_nonce_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(
            return_value={
                "_id": "mock_nonce_id",
                "nonce": nonce,
                "expiresAtUtc": datetime.now(UTC) + timedelta(minutes=5),
            }
        )
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[get_nonce_collection] = override_get_nonce_collection

    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "accessToken" in data
        token = data["accessToken"]
        assert len(token) > 0
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_user_not_found(async_client_no_auth, sample_user_id) -> None:
    """Test verifying auth for non-existent user."""
    # Mock nonce and compute proof
    nonce = b"random_nonce_12345"
    proof = hmac.new(key=b"authverifier1234567890ab", msg=nonce, digestmod=sha256).digest()

    verify_request = {
        "_id": str(sample_user_id),
        "proof": base64.b64encode(proof).decode("utf-8"),
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=None)  # Simulate user not found
        return mock

    def override_get_nonce_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(
            return_value={
                "_id": "mock_nonce_id",
                "nonce": nonce,
                "expiresAtUtc": datetime.now(UTC) + timedelta(minutes=5),
            }
        )
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[get_nonce_collection] = override_get_nonce_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_invalid_verifier(async_client_no_auth, mock_user) -> None:
    """Test verifying auth with incorrect auth_verifier."""
    # Mock nonce and compute proof with an invalid auth_verifier
    nonce = b"random_nonce_12345"
    invalid_auth_verifier = b"wrongverifier1234567890ab"
    proof = hmac.new(key=invalid_auth_verifier, msg=nonce, digestmod=sha256).digest()

    verify_request = {
        "_id": str(mock_user["_id"]),
        "proof": base64.b64encode(proof).decode("utf-8"),
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user)  # Simulate valid user
        return mock

    def override_get_nonce_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(
            return_value={
                "_id": "mock_nonce_id",
                "nonce": nonce,
                "expiresAtUtc": datetime.now(UTC) + timedelta(minutes=5),
            }
        )
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[get_nonce_collection] = override_get_nonce_collection

    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_invalid_uuid(async_client_no_auth) -> None:
    """Test verifying auth with invalid UUID format."""
    verify_request = {
        "_id": "not-a-valid-uuid",
        "authVerifier": base64.b64encode(b"authverifier1234567890ab").decode("utf-8"),
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
        json={"authVerifier": base64.b64encode(b"authverifier1234567890ab").decode("utf-8")},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # Missing both
    response = await async_client_no_auth.post("/v1/auth/verify", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


########################################################################
# Proof Tests
########################################################################


@pytest.mark.asyncio
async def test_generated_token_can_be_used_for_auth(async_client_no_auth, mock_user) -> None:
    """Test that token from verify endpoint can be used for authenticated requests."""
    # Mock nonce and compute proof
    nonce = b"random_nonce_12345"
    proof: bytes = hmac.new(key=mock_user["authVerifier"], msg=nonce, digestmod=sha256).digest()

    verify_request: dict = {
        "_id": str(mock_user["_id"]),
        "proof": base64.b64encode(proof).decode("utf-8"),
    }

    test_mock_user = mock_user.copy()
    test_mock_user["emailVerified"] = True

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=test_mock_user)
        return mock

    def override_get_nonce_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(
            return_value={
                "_id": "mock_nonce_id",
                "nonce": nonce,
                "expiresAtUtc": datetime.now(UTC) + timedelta(minutes=5),
            }
        )
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[get_nonce_collection] = override_get_nonce_collection
    try:
        # Generate token via verify
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)
        assert response.status_code == status.HTTP_200_OK
        token = response.json()["accessToken"]

        # Try to use the token for an authenticated request
        auth_response = await async_client_no_auth.get(
            f"/v1/users/{mock_user['_id']}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert auth_response.status_code == status.HTTP_200_OK
        data = auth_response.json()
        assert data["_id"] == str(mock_user["_id"])
        assert data["email"] == "test@example.com"
    finally:
        app.dependency_overrides.clear()
