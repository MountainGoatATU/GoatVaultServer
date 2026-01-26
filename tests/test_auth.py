import base64
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status

from app.database import get_user_collection
from app.main import app
from app.utils.validators import validate_email_available


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
        response = await async_client_no_auth.post("/v1/auth/register", json=sample_user_data)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == sample_user_data["email"]
        assert "_id" in data or "id" in data
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client_no_auth, sample_user_data, mock_user) -> None:
    """Test registering a user with an email that already exists."""

    # Configure app.state.db mock to return existing user for validator
    mock_collection = AsyncMock()
    mock_collection.find_one = AsyncMock(return_value=mock_user)

    # Update the mock_database fixture's collection for this test
    app.state.db.__getitem__.return_value = mock_collection

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
        assert "auth_salt" in data
        assert "mfa_enabled" in data
    finally:
        app.dependency_overrides.clear()
        assert not data["mfa_enabled"]


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

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


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

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=test_mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        token = data["access_token"]
        assert len(token) > 0
    finally:
        app.dependency_overrides.clear()
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

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=None)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_404_NOT_FOUND
    finally:
        app.dependency_overrides.clear()
        assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_verify_invalid_verifier(async_client_no_auth, mock_user) -> None:
    """Test verifying auth with incorrect auth_verifier."""
    verify_request = {
        "_id": str(mock_user["_id"]),
        "auth_verifier": base64.b64encode(b"wrongverifier1234567890ab").decode("utf-8"),
    }

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    finally:
        app.dependency_overrides.clear()
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

    def override_get_user_collection():
        mock = AsyncMock()
        mock.find_one = AsyncMock(return_value=mock_user)
        return mock

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    try:
        # Generate token via verify
        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)
        assert response.status_code == status.HTTP_200_OK
        token = response.json()["access_token"]

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


@pytest.mark.asyncio
async def test_auth_endpoints_no_auth_required(
    async_client_no_auth, mock_user, sample_user_data
) -> None:
    """Test that auth endpoints do not require authentication."""

    # Register endpoint
    def override_get_user_collection():
        mock = AsyncMock()
        mock_result = MagicMock()
        mock_result.inserted_id = uuid.uuid4()
        mock.insert_one = AsyncMock(return_value=mock_result)
        mock.find_one = AsyncMock(return_value=mock_user)
        return mock

    async def mock_validate_email(email: str, request):
        pass  # Email is available

    app.dependency_overrides[get_user_collection] = override_get_user_collection
    app.dependency_overrides[validate_email_available] = mock_validate_email
    try:
        # Test register endpoint
        response = await async_client_no_auth.post("/v1/auth/register", json=sample_user_data)
        assert response.status_code == status.HTTP_200_OK

        # Test init endpoint
        response = await async_client_no_auth.post(
            "/v1/auth/init",
            json={"email": mock_user["email"]},
        )
        assert response.status_code == status.HTTP_200_OK

        # Test verify endpoint
        verify_request = {
            "_id": str(mock_user["_id"]),
            "auth_verifier": base64.b64encode(mock_user["auth_verifier"]).decode("utf-8"),
        }

        response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)
        assert response.status_code == status.HTTP_200_OK
    finally:
        app.dependency_overrides.clear()


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
        # Step 1: Register
        register_response = await async_client_no_auth.post(
            "/v1/auth/register",
            json=sample_user_data,
        )

        assert register_response.status_code == status.HTTP_200_OK
        assert "email" in register_response.json()

        # Step 2: Init (get user's auth_salt and vault)
        init_response = await async_client_no_auth.post(
            "/v1/auth/init",
            json={"email": sample_user_data["email"]},
        )

        assert init_response.status_code == status.HTTP_200_OK
        init_data = init_response.json()
        assert "auth_salt" in init_data
        assert init_data["_id"] == str(created_user["_id"])

        # Step 3: Verify (get JWT token)
        verify_request = {
            "_id": str(created_user["_id"]),
            "auth_verifier": sample_user_data["auth_verifier"],
        }

        verify_response = await async_client_no_auth.post("/v1/auth/verify", json=verify_request)

        assert verify_response.status_code == status.HTTP_200_OK
        verify_data = verify_response.json()
        assert "access_token" in verify_data
        assert len(verify_data["access_token"]) > 0
        assert verify_data["token_type"] == "bearer"

        # Step 4: Use token to access protected endpoint
        token = verify_data["access_token"]

        user_response = await async_client_no_auth.get(
            f"/v1/users/{new_user_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert user_response.status_code == status.HTTP_200_OK
        user_response_data = user_response.json()
        user_id = user_response_data.get("id") or user_response_data.get("_id")
        assert user_id == str(new_user_id)
        assert user_response_data["email"] == sample_user_data["email"]
    finally:
        app.dependency_overrides.clear()


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
