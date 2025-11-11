import base64
import os
import uuid
from collections.abc import AsyncGenerator
from typing import Annotated
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from httpx import ASGITransport, AsyncClient

# Set test environment variables before importing app
os.environ["MONGODB_URL"] = "mongodb://localhost:27017"
os.environ["DATABASE_NAME"] = "test_goatvault"
os.environ["JWT_SECRET"] = "test-jwt-secret-12345"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ISSUER"] = "test-issuer"
os.environ["TOKEN_EXP_HOURS"] = "1"

from app.auth import create_jwt_token
from app.main import app

bearer_scheme = HTTPBearer(auto_error=True)


@pytest.fixture
def sample_user_id() -> uuid.UUID:
    """Return a sample user UUID."""
    return uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


@pytest.fixture
def sample_vault_id() -> uuid.UUID:
    """Return a sample vault UUID."""
    return uuid.UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")


@pytest.fixture
def test_token(sample_user_id: uuid.UUID) -> str:
    """Generate a valid JWT token for testing."""
    return create_jwt_token(sample_user_id)


@pytest.fixture
def test_credentials(test_token: str) -> HTTPAuthorizationCredentials:
    """Return HTTPAuthorizationCredentials with test token."""
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=test_token)


@pytest.fixture
def invalid_token() -> str:
    """Return an invalid JWT token for testing auth failures."""
    return "invalid.jwt.token"


@pytest.fixture
def expired_token() -> str:
    """Return an expired JWT token for testing."""
    from datetime import UTC, datetime, timedelta

    import jwt

    payload = {
        "sub": str(uuid.uuid4()),
        "iss": os.getenv("ISSUER"),
        "exp": datetime.now(UTC) - timedelta(hours=1),  # Expired 1 hour ago
        "iat": datetime.now(UTC) - timedelta(hours=2),
    }
    return jwt.encode(payload, os.getenv("JWT_SECRET"), algorithm=os.getenv("JWT_ALGORITHM"))


@pytest.fixture
def wrong_issuer_token(sample_user_id: uuid.UUID) -> str:
    """Return a JWT token with wrong issuer for testing."""
    from datetime import UTC, datetime, timedelta

    import jwt

    payload = {
        "sub": str(sample_user_id),
        "iss": "wrong-issuer",
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, os.getenv("JWT_SECRET"), algorithm=os.getenv("JWT_ALGORITHM"))


@pytest.fixture
def auth_headers(test_token: str) -> dict[str, str]:
    """Return headers with valid Bearer token for authenticated requests."""
    return {"Authorization": f"Bearer {test_token}"}


@pytest.fixture
def sample_user_data() -> dict:
    """Return sample user creation data (with base64 encoded bytes for JSON)."""
    return {
        "email": "test@example.com",
        "salt": base64.b64encode(b"random_salt_1234").decode("utf-8"),
        "password_hash": base64.b64encode(b"hashed_password_").decode("utf-8"),
    }


@pytest.fixture
def sample_vault_data() -> dict:
    """Return sample vault creation data (with base64 encoded bytes for JSON)."""
    return {
        "name": "My Test Vault",
        "salt": base64.b64encode(b"vault_salt_12345").decode("utf-8"),
        "encrypted_blob": base64.b64encode(b"encrypted_data_blob").decode("utf-8"),
        "nonce": base64.b64encode(b"random_nonce_123").decode("utf-8"),
        "auth_tag": base64.b64encode(b"auth_tag_1234567").decode("utf-8"),
    }


@pytest.fixture
async def async_client(
    auth_headers: dict[str, str],
) -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing with authentication headers."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers
    ) as client:
        yield client


@pytest.fixture
async def async_client_no_auth() -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing without authentication."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


@pytest.fixture
def mock_user_collection() -> MagicMock:
    """Create a mock user collection."""
    mock = MagicMock()
    mock.find_one = AsyncMock()
    mock.insert_one = AsyncMock()
    mock.update_one = AsyncMock()
    mock.find_one_and_delete = AsyncMock()
    mock.create_indexes = AsyncMock()
    return mock


@pytest.fixture
def mock_vault_collection() -> MagicMock:
    """Create a mock vault collection."""
    mock = MagicMock()
    mock.find = MagicMock()
    mock.find_one = AsyncMock()
    mock.insert_one = AsyncMock()
    mock.find_one_and_update = AsyncMock()
    mock.find_one_and_delete = AsyncMock()
    mock.delete_many = AsyncMock()
    mock.create_indexes = AsyncMock()
    return mock
