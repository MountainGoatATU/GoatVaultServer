import base64
import os
import uuid
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

# Set test environment variables before importing app
os.environ["MONGODB_URL"] = "mongodb://localhost:27017"
os.environ["DATABASE_NAME"] = "test_goatvault"
os.environ["API_KEY"] = "test-api-key-12345"

from app.main import app


@pytest.fixture
def test_api_key() -> str:
    """Return the test API key."""
    return "test-api-key-12345"


@pytest.fixture
def invalid_api_key() -> str:
    """Return an invalid API key for testing auth failures."""
    return "invalid-key"


@pytest.fixture
def api_headers(test_api_key: str) -> dict[str, str]:
    """Return headers with valid API key."""
    return {"X-API-Key": test_api_key}


@pytest.fixture
def sample_user_id() -> uuid.UUID:
    """Return a sample user UUID."""
    return uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


@pytest.fixture
def sample_vault_id() -> uuid.UUID:
    """Return a sample vault UUID."""
    return uuid.UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")


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
    api_headers: dict[str, str],
) -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=api_headers
    ) as client:
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
