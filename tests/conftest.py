import base64
import os
import uuid
from collections.abc import AsyncGenerator, Generator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.security import HTTPBearer
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.middleware import RequestLoggingMiddleware
from app.routes.auth_route import limiter

########################################################################
# Constants
########################################################################

TEST_USER_ID = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
TEST_EMAIL = "test@example.com"
TEST_AUTH_SALT = b"salt1234567890ab"
TEST_AUTH_VERIFIER = b"authverifier1234567890ab"
TEST_VAULT_SALT = b"vault_salt_12345"

TEST_AUTH_TAG = b"auth_tag_1234567"
TEST_ENCRYPTED_BLOB = b"encrypted_data_blob"
TEST_NONCE = b"random_nonce_123"

TEST_BASE_URL = "http://test"

########################################################################
# Utility functions
########################################################################


def encode_base64(data: bytes) -> str:
    """Helper to encode bytes to base64 string."""
    return base64.b64encode(data).decode("utf-8")


def create_mock_collection() -> MagicMock:
    """Create a dynamic mock collection."""
    mock = MagicMock()
    mock.find_one = AsyncMock()
    mock.insert_one = AsyncMock()
    mock.update_one = AsyncMock()
    mock.find_one_and_delete = AsyncMock()
    mock.create_indexes = AsyncMock()
    return mock


########################################################################
# Auto-Use Fixtures
########################################################################


@pytest.fixture(scope="session", autouse=True)
def load_test_env():
    """Load test environment variables."""
    from dotenv import load_dotenv

    load_dotenv(".env.test")


@pytest.fixture(autouse=True)
def mock_database() -> Generator[None]:
    """Mock the database for all tests."""

    # Create mock database and attach to app state
    mock_db = MagicMock()
    mock_collection = MagicMock()

    # Default to None so validators don't think a user exists
    mock_collection.find_one = AsyncMock(return_value=None)

    # Make insert_one return a realistic result object with a UUID inserted_id.
    # This prevents AsyncMock.insert_one() from returning an AsyncMock whose
    # `inserted_id` would also be an AsyncMock (which Pydantic can't coerce to UUID).
    mock_insert_result = MagicMock()
    mock_insert_result.inserted_id: UUID = uuid.uuid4()
    mock_collection.insert_one = AsyncMock(return_value=mock_insert_result)

    # Other DB methods used by tests/routes
    mock_collection.update_one = AsyncMock()
    mock_collection.find_one_and_delete = AsyncMock()

    mock_db.__getitem__ = MagicMock(return_value=mock_collection)
    app.state.db: MagicMock = mock_db

    yield

    # Clean
    if hasattr(app.state, "db"):
        delattr(app.state, "db")


bearer_scheme = HTTPBearer(auto_error=True)


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> Generator[None]:
    """Reset the rate limiter before each test."""
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def validate_env() -> None:
    required_vars = [
        "MONGODB_URL",
        "DATABASE_NAME",
        "JWT_SECRET",
        "JWT_ALGORITHM",
        "ISSUER",
        "ACCESS_TOKEN_EXP_MINUTES",
        "REFRESH_TOKEN_EXP_DAYS",
        "MAIL_SECRET",
        "MAIL_USERNAME",
        "MAIL_PASSWORD",
        "MAIL_FROM",
        "MAIL_SERVER",
        "MAIL_PORT",
    ]

    for var in required_vars:
        assert os.getenv(var), f"Environment variable {var} is not set"


########################################################################
# Sample Data Fixtures
########################################################################


@pytest.fixture
def sample_user_id() -> uuid.UUID:
    """Return a sample user UUID."""
    return TEST_USER_ID


@pytest.fixture
def sample_vault_data() -> dict:
    """Return sample vault creation data with base64 encoding."""
    return {
        "encryptedBlob": encode_base64(TEST_ENCRYPTED_BLOB),
        "nonce": encode_base64(TEST_NONCE),
        "authTag": encode_base64(TEST_AUTH_TAG),
    }


@pytest.fixture
def sample_register_payload(sample_vault_data: dict) -> dict:
    """Return sample registration payload (alias for sample_user_data)."""
    return {
        "email": TEST_EMAIL,
        "authSalt": encode_base64(TEST_AUTH_SALT),
        "authVerifier": encode_base64(TEST_AUTH_VERIFIER),
        "vaultSalt": encode_base64(TEST_VAULT_SALT),
        "vault": sample_vault_data,
    }


########################################################################
# Mock Collections
########################################################################


@pytest.fixture
def mock_user_collection() -> MagicMock:
    """Fixture for mock user collection."""
    return create_mock_collection()


@pytest.fixture
def mock_refresh_token_collection() -> MagicMock:
    """Fixture for mock refresh token collection."""
    return create_mock_collection()


@pytest.fixture
def mock_nonce_collection() -> MagicMock:
    """Fixture for mock nonce collection."""
    return create_mock_collection()


########################################################################
# Mock Model Fixtures
########################################################################


@pytest.fixture
def mock_user(sample_user_id: UUID, mock_vault_object: dict) -> dict:
    """Return a complete mock user object as stored in MongoDB."""
    return {
        "_id": sample_user_id,
        "email": TEST_EMAIL,
        "authSalt": TEST_AUTH_SALT,  # 16 bytes
        "authVerifier": TEST_AUTH_VERIFIER,  # 24 bytes
        "mfaEnabled": False,
        "mfaSecret": None,
        "shamirEnabled": False,
        "emailVerified": True,
        "vaultSalt": TEST_VAULT_SALT,
        "vault": mock_vault_object,
        "createdAtUtc": datetime.now(UTC),
        "updatedAtUtc": datetime.now(UTC),
    }


@pytest.fixture
def mock_user_with_mfa(mock_user: dict, mfa_secret: str) -> dict:
    """Return a mock user object with MFA enabled."""
    mock_user.update({"mfaEnabled": True, "mfaSecret": mfa_secret})
    return mock_user


@pytest.fixture
def mock_vault_object() -> dict:
    """Return a properly structured mock vault object (as stored in MongoDB)."""
    return {
        "encryptedBlob": TEST_ENCRYPTED_BLOB,
        "nonce": TEST_NONCE,  # 16 bytes
        "authTag": TEST_AUTH_TAG,  # 16 bytes
    }


@pytest.fixture
def mock_request() -> MagicMock:
    """Create a mock request object with app.state.db for validator tests."""
    mock_req = MagicMock()
    mock_req.app.state.db = MagicMock()
    mock_collection = AsyncMock()
    mock_collection.find_one = AsyncMock()
    mock_collection.insert_one = AsyncMock()
    mock_collection.update_one = AsyncMock()
    mock_collection.find_one_and_delete = AsyncMock()
    mock_req.app.state.db.__getitem__ = MagicMock(return_value=mock_collection)
    return mock_req


########################################################################
# Authentication Fixtures
########################################################################


@pytest.fixture(params=["valid", "expired", "invalid", "wrong_issuer"])
def token(request, sample_user_id):
    """Return different types of tokens based on the parameter."""
    from datetime import UTC, datetime, timedelta

    import jwt

    payload: dict = {
        "sub": str(sample_user_id),
        "iss": os.getenv("ISSUER"),
        "iat": datetime.now(UTC),
    }

    if request.param == "valid":
        payload["exp"] = datetime.now(UTC) + timedelta(hours=1)
    elif request.param == "expired":
        payload["exp"] = datetime.now(UTC) - timedelta(hours=1)
    elif request.param == "invalid":
        return "invalid.jwt.token"
    elif request.param == "wrong_issuer":
        payload["iss"] = "wrong-issuer"
        payload["exp"] = datetime.now(UTC) + timedelta(hours=1)

    return jwt.encode(payload, os.getenv("JWT_SECRET"), algorithm=os.getenv("JWT_ALGORITHM"))


@pytest.fixture
def auth_headers(token: str) -> dict[str, str]:
    """Return headers with valid Bearer token for authenticated requests."""
    return {"Authorization": f"Bearer {token}"}


########################################################################
# MFA Fixtures
########################################################################


@pytest.fixture
def mfa_secret() -> str:
    """Return a valid TOTP secret for MFA testing."""
    import pyotp

    return pyotp.random_base32()


@pytest.fixture
def valid_mfa_code(mfa_secret: str) -> str:
    """Generate a valid MFA code for the given secret."""
    import pyotp

    totp = pyotp.TOTP(mfa_secret)
    return totp.now()


########################################################################
# Logging Fixtures
########################################################################


@pytest.fixture
def app_with_logging() -> FastAPI:
    """Create a FastAPI app with logging middleware for testing."""
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)  # type: ignore[arg-type]

    @app.get("/test-get")
    async def test_get() -> dict:
        return {"message": "GET success"}

    @app.post("/test-post")
    async def test_post(data: dict) -> dict:
        return {"message": "POST success", "received": data}

    @app.get("/test-no-client")
    async def test_no_client() -> dict:
        return {"message": "No client info"}

    @app.post("/test-binary")
    async def test_binary() -> dict:
        return {"message": "Binary data received"}

    @app.get("/test-error")
    async def test_error() -> None:
        raise ValueError("Test error")

    return app


########################################################################
# Client Fixtures
########################################################################


@pytest.fixture
async def async_client(auth_headers: dict[str, str]) -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing with authentication headers."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=TEST_BASE_URL, headers=auth_headers
    ) as client:
        yield client


@pytest.fixture
async def async_client_no_auth() -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing without authentication."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url=TEST_BASE_URL) as client:
        yield client
