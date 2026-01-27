import base64
import os
import uuid
from collections.abc import AsyncGenerator, Generator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from httpx import ASGITransport, AsyncClient

# Test environment variables
os.environ["MONGODB_URL"] = "mongodb://localhost:27017"
os.environ["DATABASE_NAME"] = "test_goatvault"
os.environ["JWT_SECRET"] = "test-jwt-secret-123456789abcdefg"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ISSUER"] = "test-issuer"
os.environ["TOKEN_EXP_HOURS"] = "1"

from app.main import app
from app.routes.auth_route import limiter
from app.utils import create_jwt_token

bearer_scheme = HTTPBearer(auto_error=True)


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


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> Generator[None]:
    """Reset the rate limiter before each test."""
    limiter.reset()
    yield
    limiter.reset()


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
    """Return a valid JWT token for testing."""
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
def mock_vault_object(sample_vault_id: uuid.UUID) -> dict:
    """Return a properly structured mock vault object (as stored in MongoDB)."""
    return {
        "_id": sample_vault_id,
        "vault_salt": b"vault_salt_12345",  # 16 bytes
        "encrypted_blob": b"encrypted_data_blob",
        "nonce": b"random_nonce_123",  # 16 bytes
        "auth_tag": b"auth_tag_1234567",  # 16 bytes
    }


@pytest.fixture
def sample_user_data(sample_vault_data: dict) -> dict:
    """Return sample user creation data (with base64 encoded bytes for JSON)."""
    return {
        "email": "test@example.com",
        "auth_salt": base64.b64encode(b"salt1234567890ab").decode("utf-8"),  # 16 bytes
        "auth_verifier": base64.b64encode(b"authverifier1234567890ab").decode("utf-8"),  # 24 bytes
        "vault": sample_vault_data,
    }


@pytest.fixture
def sample_vault_data() -> dict:
    """Return sample vault creation data (with base64 encoded bytes for JSON)."""
    return {
        "vault_salt": base64.b64encode(b"vault_salt_12345").decode("utf-8"),
        "encrypted_blob": base64.b64encode(b"encrypted_data_blob").decode("utf-8"),
        "nonce": base64.b64encode(b"random_nonce_123").decode("utf-8"),
        "auth_tag": base64.b64encode(b"auth_tag_1234567").decode("utf-8"),
    }


@pytest.fixture
def sample_register_payload(sample_vault_data: dict) -> dict:
    """Return sample registration payload (alias for sample_user_data)."""
    return {
        "email": "test@example.com",
        "auth_salt": base64.b64encode(b"salt1234567890ab").decode("utf-8"),
        "auth_verifier": base64.b64encode(b"authverifier1234567890ab").decode("utf-8"),
        "vault": sample_vault_data,
    }


@pytest.fixture
def mock_user(sample_user_id: uuid.UUID, mock_vault_object: dict) -> dict:
    """Return a complete mock user object as stored in MongoDB."""
    return {
        "_id": sample_user_id,
        "email": "test@example.com",
        "auth_salt": b"salt1234567890ab",  # 16 bytes
        "auth_verifier": b"authverifier1234567890ab",  # 24 bytes
        "mfa_enabled": False,
        "mfa_secret": None,
        "vault": mock_vault_object,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
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
def mfa_secret() -> str:
    """Return a valid TOTP secret for MFA testing."""
    import pyotp

    return pyotp.random_base32()


@pytest.fixture
def mock_user_with_mfa(sample_user_id: uuid.UUID, mock_vault_object: dict, mfa_secret: str) -> dict:
    """Return a complete mock user object with MFA enabled."""
    return {
        "_id": sample_user_id,
        "email": "mfa@example.com",
        "auth_salt": b"salt1234567890ab",
        "auth_verifier": b"authverifier1234567890ab",
        "mfa_enabled": True,
        "mfa_secret": mfa_secret,
        "vault": mock_vault_object,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }


@pytest.fixture
def valid_mfa_code(mfa_secret: str) -> str:
    """Generate a valid MFA code for the given secret."""
    import pyotp

    totp = pyotp.TOTP(mfa_secret)
    return totp.now()


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
