import base64
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient

from app.database import get_refresh_collection
from app.main import app
from app.models import RefreshRotationResult, RefreshTokenModel, TokenPayload
from app.utils import (
    create_jwt_token,
    create_refresh_token,
    hash_token,
    revoke_refresh_token,
    rotate_refresh_token,
    store_refresh_token,
    verify_refresh_token,
    verify_token,
)
from app.utils.auth import ensure_bytes


@pytest.mark.asyncio
async def test_verify_token_valid(test_credentials) -> None:
    """Test that valid JWT token is accepted."""
    result: TokenPayload = await verify_token(test_credentials)

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

    exception: HTTPException = exc_info.value
    assert exception.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid" in exception.detail
    assert "token" in exception.detail.lower()


@pytest.mark.asyncio
async def test_verify_token_expired(expired_token) -> None:
    """Test that expired JWT token raises HTTPException."""
    expired_credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)

    with pytest.raises(HTTPException) as exc_info:
        await verify_token(expired_credentials)

    exception: HTTPException = exc_info.value
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

    exception: HTTPException = exc_info.value
    assert exception.status_code == status.HTTP_403_FORBIDDEN
    assert "Token issuer mismatch" in exception.detail


@pytest.mark.asyncio
async def test_create_jwt_token(sample_user_id) -> None:
    """Test that JWT token is created successfully."""
    token: str = create_jwt_token(sample_user_id)

    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 0

    # Verify the token can be decoded
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    payload = await verify_token(credentials)

    assert payload.sub == sample_user_id
    assert payload.iss == "test-issuer"


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
    token: str = jwt.encode(payload, os.getenv("JWT_SECRET"), algorithm=os.getenv("JWT_ALGORITHM"))

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    # This should still decode successfully, but sub will be None
    with pytest.raises(HTTPException) as exc_info:
        await verify_token(credentials)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert (
        "missing required 'sub'" in str(exc_info.value.detail).lower()
        or "token missing" in str(exc_info.value.detail).lower()
    )


@pytest.mark.asyncio
async def test_store_and_verify_refresh_token() -> None:
    """Unit-level: store a refresh token and then verify it via the helper."""
    user_id: UUID = uuid.uuid4()
    raw: str = create_refresh_token()

    # Create a fake collection to capture/return inserted documents
    refresh_collection = AsyncMock()
    inserted_id: UUID = uuid.uuid4()
    mock_insert_result = MagicMock()
    mock_insert_result.inserted_id: UUID = inserted_id
    refresh_collection.insert_one = AsyncMock(return_value=mock_insert_result)

    # Call store_refresh_token; it will call insert_one on the collection
    stored_doc: RefreshTokenModel = await store_refresh_token(refresh_collection, user_id, raw)

    # Ensure the returned doc has _id set to the mocked inserted id
    assert stored_doc.id == inserted_id
    assert stored_doc.user_id == user_id

    # Now configure find_one to return the stored doc when verify_refresh_token is called
    refresh_collection.find_one = AsyncMock(return_value=stored_doc)

    # verify_refresh_token should now return the stored doc
    rec = await verify_refresh_token(refresh_collection, raw)
    assert rec is not None
    assert rec.id == inserted_id
    assert rec.user_id == user_id


@pytest.mark.asyncio
async def test_rotate_and_revoke_refresh_token() -> None:
    """Unit-level: rotating should revoke the old token and create a new one; revoke should mark revoked."""
    user_id = uuid.uuid4()
    old_raw = create_refresh_token()
    old_hash = hash_token(old_raw)

    # Build the record that verify_refresh_token should return for the old token
    old_rec = {
        "_id": uuid.uuid4(),
        "user_id": user_id,
        "token_hash": old_hash,
        "created_at": datetime.now(UTC),
        "expires_at": datetime.now(UTC) + timedelta(days=30),
        "revoked": False,
    }

    refresh_collection = AsyncMock()
    # verify_refresh_token uses find_one(token_hash)
    refresh_collection.find_one = AsyncMock(return_value=old_rec)
    # update_one used to mark revoked
    refresh_collection.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
    # insert_one used to store new token
    new_inserted_id = uuid.uuid4()
    mock_insert_result = MagicMock()
    mock_insert_result.inserted_id = new_inserted_id
    refresh_collection.insert_one = AsyncMock(return_value=mock_insert_result)

    # Call rotate_refresh_token - should return a dict with raw and record
    rotation: RefreshRotationResult | None = await rotate_refresh_token(
        refresh_collection, old_raw, user_id
    )

    assert rotation is not None
    assert hasattr(rotation, "raw") and hasattr(rotation, "record")
    assert rotation.record.id == new_inserted_id

    # Now test revoke_refresh_token
    # Configure update_one to pretend it updated one document
    refresh_collection.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
    ok = await revoke_refresh_token(refresh_collection, old_raw)
    assert ok is True


@pytest.mark.asyncio
async def test_refresh_and_logout_endpoints(async_client_no_auth: AsyncClient, monkeypatch) -> None:
    """Integration-ish: test /v1/auth/refresh and /v1/auth/logout endpoints using dependency overrides."""
    old_raw = "old-refresh-token-value"
    user_id = uuid.uuid4()

    # Prepare a dummy rotation result the route should return
    new_raw = "new-rotated-refresh-token"
    new_record = RefreshTokenModel.model_validate(
        {
            "_id": uuid.uuid4(),
            "user_id": user_id,
            "token_hash": "irrelevant-for-test",
            "created_at": datetime.now(UTC),
            "expires_at": datetime.now(UTC) + timedelta(days=30),
            "revoked": False,
        }
    )
    rotation_result = RefreshRotationResult(raw=new_raw, record=new_record)

    # Override the get_refresh_collection dependency to return a mock collection
    def override_get_refresh_collection():
        mock = AsyncMock()
        # verify_refresh_token will be called in the route; return a full, valid-looking record
        mock.find_one = AsyncMock(
            return_value={
                "_id": uuid.uuid4(),
                "user_id": user_id,
                # include required fields so verify_refresh_token treats it as valid
                "token_hash": "irrelevant-for-test",
                "created_at": datetime.now(UTC),
                "expires_at": datetime.now(UTC) + timedelta(days=1),  # not expired
                "revoked": False,
            }
        )
        # update_one/insert_one may be called by rotation; provide AsyncMock implementations
        mock.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
        mock.insert_one = AsyncMock(return_value=MagicMock(inserted_id=uuid.uuid4()))
        return mock

    app.dependency_overrides[get_refresh_collection] = override_get_refresh_collection

    # Monkeypatch rotate_refresh_token and revoke_refresh_token used by the route
    monkeypatch.setattr(
        "app.routes.auth_route.rotate_refresh_token", AsyncMock(return_value=rotation_result)
    )
    monkeypatch.setattr("app.routes.auth_route.revoke_refresh_token", AsyncMock(return_value=True))

    try:
        # Call refresh endpoint
        response = await async_client_no_auth.post(
            "/v1/auth/refresh", json={"refresh_token": old_raw}
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert "access_token" in body
        assert body["refresh_token"] == new_raw

        # Call logout endpoint - should return ok even if token is unknown (we mocked True)
        response = await async_client_no_auth.post(
            "/v1/auth/logout", json={"refresh_token": old_raw}
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}
    finally:
        app.dependency_overrides.clear()


def test_ensure_bytes_variants():
    b = b"hello"
    assert ensure_bytes(b) == b

    # base64 string -> decoded bytes
    enc = base64.b64encode(b).decode("utf-8")
    assert ensure_bytes(enc) == b

    # plain string -> utf-8 bytes
    s = "plain-string"
    assert ensure_bytes(s) == s.encode("utf-8")

    # memoryview -> bytes
    mv = memoryview(b)
    assert ensure_bytes(mv) == b

    # list of ints -> bytes
    lst = [104, 101, 108, 108, 111]
    assert ensure_bytes(lst) == b"hello"


@pytest.mark.asyncio
async def test_store_refresh_token_returns_uuid_and_hash():
    refresh_collection = AsyncMock()

    raw = create_refresh_token()
    new_id = uuid.uuid4()

    mock_insert_result = MagicMock()
    mock_insert_result.inserted_id = new_id
    refresh_collection.insert_one = AsyncMock(return_value=mock_insert_result)

    user_id = uuid.uuid4()
    stored: RefreshTokenModel = await store_refresh_token(refresh_collection, user_id, raw)

    # Model should have UUID id equal to inserted id and correct user_id
    assert stored.id == new_id
    assert stored.user_id == user_id
    # token_hash should match
    assert stored.token_hash == hash_token(raw)


@pytest.mark.asyncio
async def test_verify_refresh_token_handles_naive_datetimes():
    refresh_collection = AsyncMock()
    raw = "raw-refresh-token"
    token_hash = hash_token(raw)

    now = datetime.now(UTC)
    # naive created_at and expires_at (no tzinfo)
    naive_created = now.replace(tzinfo=None)
    naive_expires_future = (now + timedelta(days=1)).replace(tzinfo=None)

    rec = {
        "_id": uuid.uuid4(),
        "user_id": uuid.uuid4(),
        "token_hash": token_hash,
        "created_at": naive_created,
        "expires_at": naive_expires_future,
        "revoked": False,
    }

    refresh_collection.find_one = AsyncMock(return_value=rec)

    verified = await verify_refresh_token(refresh_collection, raw)
    assert verified is not None
    assert isinstance(verified, RefreshTokenModel)
    assert verified.user_id == rec["user_id"]

    # Now test expired naive datetime
    naive_expires_past = (now - timedelta(days=1)).replace(tzinfo=None)
    rec_expired = rec.copy()
    rec_expired["expires_at"] = naive_expires_past
    refresh_collection.find_one = AsyncMock(return_value=rec_expired)

    verified2 = await verify_refresh_token(refresh_collection, raw)
    assert verified2 is None


@pytest.mark.asyncio
async def test_rotate_refresh_token_success_and_failure():
    refresh_collection = AsyncMock()
    old_raw = "old-raw"
    user_id = uuid.uuid4()

    # Success case: find_one_and_update returns previous doc (non-None)
    claimed_doc = {
        "_id": uuid.uuid4(),
        "user_id": user_id,
        "token_hash": hash_token(old_raw),
        "created_at": datetime.now(UTC),
        "expires_at": datetime.now(UTC) + timedelta(days=30),
        "revoked": False,
    }
    refresh_collection.find_one_and_update = AsyncMock(return_value=claimed_doc)

    new_inserted_id = uuid.uuid4()
    mock_insert_result = MagicMock()
    mock_insert_result.inserted_id = new_inserted_id
    refresh_collection.insert_one = AsyncMock(return_value=mock_insert_result)

    rotation = await rotate_refresh_token(refresh_collection, old_raw, user_id)
    assert rotation is not None
    assert hasattr(rotation, "raw") and hasattr(rotation, "record")
    assert rotation.record.id == new_inserted_id
    assert isinstance(rotation.raw, str) and len(rotation.raw) > 0

    # Failure case: find_one_and_update returns None
    refresh_collection.find_one_and_update = AsyncMock(return_value=None)
    rotation2 = await rotate_refresh_token(refresh_collection, old_raw, user_id)
    assert rotation2 is None


@pytest.mark.asyncio
async def test_revoke_refresh_token_branches():
    refresh_collection = AsyncMock()
    raw = "sometoken"

    # Success: modified_count > 0
    refresh_collection.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
    ok = await revoke_refresh_token(refresh_collection, raw)
    assert ok is True

    # Failure: modified_count == 0
    refresh_collection.update_one = AsyncMock(return_value=MagicMock(modified_count=0))
    ok2 = await revoke_refresh_token(refresh_collection, raw)
    assert ok2 is False
