import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import jwt
import pyotp
from dotenv import load_dotenv
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult

from app.models import RefreshRotationResult, RefreshTokenModel, TokenPayload

"""
Settings
"""

# Load environment variables
load_dotenv()

JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")  # Default to HS256
TOKEN_EXP_HOURS: int = int(os.getenv("TOKEN_EXP_HOURS", 12))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))

JWT_SECRET: str | None = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")
if len(JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET must be at least 32 characters")

ISSUER: str | None = os.getenv("ISSUER")
if not ISSUER:
    raise ValueError("ISSUER environment variable is required.")


"""
Helpers
"""


def _now() -> datetime:
    return datetime.now(UTC)


def hash_token(raw_token: str) -> str:
    """Hash a refresh token for storage (SHA256 hex)."""
    h = hashlib.sha256()
    h.update(raw_token.encode("utf-8"))
    return h.hexdigest()


def create_refresh_token() -> str:
    """Create a new random refresh token (raw value to return to client)."""
    return secrets.token_urlsafe(48)


"""
Refresh Token Helpers
"""


async def store_refresh_token(
    refresh_collection: AsyncIOMotorCollection, user_id: UUID, raw_token: str
) -> RefreshTokenModel:
    """Store hashed refresh token in DB and return the DB record dict."""
    now: datetime = _now()
    expires_at: datetime = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    token_hash: str = hash_token(raw_token)

    doc: dict = {
        "user_id": user_id,
        "token_hash": token_hash,
        "created_at": now,
        "expires_at": expires_at,
        "revoked": False,
    }
    result: InsertOneResult = await refresh_collection.insert_one(doc)
    doc["_id"] = result.inserted_id
    return RefreshTokenModel.model_validate(doc)


async def verify_refresh_token(
    refresh_collection: AsyncIOMotorCollection, raw_token: str
) -> RefreshTokenModel | None:
    """Verify a refresh token and return the DB record if valid and not revoked/expired."""
    token_hash: str = hash_token(raw_token)
    now: datetime = _now()
    rec = await refresh_collection.find_one({"token_hash": token_hash})
    if not rec:
        return None

    # normalize
    rec_dict = rec.model_dump() if isinstance(rec, RefreshTokenModel) else rec

    if rec_dict.get("revoked", False):
        return None
    if rec_dict.get("expires_at") is None or rec_dict["expires_at"] < now:
        return None
    return RefreshTokenModel.model_validate(rec_dict)


async def rotate_refresh_token(
    refresh_collection: AsyncIOMotorCollection, old_raw_token: str, user_id: UUID
) -> RefreshRotationResult | None:
    """Rotate a refresh token: verify old one, revoke it, create & store a new one."""

    token_hash: str = hash_token(old_raw_token)
    now: datetime = _now()

    # Find non-revoked, non-expired token and mark it revoked
    claimed = await refresh_collection.find_one_and_update(
        {"token_hash": token_hash, "revoked": False, "expires_at": {"$gt": now}},
        {"$set": {"revoked": True}},
        return_document=ReturnDocument.BEFORE,
    )

    if not claimed:
        return None

    # Create and store a new refresh token
    new_raw: str = create_refresh_token()
    new_rec: RefreshTokenModel = await store_refresh_token(refresh_collection, user_id, new_raw)
    return RefreshRotationResult(raw=new_raw, record=new_rec)


async def revoke_refresh_token(refresh_collection: AsyncIOMotorCollection, raw_token: str) -> bool:
    """Revoke a refresh token by raw token string."""
    token_hash: str = hash_token(raw_token)
    result = await refresh_collection.update_one(
        {"token_hash": token_hash, "revoked": False}, {"$set": {"revoked": True}}
    )
    return result.modified_count > 0


"""
JWT Helpers
"""


def create_jwt_token(user_id: UUID) -> str:
    """Generate a signed JWT for a given user UUID."""
    expire = _now() + timedelta(hours=TOKEN_EXP_HOURS)
    payload = {
        "sub": str(user_id),  # Subject (the user)
        "iss": ISSUER,  # Standard JWT claim (issuer)
        "exp": expire,  # Expiration time
        "iat": _now(),  # Issued at
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


bearer_scheme = HTTPBearer(auto_error=True)


async def verify_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer_scheme)],
) -> TokenPayload:
    """Verifies that the provided Bearer JWT token is valid and that its 'iss'
    (issuer) claim matches the SERVER_NAME environment variable.
    """
    token: str = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "iss"]},
        )
    except PyJWTError as e:
        match e:
            case jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                ) from e
            case jwt.InvalidTokenError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                ) from e
            case _:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid or expired JWT token: {e!s}",
                ) from e

    issuer = payload.get("iss")
    if issuer != ISSUER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token issuer mismatch",
        )

    if "sub" not in payload or payload.get("sub") is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required 'sub' (subject) claim",
        )

    # Convert payload to TokenPayload model
    try:
        token_payload: TokenPayload = TokenPayload.model_validate(payload)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token payload: {e!s}",
        ) from e

    return token_payload


"""
MFA & User Access Checks
"""


def verify_mfa(otp: str | None, secret_key: str | None) -> bool:
    """Verify the user's multi-factor authentication token."""
    if not otp or not secret_key:
        return False

    try:
        totp = pyotp.TOTP(secret_key)
        return totp.verify(otp, valid_window=1)
    except Exception:
        return False


def verify_user_access(token_payload: TokenPayload, user_id: UUID) -> None:
    """Verify that the authenticated user is accessing their own resources."""
    requesting_user_id: UUID = token_payload.sub
    if requesting_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You can only access your own resources"
        )
