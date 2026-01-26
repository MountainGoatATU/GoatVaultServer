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

from app.models import TokenPayload

# Load environment variables
load_dotenv()

JWT_SECRET: str | None = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")
if len(JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET must be at least 32 characters")

JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")  # Default to HS256

ISSUER: str | None = os.getenv("ISSUER")
if not ISSUER:
    raise ValueError("ISSUER environment variable is required.")

TOKEN_EXP_HOURS: int = int(os.getenv("TOKEN_EXP_HOURS", 12))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))


def hash_token(raw_token: str) -> str:
    """Hash a refresh token for storage (SHA256 hex)."""
    h = hashlib.sha256()
    h.update(raw_token.encode("utf-8"))
    return h.hexdigest()


def create_refresh_token() -> str:
    """Create a new random refresh token (raw value to return to client)."""
    return secrets.token_urlsafe(48)


async def store_refresh_token(refresh_collection, user_id: UUID, raw_token: str) -> dict:
    """Store hashed refresh token in DB and return the DB record dict."""
    now: datetime = datetime.now(UTC)
    expires_at: datetime = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    token_hash: str = hash_token(raw_token)

    doc = {
        "user_id": user_id,
        "token_hash": token_hash,
        "created_at": now,
        "expires_at": expires_at,
        "revoked": False,
    }
    result = await refresh_collection.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


async def verify_refresh_token(refresh_collection, raw_token: str) -> dict | None:
    """Verify a refresh token and return the DB record if valid and not revoked/expired."""
    token_hash: str = hash_token(raw_token)
    now: datetime = datetime.now(UTC)
    rec = await refresh_collection.find_one({"token_hash": token_hash})
    if not rec:
        return None
    if rec.get("revoked", False):
        return None
    if rec.get("expires_at") is None or rec["expires_at"] < now:
        return None
    return rec


async def rotate_refresh_token(refresh_collection, old_raw_token: str, user_id: UUID):
    """Rotate a refresh token: verify old one, revoke it, create & store a new one."""
    rec = await verify_refresh_token(refresh_collection, old_raw_token)
    if not rec:
        return None

    # revoke old
    await refresh_collection.update_one({"_id": rec["_id"]}, {"$set": {"revoked": True}})

    # create and store new
    new_raw: str = create_refresh_token()
    new_rec = await store_refresh_token(refresh_collection, user_id, new_raw)
    return {"raw": new_raw, "record": new_rec}


async def revoke_refresh_token(refresh_collection, raw_token: str) -> bool:
    """Revoke a refresh token by raw token string; return True if a record was updated."""
    token_hash: str = hash_token(raw_token)
    result = await refresh_collection.update_one(
        {"token_hash": token_hash, "revoked": False}, {"$set": {"revoked": True}}
    )
    return result.modified_count > 0


def create_jwt_token(user_id: UUID) -> str:
    """Generate a signed JWT for a given user UUID."""
    expire = datetime.now(UTC) + timedelta(hours=TOKEN_EXP_HOURS)

    payload = {
        "sub": str(user_id),  # Subject (the user)
        "iss": ISSUER,  # Standard JWT claim (issuer)
        "exp": expire,  # Expiration time
        "iat": datetime.now(UTC),  # Issued at
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
