import base64
import hashlib
import hmac
import logging
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Annotated
from uuid import UUID

import jwt
import pyotp
from dotenv import load_dotenv
from fastapi import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult

from app.models import RefreshRotationResult, RefreshTokenModel, TokenPayload
from app.utils.exceptions import CredentialsException, ForbiddenException, InvalidJWTException

"""
Settings
"""

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")  # Default to HS256
ACCESS_TOKEN_EXP_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXP_MINUTES", 5))
REFRESH_TOKEN_EXP_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXP_DAYS", 7))

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


def get_now() -> datetime:
    return datetime.now(UTC)


def hash_token(raw_token: str) -> str:
    """Hash a refresh token for storage (SHA256 hex)."""
    logger.info("Hashing refresh token")
    h = hashlib.sha256()
    h.update(raw_token.encode("utf-8"))
    logger.info(f"Hashed token: {h.hexdigest()}")
    return h.hexdigest()


def create_refresh_token() -> str:
    """Create a new random refresh token (raw value to return to client)."""
    logger.info("Creating new refresh token")
    return secrets.token_urlsafe(48)


def ensure_bytes(value) -> bytes:
    """Normalize common token-like/byte-like inputs to bytes."""
    logger.info("Ensuring bytes")

    # memoryview -> bytes
    if isinstance(value, memoryview):
        return bytes(value)

    # bytes/bytearray -> bytes
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)

    # list of ints -> bytes
    if isinstance(value, list):
        try:
            return bytes(value)
        except Exception as e:
            logger.info("Cannot convert list to bytes")
            raise TypeError(f"Cannot convert list to bytes: {e}") from e

    # str -> try base64 decode, fall back to utf-8
    if isinstance(value, str):
        try:
            # Accept padded and unpadded base64; base64.b64decode will raise on invalid input
            return base64.b64decode(value, validate=True)
        except Exception:
            logger.info("Exception while converting string to bytes")
            # fallback to plain utf-8
            return value.encode("utf-8")

    raise TypeError(f"Unsupported type for bytes conversion: {type(value)!r}")


def ensure_aware(dt_value):
    if dt_value is None:
        logger.info("Datetime is None")
        return None
    # If Pydantic model instance field (already datetime), preserve/normalize
    try:
        # datetime objects only
        if not isinstance(dt_value, datetime):
            logger.info(f"Converting datetime {dt_value} to UTC")
            return dt_value.astimezone(UTC)
        if dt_value.tzinfo is None:
            # assume stored naive datetimes are UTC
            return dt_value.replace(tzinfo=UTC)
        # convert to UTC uniformly
        logger.info(f"Converting datetime {dt_value} to UTC")
        return dt_value.astimezone(UTC)
    except Exception:
        return dt_value

    if dt_value.tzinfo is None:
        # assume stored naive datetimes are UTC
        return dt_value.replace(tzinfo=UTC)
    # convert to UTC uniformly
    logger.info(f"Converting datetime {dt_value} to UTC")
    return dt_value.astimezone(UTC)


"""
Refresh Token Helpers
"""


async def store_refresh_token(
    refresh_collection: AsyncIOMotorCollection, user_id: UUID, raw_token: str
) -> RefreshTokenModel:
    """Store hashed refresh token in DB and return the DB record dict."""
    logger.info(f"Storing refresh token for user {user_id}")
    now: datetime = get_now()
    expires_at: datetime = now + timedelta(days=REFRESH_TOKEN_EXP_DAYS)
    token_hash: str = hash_token(raw_token)

    new_id: UUID = uuid.uuid4()
    doc: dict = {
        "_id": new_id,
        "userId": user_id,
        "tokenHash": token_hash,
        "createdAtUtc": now,
        "expiresAtUtc": expires_at,
        "revoked": False,
    }

    result: InsertOneResult = await refresh_collection.insert_one(doc)
    doc["_id"] = getattr(result, "inserted_id", new_id)
    logger.info(f"New token {raw_token} stored")
    return RefreshTokenModel.model_validate(doc)


async def verify_refresh_token(
    refresh_collection: AsyncIOMotorCollection, raw_token: str
) -> RefreshTokenModel | None:
    """Verify a refresh token and return the DB record if valid and not revoked/expired."""
    logger.info("Verifying refresh token")
    token_hash: str = hash_token(raw_token)
    now: datetime = get_now()
    rec = await refresh_collection.find_one({"tokenHash": token_hash})
    if not rec:
        logger.info("No token hash found")
        return None

    # normalize to a dict
    rec_dict = rec.model_dump() if isinstance(rec, RefreshTokenModel) else rec

    if "createdAtUtc" in rec_dict:
        rec_dict["createdAtUtc"] = ensure_aware(rec_dict.get("createdAtUtc"))
    if "expiresAtUtc" in rec_dict:
        rec_dict["expiresAtUtc"] = ensure_aware(rec_dict.get("expiresAtUtc"))

    if rec_dict.get("revoked", False):
        logger.info("Token is revoked")
        return None
    if rec_dict.get("expiresAtUtc") is None or rec_dict["expiresAtUtc"] < now:
        logger.info("Token is expired")
        return None
    logger.info(f"Token {raw_token} is valid")
    return RefreshTokenModel.model_validate(rec_dict)


async def rotate_refresh_token(
    refresh_collection: AsyncIOMotorCollection, old_raw_token: str, user_id: UUID
) -> RefreshRotationResult | None:
    """Rotate a refresh token: verify old one, revoke it, create & store a new one."""
    logger.info(f"Rotating refresh token for user {user_id}")

    token_hash: str = hash_token(old_raw_token)
    now: datetime = get_now()

    # Find non-revoked, non-expired token and mark it revoked
    claimed = await refresh_collection.find_one_and_update(
        {"tokenHash": token_hash, "revoked": False, "expiresAtUtc": {"$gt": now}},
        {"$set": {"revoked": True}},
        return_document=ReturnDocument.BEFORE,
    )

    if not claimed:
        logger.info("Token not found")
        return None

    # Create and store a new refresh token
    new_raw: str = create_refresh_token()
    new_rec: RefreshTokenModel = await store_refresh_token(refresh_collection, user_id, new_raw)
    logger.info(f"New token {new_raw} created")
    return RefreshRotationResult(raw=new_raw, record=new_rec)


async def revoke_refresh_token(refresh_collection: AsyncIOMotorCollection, raw_token: str) -> bool:
    """Revoke a refresh token by raw token string."""
    logger.info(f"Revoking refresh token {raw_token}")
    token_hash: str = hash_token(raw_token)
    result = await refresh_collection.update_one(
        {"tokenHash": token_hash, "revoked": False}, {"$set": {"revoked": True}}
    )
    logger.info(f"Token {raw_token} revoked")
    return result.modified_count > 0


"""
JWT Helpers
"""


def create_jwt_token(user_id: UUID) -> str:
    """Generate a signed JWT for a given user UUID."""
    logger.info(f"Creating JWT token for user {user_id}")
    now: datetime = get_now()
    expire: datetime = now + timedelta(minutes=ACCESS_TOKEN_EXP_MINUTES)

    payload: dict = {
        "sub": str(user_id),  # Subject (the user)
        "iss": ISSUER,  # Standard JWT claim (issuer)
        "iat": now,  # Issued at
        "exp": expire,  # Expiration time
    }

    logger.info(f"Token {payload} created")
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


bearer_scheme = HTTPBearer(auto_error=True)


async def verify_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer_scheme)],
) -> TokenPayload:
    """Verifies that the provided Bearer JWT token is valid and that its 'iss'
    (issuer) claim matches the SERVER_NAME environment variable.
    """
    logger.info(f"Verifying token {credentials.credentials}")
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
                logger.info(f"Token {token} expired")
                raise InvalidJWTException from e
            case jwt.InvalidTokenError:
                logger.info(f"Token {token} invalid")
                raise InvalidJWTException from e
            case _:
                logger.info(f"Token {token} error")
                raise InvalidJWTException from e

    issuer = payload.get("iss")
    if issuer != ISSUER:
        logger.info(f"Token {token} issuer mismatch")
        raise InvalidJWTException

    if "sub" not in payload or payload.get("sub") is None:
        logger.info(f"Token {token} missing required 'sub' (subject) claim")
        raise InvalidJWTException

    # Convert payload to TokenPayload model
    try:
        token_payload: TokenPayload = TokenPayload.model_validate(payload)
    except Exception as e:
        logger.info(f"Token {token} invalid payload")
        raise InvalidJWTException from e

    logger.info(f"Token {token} verified")
    return token_payload


"""
MFA & User Access Checks
"""


def verify_mfa(otp: str | None, secret_key: str | None) -> bool:
    """Verify the user's multi-factor authentication token."""
    logger.info(f"Verifying MFA for OTP {otp} and secret key {secret_key}")
    if not otp or not secret_key:
        logger.info("OTP or secret key missing")
        return False

    try:
        totp = pyotp.TOTP(secret_key)
        logger.info(f"TOTP instance created for secret key {secret_key}")
        return totp.verify(otp, valid_window=1)
    except Exception:
        logger.exception("Error verifying MFA")
        return False


def verify_user_access(token_payload: TokenPayload, user_id: UUID) -> None:
    """Verify that the authenticated user is accessing their own resources."""
    requesting_user_id: UUID = token_payload.sub
    if requesting_user_id != user_id:
        logger.info(f"Requesting user ID {requesting_user_id} does not match user ID {user_id}")
        raise ForbiddenException
    logger.info(f"User access verified for user ID {user_id}")
