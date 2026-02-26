import logging
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

import jwt
import pyotp
from dotenv import load_dotenv
from fastapi import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReturnDocument
from pymongo.results import InsertOneResult, UpdateResult

from app.exceptions import ForbiddenException, InvalidJWTException
from app.models import RefreshRotationResult, RefreshTokenModel, TokenPayload
from app.utils.crypto import decrypt_mfa_secret, hash_token
from app.utils.time import ensure_aware, get_now

_logger = logging.getLogger(__name__)

########################################################################
# Environment Variables
########################################################################

load_dotenv()

_BEARER_SCHEME = HTTPBearer(auto_error=True)
_ACCESS_TOKEN_EXP_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXP_MINUTES", 5))
_REFRESH_TOKEN_EXP_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXP_DAYS", 7))
_JWT_SECRET: str | None = os.getenv("JWT_SECRET")
if not _JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")
if len(_JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET must be at least 32 characters")

JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")  # Default to HS256
MAIL_SECRET: str | None = os.getenv("MAIL_SECRET")
if not MAIL_SECRET:
    raise ValueError("MAIL_SECRET environment variable is required")
if len(MAIL_SECRET) < 32:
    raise ValueError("MAIL_SECRET must be at least 32 characters")
ISSUER: str | None = os.getenv("ISSUER")
if not ISSUER:
    raise ValueError("ISSUER environment variable is required.")


########################################################################
# Refresh Token Helpers
########################################################################


def create_refresh_token() -> str:
    """Create a new random refresh token (raw value to return to client)."""
    _logger.info("Creating new refresh token")
    return secrets.token_urlsafe(48)


async def store_refresh_token(
    refresh_collection: AsyncIOMotorCollection, user_id: UUID, raw_token: str
) -> RefreshTokenModel:
    """Store hashed refresh token in DB and return the DB record dict."""
    _logger.info(f"Storing refresh token for user {user_id}")
    now: datetime = get_now()
    expires_at: datetime = now + timedelta(days=_REFRESH_TOKEN_EXP_DAYS)
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
    _logger.info(f"New token {raw_token} stored")
    return RefreshTokenModel.model_validate(doc)


async def verify_refresh_token(
    refresh_collection: AsyncIOMotorCollection, raw_token: str
) -> RefreshTokenModel | None:
    """Verify a refresh token and return the DB record if valid and not revoked/expired."""
    _logger.info("Verifying refresh token")
    token_hash: str = hash_token(raw_token)
    now: datetime = get_now()
    rec = await refresh_collection.find_one({"tokenHash": token_hash})
    if not rec:
        _logger.info("No token hash found")
        return None

    # normalize to a dict
    rec_dict: dict = rec.model_dump() if isinstance(rec, RefreshTokenModel) else rec

    if "createdAtUtc" in rec_dict:
        rec_dict["createdAtUtc"] = ensure_aware(rec_dict.get("createdAtUtc"))
    if "expiresAtUtc" in rec_dict:
        rec_dict["expiresAtUtc"] = ensure_aware(rec_dict.get("expiresAtUtc"))

    if rec_dict.get("revoked", False):
        _logger.info("Token is revoked")
        return None
    if rec_dict.get("expiresAtUtc") is None or rec_dict["expiresAtUtc"] < now:
        _logger.info("Token is expired")
        return None

    _logger.info(f"Token {raw_token} is valid")
    return RefreshTokenModel.model_validate(rec_dict)


async def rotate_refresh_token(
    refresh_collection: AsyncIOMotorCollection, old_raw_token: str, user_id: UUID
) -> RefreshRotationResult | None:
    """Rotate a refresh token: verify old one, revoke it, create & store a new one."""
    _logger.info(f"Rotating refresh token for user {user_id}")

    token_hash: str = hash_token(old_raw_token)
    now: datetime = get_now()

    # Find non-revoked, non-expired token and mark it revoked
    claimed: UpdateResult | None = await refresh_collection.find_one_and_update(
        {"tokenHash": token_hash, "revoked": False, "expiresAtUtc": {"$gt": now}},
        {"$set": {"revoked": True}},
        return_document=ReturnDocument.BEFORE,
    )

    if not claimed:
        _logger.info("Token not found")
        return None

    # Create and store a new refresh token
    new_raw: str = create_refresh_token()
    new_rec: RefreshTokenModel = await store_refresh_token(refresh_collection, user_id, new_raw)
    _logger.info(f"New token {new_raw} created")
    return RefreshRotationResult(raw=new_raw, record=new_rec)


async def revoke_refresh_token(refresh_collection: AsyncIOMotorCollection, raw_token: str) -> bool:
    """Revoke a refresh token by raw token string."""
    _logger.info(f"Revoking refresh token {raw_token}")
    token_hash: str = hash_token(raw_token)
    result = await refresh_collection.update_one(
        {"tokenHash": token_hash, "revoked": False}, {"$set": {"revoked": True}}
    )
    _logger.info(f"Token {raw_token} revoked")
    return result.modified_count > 0


########################################################################
# Access Token Helpers
########################################################################


def create_access_token(user_id: UUID) -> str:
    """Generate a signed JWT for a given user UUID."""
    _logger.info(f"Creating JWT token for user {user_id}")
    now: datetime = get_now()
    expire: datetime = now + timedelta(minutes=_ACCESS_TOKEN_EXP_MINUTES)

    payload: dict = {
        "sub": str(user_id),  # Subject (the user)
        "iss": ISSUER,  # Standard JWT claim (issuer)
        "iat": now,  # Issued at
        "exp": expire,  # Expiration time
    }

    _logger.info(f"Token {payload} created")
    return jwt.encode(payload, _JWT_SECRET, algorithm=JWT_ALGORITHM)  # ty: ignore[invalid-argument-type]


async def verify_access_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(_BEARER_SCHEME)],
) -> TokenPayload:
    """Verifies that the provided Bearer JWT token is valid and that its 'iss'
    (issuer) claim matches the SERVER_NAME environment variable.
    """
    _logger.info(f"Verifying token {credentials.credentials}")
    token: str = credentials.credentials

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            _JWT_SECRET,  # ty: ignore[invalid-argument-type]
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "iss"]},
        )
    except PyJWTError as e:
        match e:
            case jwt.ExpiredSignatureError:
                _logger.info(f"Token {token} expired")
                raise InvalidJWTException from e
            case jwt.InvalidTokenError:
                _logger.info(f"Token {token} invalid")
                raise InvalidJWTException from e
            case _:
                _logger.info(f"Token {token} error")
                raise InvalidJWTException from e

    issuer: str | None = payload.get("iss")
    if issuer != ISSUER:
        _logger.info(f"Token {token} issuer mismatch")
        raise InvalidJWTException

    if "sub" not in payload or payload.get("sub") is None:
        _logger.info(f"Token {token} missing required 'sub' (subject) claim")
        raise InvalidJWTException

    # Convert payload to TokenPayload model
    try:
        token_payload: TokenPayload = TokenPayload.model_validate(payload)
    except Exception as e:
        _logger.info(f"Token {token} invalid payload")
        raise InvalidJWTException from e

    _logger.info(f"Token {token} verified")
    return token_payload


def create_email_verification_access_token(user_id: uuid.UUID) -> str:
    """Create a JWT token for email verification with 1h expiry."""
    now: datetime = datetime.now(UTC)
    expire: datetime = now + timedelta(hours=1)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "iss": ISSUER,
        "iat": now,
        "exp": expire,
        "purpose": "email_verification",
    }
    return jwt.encode(payload, MAIL_SECRET, algorithm=JWT_ALGORITHM)  # ty: ignore[invalid-argument-type]


########################################################################
# MFA Checks
########################################################################


def verify_mfa(otp: str | None, secret_key: str | None) -> bool:
    """Verify the user's multi-factor authentication token."""
    _logger.info(f"Verifying MFA for OTP {otp} and encrypted MFA secret {secret_key}")

    if not otp or not secret_key:
        _logger.info("OTP or encrypted MFA secret missing")
        return False

    try:
        mfa_secret: str = decrypt_mfa_secret(secret_key)
        totp = pyotp.TOTP(mfa_secret)
        _logger.info(f"TOTP instance created for secret key {mfa_secret}")
        return totp.verify(otp, valid_window=1)
    except Exception:
        _logger.exception("Error verifying MFA")
        return False


########################################################################
# User Access Checks
########################################################################


def verify_user_access(token_payload: TokenPayload, user_id: UUID) -> None:
    """Verify that the authenticated user is accessing their own resources."""
    requesting_user_id: UUID = token_payload.sub
    if requesting_user_id != user_id:
        _logger.info(f"Requesting user ID {requesting_user_id} does not match user ID {user_id}")
        raise ForbiddenException
    _logger.info(f"User access verified for user ID {user_id}")
