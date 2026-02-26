import hmac
import logging
import uuid
from datetime import UTC
from hashlib import sha256
from logging import Logger
from typing import Annotated
from uuid import UUID

from bson import Binary
from fastapi import Body, Depends, Request
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.results import InsertOneResult

from app.database import get_nonce_collection, get_refresh_collection, get_user_collection
from app.exceptions import UserCreationFailedException
from app.exceptions.exceptions import (
    CredentialsException,
    EmailNotVerifiedException,
    InvalidMfaCodeException,
    InvalidRefreshTokenException,
)
from app.models import (
    AuthInitRequest,
    AuthInitResponse,
    AuthLogoutResponse,
    AuthRefreshRequest,
    AuthRefreshResponse,
    AuthRegisterRequest,
    AuthRegisterResponse,
    AuthVerifyRequest,
    AuthVerifyResponse,
    NonceModel,
    RefreshRotationResult,
    RefreshTokenModel,
    User,
)
from app.utils import (
    create_access_token,
    create_email_verification_access_token,
    create_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
    send_verification_email,
    store_refresh_token,
    validate_email_available,
    verify_mfa,
    verify_refresh_token,
)
from app.utils.auth import ISSUER, JWT_ALGORITHM, MAIL_SECRET, jwt
from app.utils.bytes import ensure_bytes
from app.utils.crypto import generate_nonce, generate_salt
from app.utils.time import get_now, get_now_plus_two_minutes

_logger: Logger = logging.getLogger(__name__)

########################################################################
# Register New User
########################################################################


async def register_user(
    request: Request,
    payload: Annotated[AuthRegisterRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> AuthRegisterResponse:
    """Register new user."""
    _logger.info(f"Registering new user with email: {payload.email}")
    await validate_email_available(request, payload.email)

    new_user = User(
        email=payload.email,
        auth_salt=payload.auth_salt,
        auth_verifier=payload.auth_verifier,
        vault_salt=payload.vault_salt,
        vault=payload.vault,
        email_verified=False,
    )

    verification_token: str = create_email_verification_access_token(new_user.id)

    new_user_dict: User = new_user.model_dump(by_alias=True, mode="python")

    if isinstance(new_user_dict.get("authVerifier"), (bytes, bytearray)):
        new_user_dict["authVerifier"] = Binary(new_user_dict["authVerifier"])

    created_user: InsertOneResult = await user_collection.insert_one(new_user_dict)
    created_user_obj = await user_collection.find_one({"_id": created_user.inserted_id})

    if created_user_obj is None:
        _logger.error(f"Failed to create user: {payload.email}")
        raise UserCreationFailedException

    try:
        await send_verification_email(payload.email, verification_token)
        _logger.info(f"Verification email sent to: {payload.email}")
    except Exception as e:
        _logger.error(f"Failed to send verification email: {e}")
    _logger.info(f"User registered successfully: {payload.email}")
    return AuthRegisterResponse(**created_user_obj)


########################################################################
# Verify User Email
########################################################################


async def verify_email(
    token: str,
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> dict:
    try:
        payload: dict[str, str] = jwt.decode(
            token,
            MAIL_SECRET,  # ty: ignore[invalid-argument-type]
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "iss"]},
        )
    except Exception:
        return {"success": False, "message": "Invalid or expired verification token."}

    if payload.get("iss") != ISSUER:
        return {"success": False, "message": "Invalid token issuer."}

    if payload.get("purpose") != "email_verification":
        return {"success": False, "message": "Invalid token purpose."}

    user_id = UUID(payload.get("sub"))
    user_data = await user_collection.find_one({"_id": user_id})

    if not user_data:
        return {"success": False, "message": "User not found."}

    user = User(**user_data)

    if user.email_verified:
        return {"success": True, "message": "Email already verified."}

    user.email_verified = True
    await user_collection.update_one(
        {"_id": user.id}, {"$set": {"emailVerified": user.email_verified}}
    )

    return {"success": True, "message": "Email successfully verified."}


########################################################################
# Initiate User Authentication
########################################################################


async def init_auth(
    payload: Annotated[AuthInitRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
    nonce_collection: Annotated[AsyncIOMotorCollection, Depends(get_nonce_collection)],
) -> AuthInitResponse:
    _logger.info(f"Auth init requested for email: {payload.email}")

    user: User | None = await user_collection.find_one({"email": payload.email})

    nonce: bytes = generate_nonce()

    # Return fake response if user not found
    if not user:
        _logger.warning(f"User not found for auth init: {payload.email}")
        return AuthInitResponse(
            _id=uuid.uuid4(),
            auth_salt=generate_salt(),
            nonce=nonce,
            mfa_enabled=False,
        )

    nonce_record = NonceModel(
        user_id=user["_id"],
        nonce=nonce,
        created_at_utc=get_now(),
        expires_at_utc=get_now_plus_two_minutes(),
    )

    await nonce_collection.insert_one(nonce_record.model_dump(by_alias=True))

    _logger.info(f"Auth init successful for user: {user['_id']}")

    return AuthInitResponse(
        _id=user["_id"],
        auth_salt=user["authSalt"],
        nonce=nonce,
        mfa_enabled=user["mfaEnabled"],
    )


########################################################################
# Verify User Authentication
########################################################################


async def verify_auth(
    payload: Annotated[AuthVerifyRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
    nonce_collection: Annotated[AsyncIOMotorCollection, Depends(get_nonce_collection)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthVerifyResponse:
    _logger.info(f"Auth verification requested for user: {payload.id}")

    # Find user
    user: AsyncIOMotorCollection | None = await user_collection.find_one({"_id": payload.id})
    if not user:
        _logger.warning(f"User not found during verification: {payload.id}")
        raise CredentialsException

    # Check if email is verified
    if not user.get("emailVerified", False):
        _logger.warning(f"User {payload.id} tried to login without verifying email")
        raise EmailNotVerifiedException

    # Find the most recent valid nonce for this user
    stored_nonce_doc: NonceModel | None = await nonce_collection.find_one(
        {"userId": payload.id}, sort=[("createdAtUtc", -1)]
    )

    if not stored_nonce_doc:
        _logger.warning(f"No nonce found for user: {payload.id}")
        raise CredentialsException

    # Consume the nonce immediately to prevent replay
    await nonce_collection.delete_one({"_id": stored_nonce_doc["_id"]})

    # Check if nonce is expired (double check, though TTL index should handle it eventually)
    if stored_nonce_doc["expiresAtUtc"].replace(tzinfo=UTC) < get_now():
        _logger.warning(f"Nonce expired for user: {payload.id}")
        raise CredentialsException

    nonce_bytes: bytes = ensure_bytes(stored_nonce_doc["nonce"])
    user_auth_verifier: bytes = ensure_bytes(user.get("authVerifier"))
    payload_proof: bytes = ensure_bytes(payload.proof)

    # Compute expected proof: HMAC-SHA256(key=auth_verifier, msg=nonce)
    expected_proof: bytes = hmac.new(
        key=user_auth_verifier, msg=nonce_bytes, digestmod=sha256
    ).digest()

    # Compare proofs
    if not hmac.compare_digest(payload_proof, expected_proof):
        _logger.warning(f"Invalid proof provided for user: {payload.id}")
        raise CredentialsException

    # Handle MFA
    if user.get("mfaEnabled", False):
        if not payload.mfa_code:
            _logger.warning(f"MFA code required but not provided for user: {payload.id}")
            raise CredentialsException

        if not verify_mfa(payload.mfa_code, user.get("mfaSecret")):
            _logger.warning(f"Invalid MFA code for user: {payload.id}")
            raise InvalidMfaCodeException

    # Issue token
    token: str = create_access_token(payload.id)
    raw_refresh: str = create_refresh_token()

    await store_refresh_token(refresh_collection, payload.id, raw_refresh)

    _logger.info(f"Auth verification successful for user: {payload.id}")

    return AuthVerifyResponse(access_token=token, refresh_token=raw_refresh)


########################################################################
# Rotate Refresh Token
########################################################################


async def new_refresh_token(
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthRefreshResponse:
    rec: RefreshTokenModel | None = await verify_refresh_token(
        refresh_collection, payload.refresh_token
    )
    if not rec:
        _logger.warning("Invalid or expired refresh token used")
        raise InvalidRefreshTokenException

    rotation: RefreshRotationResult | None = await rotate_refresh_token(
        refresh_collection, payload.refresh_token, rec.user_id
    )
    if rotation is None:
        _logger.warning(f"Refresh token rotation failed for user: {rec.user_id}")
        raise InvalidRefreshTokenException

    access: str = create_access_token(rotation.record.user_id)
    _logger.info(f"Token refreshed successfully for user: {rec.user_id}")

    return AuthRefreshResponse(access_token=access, refresh_token=rotation.raw)


########################################################################
# Logout User
########################################################################


async def logout_user(
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthLogoutResponse:
    raw_refresh: str = payload.refresh_token

    if not raw_refresh:
        _logger.warning("Logout attempted without refresh token")
        raise InvalidRefreshTokenException

    _ok: bool = await revoke_refresh_token(refresh_collection, raw_refresh)
    _logger.info("Logout successful (refresh token revoked)")

    return AuthLogoutResponse(status="ok")
