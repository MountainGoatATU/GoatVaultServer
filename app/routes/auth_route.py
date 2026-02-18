import hmac
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Annotated

from bson import Binary
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.results import InsertOneResult
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_nonce_collection, get_refresh_collection, get_user_collection
from app.models import (
    AuthInitRequest,
    AuthInitResponse,
    AuthLogoutResponse,
    AuthRefreshRequest,
    AuthRefreshResponse,
    AuthRegisterResponse,
    AuthRequest,
    AuthResponse,
    NonceModel,
    RefreshRotationResult,
    RefreshTokenModel,
    UserCreateRequest,
    UserModel,
)
from app.utils import (
    CredentialsException,
    InvalidMfaCodeException,
    MfaCodeRequiredException,
    UserCreationFailedException,
    create_jwt_token,
    create_refresh_token,
    ensure_bytes,
    get_now,
    revoke_refresh_token,
    rotate_refresh_token,
    store_refresh_token,
    validate_email_available,
    verify_mfa,
    verify_refresh_token,
)

logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post(
    "/register",
    response_description="Register new user",
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("2/minute")
async def register(
    request: Request,
    payload: Annotated[UserCreateRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> AuthRegisterResponse:
    """Register new user."""
    logger.info(f"Registering new user with email: {payload.email}")
    await validate_email_available(payload.email, request)

    new_user = UserModel(
        email=payload.email,
        auth_salt=payload.auth_salt,
        auth_verifier=payload.auth_verifier,
        vault_salt=payload.vault_salt,
        vault=payload.vault,
    )

    new_user_dict = new_user.model_dump(by_alias=True, mode="python")

    if isinstance(new_user_dict.get("authVerifier"), (bytes, bytearray)):
        new_user_dict["authVerifier"] = Binary(new_user_dict["authVerifier"])

    created_user: InsertOneResult = await user_collection.insert_one(new_user_dict)
    created_user_obj = await user_collection.find_one({"_id": created_user.inserted_id})

    if created_user_obj is None:
        logger.error(f"Failed to create user: {payload.email}")
        raise UserCreationFailedException

    logger.info(f"User registered successfully: {payload.email}")
    return AuthRegisterResponse(**created_user_obj)


@auth_router.post(
    "/init",
    response_description="Look up user by email",
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def init(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthInitRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
    nonce_collection: Annotated[AsyncIOMotorCollection, Depends(get_nonce_collection)],
) -> AuthInitResponse:
    """Look up user by email.
    - Verify that user exists.
    - Return details including `authSalt` and encrypted `vault`.
    """
    logger.info(f"Auth init requested for email: {payload.email}")

    user: UserModel | None = await user_collection.find_one({"email": payload.email})

    # Generate nonce
    nonce: bytes = secrets.token_bytes(32)

    # Return fake response if user not found
    if not user:
        logger.warning(f"User not found for auth init: {payload.email}")
        return AuthInitResponse(
            id=uuid.uuid4(),
            auth_salt=secrets.token_bytes(32),
            nonce=nonce,
            mfa_enabled=False,
        )

    now: datetime = get_now()

    nonce_record = NonceModel(
        user_id=user["_id"],
        nonce=nonce,
        created_at_utc=now,
        expires_at_utc=now + timedelta(minutes=2),
    )

    # Store nonce with expiry (e.g. 2 minutes)
    await nonce_collection.insert_one(nonce_record.model_dump(by_alias=True))

    logger.info(f"Auth init successful for user: {user['_id']}")
    return AuthInitResponse(
        id=user["_id"],
        auth_salt=user["authSalt"],
        nonce=nonce,
        mfa_enabled=user["mfaEnabled"],
    )


@auth_router.post(
    "/verify",
    response_description="Verify auth proof",
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def verify(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
    nonce_collection: Annotated[AsyncIOMotorCollection, Depends(get_nonce_collection)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthResponse:
    """Return a JWT token for a valid `auth_verifier`.
    - Verifies that user exists.
    - Returns a signed JWT containing the authority claim.
    """
    logger.info(f"Auth verification requested for user: {payload.id}")

    # Find user
    user: UserModel | None = await user_collection.find_one({"_id": payload.id})
    if not user:
        logger.warning(f"User not found during verification: {payload.id}")
        raise CredentialsException

    # Find the most recent valid nonce for this user
    stored_nonce_doc: NonceModel | None = await nonce_collection.find_one(
        {"userId": payload.id}, sort=[("createdAtUtc", -1)]
    )

    if not stored_nonce_doc:
        logger.warning(f"No nonce found for user: {payload.id}")
        raise CredentialsException

    # Consume the nonce immediately to prevent replay
    await nonce_collection.delete_one({"_id": stored_nonce_doc["_id"]})

    # Check if nonce is expired (double check, though TTL index should handle it eventually)
    if stored_nonce_doc["expiresAtUtc"].replace(tzinfo=UTC) < datetime.now(UTC):
        logger.warning(f"Nonce expired for user: {payload.id}")
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
        logger.warning(f"Invalid proof provided for user: {payload.id}")
        raise CredentialsException

    # Handle MFA
    if user.get("mfaEnabled", False):
        if not payload.mfa_code:
            logger.warning(f"MFA code required but not provided for user: {payload.id}")
            raise MfaCodeRequiredException

        if not verify_mfa(payload.mfa_code, user.get("mfaSecret")):
            logger.warning(f"Invalid MFA code for user: {payload.id}")
            raise InvalidMfaCodeException

    # Issue token
    token: str = create_jwt_token(payload.id)
    raw_refresh: str = create_refresh_token()

    await store_refresh_token(refresh_collection, payload.id, raw_refresh)

    logger.info(f"Auth verification successful for user: {payload.id}")
    return AuthResponse(access_token=token, refresh_token=raw_refresh)


@auth_router.post("/refresh")
async def refresh_token_endpoint(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthRefreshResponse:
    rec: RefreshTokenModel | None = await verify_refresh_token(
        refresh_collection, payload.refresh_token
    )
    if not rec:
        logger.warning("Invalid or expired refresh token used")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    rotation: RefreshRotationResult | None = await rotate_refresh_token(
        refresh_collection, payload.refresh_token, rec.user_id
    )
    if rotation is None:
        logger.warning(f"Refresh token rotation failed for user: {rec.user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    access: str = create_jwt_token(rotation.record.user_id)
    logger.info(f"Token refreshed successfully for user: {rec.user_id}")
    return AuthRefreshResponse(access_token=access, refresh_token=rotation.raw)


@auth_router.post("/logout")
async def logout_endpoint(
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthLogoutResponse:
    raw_refresh: str = payload.refresh_token

    if not raw_refresh:
        logger.warning("Logout attempted without refresh token")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing refresh_token")

    _ok: bool = await revoke_refresh_token(refresh_collection, raw_refresh)
    logger.info("Logout successful (refresh token revoked)")
    return AuthLogoutResponse(status="ok")
