import hmac
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.results import InsertOneResult
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_refresh_collection, get_user_collection
from app.models import (
    AuthInitRequest,
    AuthInitResponse,
    AuthLogoutResponse,
    AuthRefreshRequest,
    AuthRefreshResponse,
    AuthRegisterResponse,
    AuthRequest,
    AuthResponse,
    UserCreateRequest,
    UserModel,
)
from app.utils import (
    InvalidAuthVerifierException,
    InvalidMfaCodeException,
    MfaCodeRequiredException,
    UserCreationFailedException,
    UserNotFoundByEmailException,
    UserNotFoundException,
    create_jwt_token,
    revoke_refresh_token,
    rotate_refresh_token,
    validate_email_available,
    verify_mfa,
    verify_refresh_token,
)

limiter = Limiter(key_func=get_remote_address)

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post(
    "/register",
    response_description="Register new user",
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    payload: Annotated[UserCreateRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> AuthRegisterResponse:
    """Register new user."""
    await validate_email_available(payload.email, request)

    new_user = UserModel(
        email=payload.email,
        auth_salt=payload.auth_salt,
        auth_verifier=payload.auth_verifier,
        vault=payload.vault,
    )

    new_user_dict = new_user.model_dump(by_alias=True, mode="python")

    created_user: InsertOneResult = await user_collection.insert_one(new_user_dict)
    created_user_obj = await user_collection.find_one({"_id": created_user.inserted_id})

    if created_user_obj is None:
        raise UserCreationFailedException

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
) -> AuthInitResponse:
    """Look up user by email.
    - Verify that user exists.
    - Return details including `auth_salt` and encrypted `vault`.
    """

    user = await user_collection.find_one({"email": payload.email})
    if not user:
        raise UserNotFoundByEmailException

    return AuthInitResponse(
        _id=user["_id"],
        auth_salt=user["auth_salt"],
        mfa_enabled=user["mfa_enabled"],
    )


@auth_router.post(
    "/verify",
    response_description="Verify auth verifier",
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def verify(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)],
) -> AuthResponse:
    """Return a JWT token for a valid `auth_verifier`.
    - Verifies that user exists.
    - Returns a signed JWT containing the authority claim.
    """

    user = await user_collection.find_one({"_id": payload.id})

    if not user:
        raise UserNotFoundException(payload.id)

    if not hmac.compare_digest(payload.auth_verifier, user["auth_verifier"]):
        raise InvalidAuthVerifierException

    if user.get("mfa_enabled", False):
        if not payload.mfa_code:
            raise MfaCodeRequiredException

        if not verify_mfa(payload.mfa_code, user.get("mfa_secret")):
            raise InvalidMfaCodeException

    token: str = create_jwt_token(payload.id)
    return AuthResponse(access_token=token)


@auth_router.post("/refresh")
async def refresh_token_endpoint(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthRefreshResponse:
    raw_refresh = payload.refresh_token
    if not raw_refresh:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing refresh_token")

    rec = await verify_refresh_token(refresh_collection, raw_refresh)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    user_id = rec["user_id"]
    # rotate: revoke old and issue new
    rotation = await rotate_refresh_token(refresh_collection, raw_refresh, user_id)
    if rotation is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    access: str = create_jwt_token(user_id)
    return AuthRefreshResponse(access_token=access, refresh_token=rotation["raw"])


@auth_router.post("/logout")
async def logout_endpoint(
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_collection: Annotated[AsyncIOMotorCollection, Depends(get_refresh_collection)],
) -> AuthLogoutResponse:
    raw_refresh: str = payload.refresh_token
    if not raw_refresh:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing refresh_token")
    _ok: bool = await revoke_refresh_token(refresh_collection, raw_refresh)
    return AuthLogoutResponse(status="ok")
