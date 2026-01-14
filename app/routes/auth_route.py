import hmac
from typing import Annotated

from fastapi import APIRouter, Body, Request, status, Depends
from pymongo.results import InsertOneResult
from slowapi import Limiter
from slowapi.util import get_remote_address
from motor.motor_asyncio import AsyncIOMotorCollection

from app.database import get_user_collection
from app.models import (
    AuthInitRequest,
    AuthInitResponse,
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
    validate_email_available,
    verify_mfa,
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
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)]
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
    request: Request, 
    payload: Annotated[AuthInitRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)]) -> AuthInitResponse:  # noqa: ARG001
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
    request: Request, 
    payload: Annotated[AuthRequest, Body()],
    user_collection: Annotated[AsyncIOMotorCollection, Depends(get_user_collection)]
) -> AuthResponse:  # noqa: ARG001
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
