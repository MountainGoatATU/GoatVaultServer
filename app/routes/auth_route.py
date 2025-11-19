import hmac
from typing import Annotated

from fastapi import APIRouter, Body, Request, status
from pymongo.results import InsertOneResult
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.auth import create_jwt_token
from app.database import user_collection
from app.exceptions import (
    InvalidAuthVerifierException,
    UserCreationFailedException,
    UserNotFoundByEmailException,
)
from app.models.auth_model import AuthInitRequest, AuthInitResponse, AuthRequest, AuthResponse
from app.models.user_model import UserCreateRequest, UserModel, UserResponse
from app.validators import validate_email_available

limiter = Limiter(key_func=get_remote_address)

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post(
    "/register",
    response_description="Register new user",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def register(request: Request, payload: Annotated[UserCreateRequest, Body()]) -> UserResponse:
    """
    Register new user.
    """
    await validate_email_available(payload.email)

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
        raise UserCreationFailedException()

    return UserResponse(**created_user_obj)


@auth_router.post(
    "/init",
    response_description="Look up user by email",
    response_model=AuthInitResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def init(request: Request, payload: Annotated[AuthInitRequest, Body()]) -> AuthInitResponse:
    """
    Look up user by email.
    - Verify that user exists.
    - Return details including `auth_salt` and encrypted `vault`.
    """
    user = await user_collection.find_one({"email": payload.email})
    if not user:
        raise UserNotFoundByEmailException()

    return AuthInitResponse(
        user_id=user["_id"],
        auth_salt=user["auth_salt"],
        vault=user["vault"],
        mfa_enabled=user["mfa_enabled"],
    )


@auth_router.post(
    "/verify",
    response_description="Verify auth verifier",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def verify(request: Request, payload: Annotated[AuthRequest, Body()]) -> AuthResponse:
    """
    Return a JWT token for a valid `auth_verifier`.
    - Verifies that user exists.
    - Returns a signed JWT containing the authority claim.
    """
    user = await user_collection.find_one({"_id": payload.user_id})
    if not user:
        raise UserNotFoundByEmailException()

    if not hmac.compare_digest(payload.auth_verifier, user["auth_verifier"]):
        raise InvalidAuthVerifierException()

    token: str = create_jwt_token(payload.user_id)
    return AuthResponse(access_token=token)
