from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, status

from app.auth import create_jwt_token
from app.database import user_collection
from app.models.auth_model import AuthInitRequest, AuthInitResponse, AuthRequest, AuthResponse

token_router = APIRouter(prefix="/auth", tags=["auth"])


@token_router.post(
    "/token",
    response_description="Generate JWT token for user",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
)
async def generate_token(payload: Annotated[AuthRequest, Body()]) -> AuthResponse:
    """
    Generate a JWT token for a valid user `UUID` and `email`.
    - Verifies that user exists in MongoDB.
    - Returns a signed JWT containing the authority claim.
    """
    user = await user_collection.find_one({"_id": payload.user_id, "email": payload.email})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    token = create_jwt_token(payload.user_id)
    return AuthResponse(access_token=token)


@token_router.post(
    "/init",
    response_description="Look up user by email",
    response_model=AuthInitResponse,
    status_code=status.HTTP_200_OK,
)
async def init(payload: Annotated[AuthInitRequest, Body()]) -> AuthInitResponse:
    """
    Look up user by email.
    """
    user = await user_collection.find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return AuthInitResponse(user_id=user["_id"], auth_salt=user["auth_salt"], vault=user["vault"])


@token_router.post(
    "/verify",
    response_description="Verify auth verifier",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
)
async def verify(payload: Annotated[AuthRequest, Body()]) -> AuthResponse:
    """
    Return a JWT token for a valid `auth_verifier`.
    - Verifies that user exists in MongoDB.
    - Returns a signed JWT containing the authority claim.
    """
    user = await user_collection.find_one({"_id": payload.user_id})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.auth_verifier != user["auth_verifier"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth verifier"
        )

    token = create_jwt_token(payload.user_id)
    return AuthResponse(access_token=token)
