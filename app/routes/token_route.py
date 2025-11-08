from fastapi import APIRouter, Body, HTTPException, status
from app.models.token_model import TokenRequest, TokenResponse
from app.database import user_collection
from app.auth import create_jwt_token

token_router = APIRouter(prefix="/token", tags=["auth"])


@token_router.post(
    "/",
    response_description="Generate JWT token for user",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
async def generate_token(payload: TokenRequest = Body(...)) -> TokenResponse:
    """
    Generate a JWT token for a valid user UUID and email.
    - Verifies that user exists in MongoDB.
    - Returns a signed JWT containing the authority claim.
    """
    user = await user_collection.find_one({"_id": payload.user_id, "email": payload.email})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    token = create_jwt_token(payload.user_id)
    return TokenResponse(access_token=token)