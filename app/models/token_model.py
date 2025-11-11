from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class TokenRequest(BaseModel):
    """Request model for generating JWT token."""
    user_id: UUID = Field(..., description="UUID of the user requesting a token")
    email: EmailStr = Field(..., max_length=254)


class TokenResponse(BaseModel):
    """Response model for the generated JWT token."""
    access_token: str = Field(..., description="Generated JWT token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
