import os
from typing import Annotated

import jwt
from dotenv import load_dotenv
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError

# Load environment variables
load_dotenv()

ISSUER: str | None = os.getenv("ISSUER")
JWT_SECRET: str | None = os.getenv("JWT_SECRET")  # Optional if you use signed tokens
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")

if not ISSUER:
    raise ValueError("ISSUER environment variable is required.")

bearer_scheme = HTTPBearer(auto_error=True)


async def verify_api_key(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer_scheme)]
) -> dict:
    """
    Verifies that the provided Bearer JWT token is valid and that its 'iss'
    (issuer) claim matches the SERVER_NAME environment variable.
    """
    token = credentials.credentials

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired JWT token: {str(e)}",
        )

    issuer = payload.get("iss")
    if issuer != ISSUER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token issuer mismatch",
        )

    return payload