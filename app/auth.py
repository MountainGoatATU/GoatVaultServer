from datetime import datetime, timedelta, UTC
from uuid import UUID
import os
from typing import Annotated

import jwt
from dotenv import load_dotenv
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError

# Load environment variables
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256") # Default to HS256
ISSUER = os.getenv("ISSUER")
TOKEN_EXP_HOURS = int(os.getenv("TOKEN_EXP_HOURS", 12))

if not ISSUER:
    raise ValueError("ISSUER environment variable is required.")

def create_jwt_token(user_id: UUID) -> str:
    """Generate a signed JWT for a given user UUID."""
    expire = datetime.now(UTC) + timedelta(hours=TOKEN_EXP_HOURS)

    payload = {
        "sub": str(user_id),         # Subject (the user)
        "iss": ISSUER,               # Standard JWT claim (issuer)
        "exp": expire,               # Expiration time
        "iat": datetime.now(UTC),    # Issued at
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

bearer_scheme = HTTPBearer(auto_error=True)

async def verify_token(
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
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    issuer = payload.get("iss")
    if issuer != ISSUER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token issuer mismatch",
        )

    return payload