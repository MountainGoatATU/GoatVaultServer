import os
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import jwt
import pyotp
from dotenv import load_dotenv
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError

# Load environment variables
load_dotenv()

JWT_SECRET: str | None = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")
if len(JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET must be at least 32 characters")

JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")  # Default to HS256

ISSUER: str | None = os.getenv("ISSUER")
if not ISSUER:
    raise ValueError("ISSUER environment variable is required.")

TOKEN_EXP_HOURS: int = int(os.getenv("TOKEN_EXP_HOURS", 12))


def create_jwt_token(user_id: UUID) -> str:
    """Generate a signed JWT for a given user UUID."""
    expire = datetime.now(UTC) + timedelta(hours=TOKEN_EXP_HOURS)

    payload = {
        "sub": str(user_id),  # Subject (the user)
        "iss": ISSUER,  # Standard JWT claim (issuer)
        "exp": expire,  # Expiration time
        "iat": datetime.now(UTC),  # Issued at
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


bearer_scheme = HTTPBearer(auto_error=True)


async def verify_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer_scheme)],
) -> dict:
    """Verifies that the provided Bearer JWT token is valid and that its 'iss'
    (issuer) claim matches the SERVER_NAME environment variable.
    """
    token: str = credentials.credentials

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except PyJWTError as e:
        match e:
            case jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                ) from e
            case jwt.InvalidTokenError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                ) from e
            case _:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid or expired JWT token: {e!s}",
                ) from e

    issuer = payload.get("iss")
    if issuer != ISSUER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token issuer mismatch",
        )

    return payload


def verify_mfa(otp: str | None, secret_key: str | None) -> bool:
    """Verify the user's multi-factor authentication token."""
    if not otp or not secret_key:
        return False

    try:
        totp = pyotp.TOTP(secret_key)
        return totp.verify(otp, valid_window=1)
    except Exception:
        return False


def verify_user_access(token_payload: dict, user_id: UUID) -> None:
    """Verify that the authenticated user is accessing their own resources."""
    requesting_user_id = UUID(token_payload["sub"])
    if requesting_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You can only access your own resources"
        )
