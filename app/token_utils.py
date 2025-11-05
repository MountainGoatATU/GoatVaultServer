import os
from datetime import datetime, timedelta, UTC
from uuid import UUID
import jwt

from dotenv import load_dotenv
from fastapi import HTTPException, status

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
AUTHORITY = os.getenv("AUTHORITY")
TOKEN_EXP_HOURS = int(os.getenv("TOKEN_EXP_HOURS", 12))


def create_jwt_token(user_id: UUID) -> str:
    """Generate a signed JWT for a given user UUID."""
    expire = datetime.now(UTC) + timedelta(hours=TOKEN_EXP_HOURS)

    payload = {
        "sub": str(user_id),         # Subject (the user)
        "authority": AUTHORITY,      # Server name issuing token
        "iss": AUTHORITY,            # Standard JWT claim (issuer)
        "exp": expire,               # Expiration time
        "iat": datetime.now(UTC),    # Issued at
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token: str) -> dict:
    """Decode and verify a JWT token, ensuring authority matches."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    authority = payload.get("authority")
    if authority != AUTHORITY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token authority"
        )

    return payload