import os
from typing import Annotated

from dotenv import load_dotenv
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

_ = load_dotenv()

API_KEY: str | None = os.getenv("API_KEY")

if not API_KEY:
    raise ValueError("API_KEY environment variable is required. ")

api_key_header: APIKeyHeader = APIKeyHeader(name="X-API-Key", auto_error=True)


async def verify_api_key(api_key: Annotated[str, Security(api_key_header)]) -> str:
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    return api_key
