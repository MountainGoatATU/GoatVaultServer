from typing import Annotated

from fastapi impoSQLrt Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from supabase import AsyncClient, AsyncClientOptions, create_async_client

from app.core.config import settings


async def get_supabase_client() -> AsyncClient:
    """for validation access_token init at life span event"""
    supabase_client: AsyncClient = await create_async_client(
        supabase_url=settings.SUPABASE_URL,
        supabase_key=settings.SUPABASE_KEY,
        options=AsyncClientOptions(postgrest_client_timeout=10, storage_client_timeout=10),
    )
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Super client not initialized")
    return supabase_client


SupabaseClient = Annotated[AsyncClient, Depends(get_supabase_client)]


# auto get token from header
reusable_oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")
TokenDep = Annotated[str, Depends(reusable_oauth2)]
