from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import (
    get_nonce_repository,
    get_refresh_token_repository,
    get_user_repository,
)
from app.models import (
    AuthInitRequest,
    AuthInitResponse,
    AuthLogoutResponse,
    AuthRefreshRequest,
    AuthRefreshResponse,
    AuthRegisterRequest,
    AuthRegisterResponse,
    AuthVerifyRequest,
    AuthVerifyResponse,
)
from app.repositories import NonceRepository, RefreshTokenRepository, UserRepository
from app.services import (
    init_auth,
    logout_user,
    new_refresh_token,
    register_user,
    verify_auth,
    verify_email,
)

limiter = Limiter(key_func=get_remote_address)

auth_router = APIRouter(prefix="/auth", tags=["auth"])

########################################################################
# POST /v1/auth/register
########################################################################


@auth_router.post(
    "/register",
    response_description="Register new user",
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("2/minute")
async def register(
    request: Request,
    payload: Annotated[AuthRegisterRequest, Body()],
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
) -> AuthRegisterResponse:
    """Register new user."""
    return await register_user(request, payload, user_repo)


########################################################################
# GET /v1/auth/email/{token}
########################################################################


@auth_router.get(
    "/email/{token}", response_description="Verify email", status_code=status.HTTP_200_OK
)
@limiter.limit("5/minute")
async def email(
    request: Request,  # noqa: ARG001
    token: str,
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
) -> dict:
    """Verify email using JWT token."""
    return await verify_email(token, user_repo)


########################################################################
# POST /v1/auth/init
########################################################################


@auth_router.post(
    "/init",
    response_description="Look up user by email",
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def init(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthInitRequest, Body()],
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    nonce_repo: Annotated[NonceRepository, Depends(get_nonce_repository)],
) -> AuthInitResponse:
    """Look up user by email.
    - Verify that user exists.
    - Return details including `authSalt` and encrypted `vault`.
    """
    return await init_auth(payload, user_repo, nonce_repo)


########################################################################
# POST /v1/auth/verify
########################################################################


@auth_router.post(
    "/verify",
    response_description="Verify auth proof",
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def verify(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthVerifyRequest, Body()],
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    nonce_repo: Annotated[NonceRepository, Depends(get_nonce_repository)],
    refresh_repo: Annotated[RefreshTokenRepository, Depends(get_refresh_token_repository)],
) -> AuthVerifyResponse:
    """Return a JWT token for a valid `auth_verifier`.
    - Verifies that user exists.
    - Returns a signed JWT containing the authority claim.
    """
    return await verify_auth(payload, user_repo, nonce_repo, refresh_repo)


########################################################################
# POST /v1/auth/refresh
########################################################################


@auth_router.post("/refresh")
async def refresh(
    request: Request,  # noqa: ARG001
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_repo: Annotated[RefreshTokenRepository, Depends(get_refresh_token_repository)],
) -> AuthRefreshResponse:
    return await new_refresh_token(payload, refresh_repo)


########################################################################
# POST /v1/auth/logout
########################################################################


@auth_router.post("/logout")
async def logout(
    payload: Annotated[AuthRefreshRequest, Body(...)],
    refresh_repo: Annotated[RefreshTokenRepository, Depends(get_refresh_token_repository)],
) -> AuthLogoutResponse:
    return await logout_user(payload, refresh_repo)
