from fastapi import APIRouter, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

auth_router = APIRouter(prefix="/auth", tags=["auth"])

########################################################################
# POST /v1/auth/register
########################################################################


@auth_router.post(
    "/register", response_description="Register new user", status_code=status.HTTP_201_CREATED
)
@limiter.limit("2/minute")
async def register(request: Request):
    """Register new user."""
    ...


########################################################################
# GET /v1/auth/email/{token}
########################################################################


@auth_router.get(
    "/email/{token}", response_description="Verify email", status_code=status.HTTP_200_OK
)
@limiter.limit("5/minute")
async def email(request: Request, token: str):
    """Verify email using JWT token."""
    ...


########################################################################
# POST /v1/auth/init
########################################################################


@auth_router.post(
    "/init", response_description="Look up user by email", status_code=status.HTTP_200_OK
)
@limiter.limit("5/minute")
async def init(request: Request):
    """Look up user by email.
    - Verify that user exists.
    - Return details including `authSalt` and encrypted `vault`.
    """
    ...


########################################################################
# POST /v1/auth/verify
########################################################################


@auth_router.post(
    "/verify", response_description="Verify auth proof", status_code=status.HTTP_200_OK
)
@limiter.limit("5/minute")
async def verify(request: Request):
    """Return a JWT token for a valid `auth_verifier`.
    - Verifies that user exists.
    - Returns a signed JWT containing the authority claim.
    """
    ...


########################################################################
# POST /v1/auth/refresh
########################################################################


@auth_router.post("/refresh")
async def refresh(request: Request): ...


########################################################################
# POST /v1/auth/logout
########################################################################


@auth_router.post("/logout")
async def logout(): ...
