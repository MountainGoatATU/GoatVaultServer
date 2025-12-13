import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.middleware.exceptions import ExceptionMiddleware

from app.database import create_indexes
from app.middleware import RequestLoggingMiddleware
from app.routes import auth_route, user_route
from app.utils import validation_exception_handler

_ = load_dotenv()

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()

PROD_SERVER_URL: str | None = os.getenv("PROD_SERVER_URL")
DEV_SERVER_URL: str | None = os.getenv("DEV_SERVER_URL")
LOCAL_SERVER_URL: str = os.getenv("LOCAL_SERVER_URL", "http://localhost:8000")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Handle application startup and shutdown events."""
    await create_indexes()
    yield


servers: list = []
if PROD_SERVER_URL:
    servers.append({"url": PROD_SERVER_URL, "description": "Production"})
if DEV_SERVER_URL:
    servers.append({"url": DEV_SERVER_URL, "description": "Development"})
if LOCAL_SERVER_URL:
    servers.append({"url": LOCAL_SERVER_URL, "description": "Local development"})

app = FastAPI(
    title="GoatVaultServer",
    description="A server for GoatVault",
    swagger_ui_parameters={
        "persistAuthorization": True,
    },
    lifespan=lifespan,
    version="1.3.0",
    servers=servers,
)

app.state.limiter = auth_route.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
app.add_middleware(ServerErrorMiddleware)  # type: ignore[arg-type]
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)  # type: ignore[arg-type]
app.add_middleware(ExceptionMiddleware)  # type: ignore[arg-type]

if ENVIRONMENT == "production":
    app.add_middleware(HTTPSRedirectMiddleware)  # type: ignore[arg-type]
else:
    app.add_middleware(RequestLoggingMiddleware)  # type: ignore[arg-type]

app.include_router(user_route.user_router, prefix="/v1")
app.include_router(auth_route.auth_router, prefix="/v1")


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint for GoatVault Server."""
    return {
        "message": "GoatVault API",
        "docs": "/docs",
    }
