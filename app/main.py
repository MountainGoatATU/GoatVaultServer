import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.middleware.exceptions import ExceptionMiddleware

from app.database import create_indexes
from app.routes import auth_route, user_route

_ = load_dotenv()

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8000").split(",")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Handle application startup and shutdown events."""
    await create_indexes()
    yield


app = FastAPI(
    title="GoatVaultServer",
    description="A server for GoatVault",
    swagger_ui_parameters={
        "persistAuthorization": True,
    },
    lifespan=lifespan,
)

app.state.limiter = auth_route.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

app.add_middleware(ServerErrorMiddleware)  # type: ignore[arg-type]
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)  # type: ignore[arg-type]
app.add_middleware(ExceptionMiddleware)  # type: ignore[arg-type]

if ENVIRONMENT == "production":
    app.add_middleware(HTTPSRedirectMiddleware)  # type: ignore[arg-type]
    app.add_middleware(
        CORSMiddleware,  # type: ignore[arg-type]
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
else:
    app.add_middleware(
        CORSMiddleware,  # type: ignore[arg-type]
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


app.include_router(user_route.user_router, prefix="/v1")
app.include_router(auth_route.auth_router, prefix="/v1")


@app.get("/")
async def root():
    """Root endpoint for GoatVault Server."""
    return {
        "message": "GoatVault API",
        "docs": "/docs",
    }
