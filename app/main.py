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

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8000").split(",")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Handle application startup and shutdown events.
    """
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

# Add rate limiter state
app.state.limiter = auth_route.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(ServerErrorMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)
app.add_middleware(ExceptionMiddleware)

# Production-only middleware
if ENVIRONMENT == "production":
    app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
else:
    # Development: Allow all origins for easier testing
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


app.include_router(user_route.user_router, prefix="/v1")
app.include_router(auth_route.auth_router, prefix="/v1")


@app.get("/")
async def root():
    """
    Root endpoint for GoatVault Server.
    """
    return {
        "message": "GoatVault API",
        "docs": "/docs",
    }
