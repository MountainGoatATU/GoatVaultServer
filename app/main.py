import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.middleware.exceptions import ExceptionMiddleware

from app.database.database import close_db, init_db
from app.middleware import RequestLoggingMiddleware
from app.routes import auth_route, user_route
from app.utils import validation_exception_handler

_ = load_dotenv()

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(app)  # create Mongo client and db bound to this event loop
    yield
    close_db(app)  # close client when Lambda container freezes or shuts down


app = FastAPI(
    title="GoatVaultServer",
    description="A server for GoatVault",
    version="1.3.0",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "version": app.version}


app.state.limiter = auth_route.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # ty:ignore[invalid-argument-type]
app.add_exception_handler(RequestValidationError, validation_exception_handler)  # ty:ignore[invalid-argument-type]

app.add_middleware(ServerErrorMiddleware)  # ty:ignore[invalid-argument-type]
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)  # ty:ignore[invalid-argument-type]
app.add_middleware(ExceptionMiddleware)  # ty:ignore[invalid-argument-type]
app.add_middleware(RequestLoggingMiddleware)  # ty:ignore[invalid-argument-type]

app.include_router(user_route.user_router, prefix="/v1")
app.include_router(auth_route.auth_router, prefix="/v1")
