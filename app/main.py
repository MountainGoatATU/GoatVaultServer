from contextlib import asynccontextmanager
import os

from app.database.database import close_db, init_db
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.middleware.exceptions import ExceptionMiddleware

from app.middleware import RequestLoggingMiddleware
from app.routes import auth_route, user_route
from app.utils import validation_exception_handler

_ = load_dotenv()

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(app)      # create Mongo client and db bound to this event loop
    yield
    close_db(app)     # close client when Lambda container freezes or shuts down

app = FastAPI(
    title="GoatVaultServer",
    description="A server for GoatVault",
    version="1.3.0",
    lifespan=lifespan
)

app.state.limiter = auth_route.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

app.add_middleware(ServerErrorMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)
app.add_middleware(ExceptionMiddleware)
app.add_middleware(RequestLoggingMiddleware)

app.include_router(user_route.user_router, prefix="/v1")
app.include_router(auth_route.auth_router, prefix="/v1")
