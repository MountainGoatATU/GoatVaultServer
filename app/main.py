from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.middleware.exceptions import ExceptionMiddleware

# from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from app.database import create_indexes
from app.routes import user_route

_ = load_dotenv()


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

app.add_middleware(ServerErrorMiddleware)
# app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)
app.add_middleware(ExceptionMiddleware)


app.include_router(user_route.user_router, prefix="/v1")


@app.get("/")
async def root():
    """
    Root endpoint for GoatVault Server.
    """
    return {
        "message": "GoatVault API",
        "docs": "/docs",
    }
