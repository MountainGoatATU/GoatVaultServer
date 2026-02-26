import logging
import os
from typing import Any

from fastapi import FastAPI, Request
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase

_logger = logging.getLogger(__name__)

########################################################################
# Init / Close Database
########################################################################


def init_db(app: FastAPI) -> None:
    """
    Attach Mongo client and database to FastAPI app state.
    Should be called in FastAPI lifespan.
    """
    app.state.mongo_client = AsyncIOMotorClient(
        os.environ["MONGODB_URL"], uuidRepresentation="standard"
    )
    app.state.db: AsyncIOMotorDatabase = app.state.mongo_client[os.environ["DATABASE_NAME"]]
    _logger.info("Database initialized")


def close_db(app: FastAPI) -> None:
    """
    Close the Mongo client when the app shuts down.
    """
    client: Any | None = getattr(app.state, "mongo_client", None)
    if client:
        client.close()
        _logger.info("Database closed")


########################################################################
# Get Collections From Database
########################################################################


def get_user_collection(request: Request) -> AsyncIOMotorCollection:
    """Dependency that returns the users collection from app state database."""
    _logger.info("Getting user collection")
    return request.app.state.db["users"]


def get_refresh_collection(request: Request) -> AsyncIOMotorCollection:
    """Dependency that returns the refresh_tokens collection from app state database."""
    _logger.info("Getting refresh collection")
    return request.app.state.db["refresh_tokens"]


def get_nonce_collection(request: Request) -> AsyncIOMotorCollection:
    """Dependency that returns the nonces collection from app state database."""
    _logger.info("Getting nonce collection")
    return request.app.state.db["nonces"]
