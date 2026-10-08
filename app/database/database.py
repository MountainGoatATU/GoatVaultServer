import logging

from fastapi import FastAPI, Request

from app.database.backend import DatabaseBackend
from app.repositories import NonceRepository, RefreshTokenRepository, UserRepository
from app.repositories.sql import SqlStorage

_logger = logging.getLogger(__name__)

########################################################################
# Init / Close Database
########################################################################


async def init_db(app: FastAPI) -> None:
    """Create the storage backend and make sure the schema exists."""
    backend: DatabaseBackend = SqlStorage.create()
    await backend.ensure_indexes()
    app.state.backend = backend
    _logger.info("Database backend initialized")


async def close_db(app: FastAPI) -> None:
    """Dispose the engine on shutdown."""
    backend: DatabaseBackend | None = getattr(app.state, "backend", None)
    if backend is not None:
        await backend.close()
        _logger.info("Database backend closed")


########################################################################
# Repository Dependencies
########################################################################


def get_user_repository(request: Request) -> UserRepository:
    return request.app.state.backend.user_repository


def get_nonce_repository(request: Request) -> NonceRepository:
    return request.app.state.backend.nonce_repository


def get_refresh_token_repository(request: Request) -> RefreshTokenRepository:
    return request.app.state.backend.refresh_token_repository
