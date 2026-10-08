from typing import Protocol

from app.repositories import NonceRepository, RefreshTokenRepository, UserRepository


class DatabaseBackend(Protocol):
    user_repository: UserRepository
    nonce_repository: NonceRepository
    refresh_token_repository: RefreshTokenRepository

    async def ensure_indexes(self) -> None: ...

    async def close(self) -> None: ...
