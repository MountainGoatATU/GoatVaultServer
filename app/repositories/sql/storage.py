from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.repositories.sql.engine import (
    create_engine,
    create_schema,
    create_session_factory,
    dispose_engine,
)
from app.repositories.sql.nonce_repository import SqlNonceRepository
from app.repositories.sql.refresh_token_repository import SqlRefreshTokenRepository
from app.repositories.sql.user_repository import SqlUserRepository


@dataclass
class SqlStorage:
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    user_repository: SqlUserRepository
    nonce_repository: SqlNonceRepository
    refresh_token_repository: SqlRefreshTokenRepository

    @classmethod
    def create(cls) -> "SqlStorage":
        engine = create_engine()
        session_factory = create_session_factory(engine)
        return cls(
            engine=engine,
            session_factory=session_factory,
            user_repository=SqlUserRepository(session_factory),
            nonce_repository=SqlNonceRepository(session_factory),
            refresh_token_repository=SqlRefreshTokenRepository(session_factory),
        )

    async def ensure_indexes(self) -> None:
        await create_schema(self.engine)

    async def close(self) -> None:
        await dispose_engine(self.engine)
