from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import NonceModel
from app.repositories.sql.mapping import entity_to_nonce, nonce_to_entity
from app.repositories.sql.models import NonceRow


class SqlNonceRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def insert(self, nonce: NonceModel) -> None:
        async with self._session_factory() as session:
            session.add(nonce_to_entity(nonce))
            await session.commit()

    async def find_latest_for_user(self, user_id: UUID) -> NonceModel | None:
        statement = (
            select(NonceRow)
            .where(NonceRow.user_id == user_id)
            .order_by(NonceRow.created_at_utc.desc())
            .limit(1)
        )
        async with self._session_factory() as session:
            row = (await session.execute(statement)).scalars().first()
            return entity_to_nonce(row) if row else None

    async def delete(self, nonce_id: UUID) -> None:
        statement = (
            delete(NonceRow)
            .where(NonceRow.id == nonce_id)
            .execution_options(synchronize_session=False)
        )
        async with self._session_factory() as session:
            await session.execute(statement)
            await session.commit()

    async def delete_expired(self, now: datetime) -> int:
        statement = (
            delete(NonceRow)
            .where(NonceRow.expires_at_utc < now)
            .execution_options(synchronize_session=False)
        )
        async with self._session_factory() as session:
            result = await session.execute(statement)
            await session.commit()
            return result.rowcount
