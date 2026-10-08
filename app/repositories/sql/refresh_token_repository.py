from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import RefreshTokenModel
from app.repositories.sql.mapping import entity_to_refresh_token, refresh_token_to_entity
from app.repositories.sql.models import RefreshTokenRow


class SqlRefreshTokenRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def insert(self, record: RefreshTokenModel) -> None:
        async with self._session_factory() as session:
            session.add(refresh_token_to_entity(record))
            await session.commit()

    async def find_by_hash(self, token_hash: str) -> RefreshTokenModel | None:
        statement = select(RefreshTokenRow).where(RefreshTokenRow.token_hash == token_hash)
        async with self._session_factory() as session:
            row = (await session.execute(statement)).scalars().first()
            return entity_to_refresh_token(row) if row else None

    async def claim(self, token_hash: str, now: datetime) -> RefreshTokenModel | None:
        claim_statement = (
            update(RefreshTokenRow)
            .where(RefreshTokenRow.token_hash == token_hash)
            .where(RefreshTokenRow.revoked.is_(False))
            .where(RefreshTokenRow.expires_at_utc > now)
            .values(revoked=True)
            .execution_options(synchronize_session=False)
        )
        async with self._session_factory() as session:
            result = await session.execute(claim_statement)
            if result.rowcount == 0:
                return None
            row = (
                (
                    await session.execute(
                        select(RefreshTokenRow).where(RefreshTokenRow.token_hash == token_hash)
                    )
                )
                .scalars()
                .first()
            )
            await session.commit()
            return entity_to_refresh_token(row) if row else None

    async def revoke_by_hash(self, token_hash: str) -> bool:
        statement = (
            update(RefreshTokenRow)
            .where(RefreshTokenRow.token_hash == token_hash)
            .where(RefreshTokenRow.revoked.is_(False))
            .values(revoked=True)
            .execution_options(synchronize_session=False)
        )
        async with self._session_factory() as session:
            result = await session.execute(statement)
            await session.commit()
            return result.rowcount > 0

    async def delete_expired(self, now: datetime) -> int:
        statement = (
            delete(RefreshTokenRow)
            .where(RefreshTokenRow.expires_at_utc < now)
            .execution_options(synchronize_session=False)
        )
        async with self._session_factory() as session:
            result = await session.execute(statement)
            await session.commit()
            return result.rowcount
