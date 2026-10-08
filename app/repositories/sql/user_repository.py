from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import User
from app.repositories.sql.mapping import (
    entity_to_user,
    profile_changes_to_columns,
    user_to_entity,
)
from app.repositories.sql.models import UserRow


class SqlUserRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def insert(self, user: User) -> User:
        async with self._session_factory() as session:
            session.add(user_to_entity(user))
            await session.commit()
        return user

    async def find_by_id(self, user_id: UUID) -> User | None:
        async with self._session_factory() as session:
            row = await session.get(UserRow, user_id)
            return entity_to_user(row) if row else None

    async def find_by_email(self, email: str) -> User | None:
        statement = select(UserRow).where(UserRow.email == email)
        async with self._session_factory() as session:
            row = (await session.execute(statement)).scalars().first()
            return entity_to_user(row) if row else None

    async def email_taken(self, email: str, exclude_id: UUID | None = None) -> bool:
        statement = select(UserRow.id).where(UserRow.email == email)
        if exclude_id is not None:
            statement = statement.where(UserRow.id != exclude_id)
        async with self._session_factory() as session:
            return (await session.execute(statement)).first() is not None

    async def update_profile(self, user_id: UUID, changes: dict[str, Any]) -> User | None:
        columns = profile_changes_to_columns(changes)
        async with self._session_factory() as session:
            row = await session.get(UserRow, user_id)
            if row is None:
                return None
            for attribute, value in columns.items():
                setattr(row, attribute, value)
            await session.commit()
            return entity_to_user(row)

    async def mark_email_verified(self, user_id: UUID) -> None:
        async with self._session_factory() as session:
            row = await session.get(UserRow, user_id)
            if row is None:
                return
            row.email_verified = True
            await session.commit()

    async def delete(self, user_id: UUID) -> bool:
        statement = (
            delete(UserRow)
            .where(UserRow.id == user_id)
            .execution_options(synchronize_session=False)
        )
        async with self._session_factory() as session:
            result = await session.execute(statement)
            await session.commit()
            return result.rowcount > 0
