from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from app.models import NonceModel, RefreshTokenModel, User


class UserRepository(Protocol):
    async def insert(self, user: User) -> User:
        """Persist a new user and return the stored record."""
        ...

    async def find_by_id(self, user_id: UUID) -> User | None:
        """Return the user with this id, or None."""
        ...

    async def find_by_email(self, email: str) -> User | None:
        """Return the user with this email, or None."""
        ...

    async def email_taken(self, email: str, exclude_id: UUID | None = None) -> bool:
        """Return True if a user other than `exclude_id` already owns this email."""
        ...

    async def update_profile(self, user_id: UUID, changes: dict[str, Any]) -> User | None:
        """Apply partial changes and return the updated user, or None if not found."""
        ...

    async def mark_email_verified(self, user_id: UUID) -> None:
        """Set the user's email_verified flag."""
        ...

    async def delete(self, user_id: UUID) -> bool:
        """Delete the user; return True if a record was removed."""
        ...


class NonceRepository(Protocol):
    async def insert(self, nonce: NonceModel) -> None:
        """Store a newly generated nonce."""
        ...

    async def find_latest_for_user(self, user_id: UUID) -> NonceModel | None:
        """Return the most recently created nonce for a user, or None."""
        ...

    async def delete(self, nonce_id: UUID) -> None:
        """Remove a single nonce (called once it has been consumed)."""
        ...

    async def delete_expired(self, now: datetime) -> int:
        """Delete nonces that expired before `now`; return the count removed."""
        ...


class RefreshTokenRepository(Protocol):
    async def insert(self, record: RefreshTokenModel) -> None:
        """Store a new refresh token record."""
        ...

    async def find_by_hash(self, token_hash: str) -> RefreshTokenModel | None:
        """Look up a refresh token by the hash of its raw value, or None."""
        ...

    async def claim(self, token_hash: str, now: datetime) -> RefreshTokenModel | None:
        """Atomically revoke a still-valid token and return it.

        Returns None if the token is missing, already revoked, or expired.
        """
        ...

    async def revoke_by_hash(self, token_hash: str) -> bool:
        """Revoke a token by hash; return True if it was revoked."""
        ...

    async def delete_expired(self, now: datetime) -> int:
        """Delete expired token records; return the count removed."""
