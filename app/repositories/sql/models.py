import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase): ...


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(Text, unique=True)
    auth_salt: Mapped[bytes]
    auth_verifier: Mapped[bytes]
    mfa_enabled: Mapped[bool] = mapped_column(default=False)
    mfa_secret: Mapped[str | None] = mapped_column(Text)
    shamir_enabled: Mapped[bool] = mapped_column(default=False)
    email_verified: Mapped[bool] = mapped_column(default=False)
    vault_salt: Mapped[bytes | None]
    vault_encrypted_blob: Mapped[bytes]
    vault_nonce: Mapped[bytes]
    vault_auth_tag: Mapped[bytes]
    argon2_time_cost: Mapped[int]
    argon2_memory_cost: Mapped[int]
    argon2_lanes: Mapped[int]
    argon2_threads: Mapped[int]
    argon2_hash_length: Mapped[int]
    created_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NonceRow(Base):
    __tablename__ = "nonces"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    nonce: Mapped[bytes]
    created_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RefreshTokenRow(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    created_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(default=False)
