from collections.abc import Mapping
from typing import Any

from app.models import Argon2Parameters, NonceModel, RefreshTokenModel, User
from app.models.vault_model import Vault
from app.repositories.sql.models import NonceRow, RefreshTokenRow, UserRow

_PROFILE_FIELD_TO_COLUMN: dict[str, str] = {
    "email": "email",
    "auth_salt": "auth_salt",
    "auth_verifier": "auth_verifier",
    "mfa_enabled": "mfa_enabled",
    "mfa_secret": "mfa_secret",
    "shamir_enabled": "shamir_enabled",
    "email_verified": "email_verified",
    "vault_salt": "vault_salt",
    "updated_at_utc": "updated_at_utc",
}


def user_to_entity(user: User) -> UserRow:
    return UserRow(
        id=user.id,
        email=user.email,
        auth_salt=user.auth_salt,
        auth_verifier=user.auth_verifier,
        mfa_enabled=user.mfa_enabled,
        mfa_secret=user.mfa_secret,
        shamir_enabled=user.shamir_enabled,
        email_verified=user.email_verified,
        vault_salt=user.vault_salt,
        vault_encrypted_blob=user.vault.encrypted_blob,
        vault_nonce=user.vault.nonce,
        vault_auth_tag=user.vault.auth_tag,
        argon2_time_cost=user.argon2_parameters.time_cost,
        argon2_memory_cost=user.argon2_parameters.memory_cost,
        argon2_lanes=user.argon2_parameters.lanes,
        argon2_threads=user.argon2_parameters.threads,
        argon2_hash_length=user.argon2_parameters.hash_length,
        created_at_utc=user.created_at_utc,
        updated_at_utc=user.updated_at_utc,
    )


def entity_to_user(row: UserRow) -> User:
    return User(
        id=row.id,
        email=row.email,
        auth_salt=bytes(row.auth_salt),
        auth_verifier=bytes(row.auth_verifier),
        mfa_enabled=row.mfa_enabled,
        mfa_secret=row.mfa_secret,
        shamir_enabled=row.shamir_enabled,
        email_verified=row.email_verified,
        vault_salt=bytes(row.vault_salt) if row.vault_salt is not None else None,
        vault=Vault(
            encrypted_blob=bytes(row.vault_encrypted_blob),
            nonce=bytes(row.vault_nonce),
            auth_tag=bytes(row.vault_auth_tag),
        ),
        argon2_parameters=Argon2Parameters(
            time_cost=row.argon2_time_cost,
            memory_cost=row.argon2_memory_cost,
            lanes=row.argon2_lanes,
            threads=row.argon2_threads,
            hash_length=row.argon2_hash_length,
        ),
        created_at_utc=row.created_at_utc,
        updated_at_utc=row.updated_at_utc,
    )


def profile_changes_to_columns(changes: Mapping[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for key, value in changes.items():
        if key == "vault":
            vault = value if isinstance(value, Vault) else Vault(**value)
            row["vault_encrypted_blob"] = vault.encrypted_blob
            row["vault_nonce"] = vault.nonce
            row["vault_auth_tag"] = vault.auth_tag
        elif key == "argon2_parameters":
            params = value if isinstance(value, Argon2Parameters) else Argon2Parameters(**value)
            row["argon2_time_cost"] = params.time_cost
            row["argon2_memory_cost"] = params.memory_cost
            row["argon2_lanes"] = params.lanes
            row["argon2_threads"] = params.threads
            row["argon2_hash_length"] = params.hash_length
        elif key in _PROFILE_FIELD_TO_COLUMN:
            row[_PROFILE_FIELD_TO_COLUMN[key]] = value
    return row


def nonce_to_entity(nonce: NonceModel) -> NonceRow:
    return NonceRow(
        id=nonce.id,
        user_id=nonce.user_id,
        nonce=nonce.nonce,
        created_at_utc=nonce.created_at_utc,
        expires_at_utc=nonce.expires_at_utc,
    )


def entity_to_nonce(row: NonceRow) -> NonceModel:
    return NonceModel(
        id=row.id,
        user_id=row.user_id,
        nonce=bytes(row.nonce),
        created_at_utc=row.created_at_utc,
        expires_at_utc=row.expires_at_utc,
    )


def refresh_token_to_entity(record: RefreshTokenModel) -> RefreshTokenRow:
    return RefreshTokenRow(
        id=record.id,
        user_id=record.user_id,
        token_hash=record.token_hash,
        created_at_utc=record.created_at_utc,
        expires_at_utc=record.expires_at_utc,
        revoked=record.revoked,
    )


def entity_to_refresh_token(row: RefreshTokenRow) -> RefreshTokenModel:
    return RefreshTokenModel(
        id=row.id,
        user_id=row.user_id,
        token_hash=row.token_hash,
        created_at_utc=row.created_at_utc,
        expires_at_utc=row.expires_at_utc,
        revoked=row.revoked,
    )
