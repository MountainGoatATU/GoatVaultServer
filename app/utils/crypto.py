import hashlib
import logging
import secrets

logger = logging.getLogger(__name__)

SALT_LENGTH: int = 32
NONCE_LENGTH: int = 32

########################################################################
# Generate Bytes
########################################################################


def generate_salt() -> bytes:
    """Generate a random salt for password hashing."""
    salt: bytes = secrets.token_bytes(SALT_LENGTH)
    return salt


def generate_nonce() -> bytes:
    """Generate a random nonce for CSRF protection."""
    nonce: bytes = secrets.token_bytes(NONCE_LENGTH)
    return nonce


########################################################################
# Hashing
########################################################################


def hash_token(raw_token: str) -> str:
    """Hash a refresh token for storage (SHA256 hex)."""
    logger.info("Hashing refresh token")
    hash = hashlib.sha256()
    hash.update(raw_token.encode("utf-8"))
    logger.info(f"Hashed token: {hash.hexdigest()}")
    return hash.hexdigest()
