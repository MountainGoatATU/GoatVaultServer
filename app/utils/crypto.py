import base64
import hashlib
import logging
import secrets

_logger = logging.getLogger(__name__)

_AES_NONCE_LENGTH: int = 12
_SALT_LENGTH: int = 32
_NONCE_LENGTH: int = 32

########################################################################
# Generate Bytes
########################################################################


def _generate_aes_nonce() -> bytes:
    """Generate a random nonce for AES."""
    nonce: bytes = secrets.token_bytes(_AES_NONCE_LENGTH)
    return nonce


def generate_salt() -> bytes:
    """Generate a random salt for password hashing."""
    salt: bytes = secrets.token_bytes(_SALT_LENGTH)
    return salt


def generate_nonce() -> bytes:
    """Generate a random nonce for CSRF protection."""
    nonce: bytes = secrets.token_bytes(_NONCE_LENGTH)
    return nonce


########################################################################
# Hashing
########################################################################


def hash_token(raw_token: str) -> str:
    """Hash a refresh token for storage (SHA256 hex)."""
    _logger.info("Hashing refresh token")
    hash = hashlib.sha256()
    hash.update(raw_token.encode("utf-8"))
    _logger.info(f"Hashed token: {hash.hexdigest()}")
    return hash.hexdigest()


########################################################################
# MFA Encryption
########################################################################


def _load_mfa_secret_key() -> bytes:
    import os

    from dotenv import load_dotenv

    load_dotenv()

    mfa_secret_key: str = os.environ.get("MFA_SECRET_KEY", "").strip().replace("\n", "")
    if not mfa_secret_key:
        raise Exception("MFA_SECRET_KEY missing")

    # Fix base64 padding if missing
    missing_padding: int = len(mfa_secret_key) % 4
    if missing_padding:
        mfa_secret_key += "=" * (4 - missing_padding)

    try:
        return base64.b64decode(mfa_secret_key)
    except Exception as e:
        raise Exception(f"Failed to decode MFA_SECRET_KEY: {e}") from e


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypt client-generated MFA secret for DB storage"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    mfa_secret_key: bytes = _load_mfa_secret_key()
    aes = AESGCM(mfa_secret_key)

    plaintext: bytes = secret.encode("utf-8")
    nonce: bytes = _generate_aes_nonce()
    ciphertext: bytes = aes.encrypt(nonce, plaintext, None)
    combined: bytes = nonce + ciphertext

    return base64.b64encode(combined).decode("ascii")


def decrypt_mfa_secret(secret: str) -> str:
    """Decrypt server-generated MFA secret from DB storage"""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    mfa_secret_key: bytes = _load_mfa_secret_key()
    aes = AESGCM(mfa_secret_key)

    combined: bytes = base64.b64decode(secret)
    nonce: bytes = combined[:_AES_NONCE_LENGTH]
    ciphertext: bytes = combined[_AES_NONCE_LENGTH:]

    plaintext: bytes = aes.decrypt(nonce, ciphertext, None)
    mfa_secret: str = plaintext.decode("utf-8")
    return mfa_secret
