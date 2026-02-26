import base64
import hashlib
import logging
import secrets

logger = logging.getLogger(__name__)

SALT_LENGTH: int = 32
NONCE_LENGTH: int = 32
AES_NONCE_LENGTH: int = 12

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


def generate_aes_nonce() -> bytes:
    """Generate a random nonce for CSRF protection."""
    nonce: bytes = secrets.token_bytes(AES_NONCE_LENGTH)
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


########################################################################
# MFA Encryption
########################################################################


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypt client-generated MFA secret for DB storage"""
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from dotenv import load_dotenv

    load_dotenv()

    MFA_SECRET_KEY: str | None = os.getenv("MFA_SECRET_KEY")
    if not MFA_SECRET_KEY:
        raise ValueError("MFA_SECRET_KEY environment variable is required")

    if not MFA_SECRET_KEY:
        raise Exception("MFA_SECRET_KEY missing")

    server_key: bytes = base64.b64decode(MFA_SECRET_KEY)
    aes = AESGCM(server_key)

    plaintext: bytes = secret.encode("utf-8")
    nonce: bytes = generate_aes_nonce()
    ciphertext: bytes = aes.encrypt(nonce, plaintext, None)
    combined: bytes = nonce + ciphertext

    return base64.b64encode(combined).decode("ascii")


def decrypt_mfa_secret(secret: str) -> str:
    """Decrypt server-generated MFA secret from DB storage"""
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from dotenv import load_dotenv

    load_dotenv()

    MFA_SECRET_KEY: str | None = os.getenv("MFA_SECRET_KEY")
    if not MFA_SECRET_KEY:
        raise ValueError("MFA_SECRET_KEY environment variable is required")

    if not MFA_SECRET_KEY:
        raise Exception("MFA_SECRET_KEY missing")

    server_key: bytes = base64.b64decode(MFA_SECRET_KEY)
    aes = AESGCM(server_key)
    combined: bytes = base64.b64decode(secret)
    nonce: bytes = combined[:AES_NONCE_LENGTH]
    ciphertext: bytes = combined[AES_NONCE_LENGTH:]

    plaintext: bytes = aes.decrypt(nonce, ciphertext, None)
    mfa_secret: str = plaintext.decode("utf-8")
    return mfa_secret
