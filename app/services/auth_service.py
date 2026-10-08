import hmac
import logging
import uuid
from hashlib import sha256
from logging import Logger
from uuid import UUID

from fastapi import Request

from app.exceptions import UserCreationFailedException
from app.exceptions.exceptions import (
    CredentialsException,
    EmailNotVerifiedException,
    InvalidMfaCodeException,
    InvalidRefreshTokenException,
)
from app.models import (
    AuthInitRequest,
    AuthInitResponse,
    AuthLogoutResponse,
    AuthRefreshRequest,
    AuthRefreshResponse,
    AuthRegisterRequest,
    AuthRegisterResponse,
    AuthVerifyRequest,
    AuthVerifyResponse,
    NonceModel,
    User,
)
from app.repositories import NonceRepository, RefreshTokenRepository, UserRepository
from app.utils import (
    create_access_token,
    create_email_verification_access_token,
    create_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
    send_verification_email,
    store_refresh_token,
    validate_email_available,
    verify_mfa,
    verify_refresh_token,
)
from app.utils.auth import ISSUER, JWT_ALGORITHM, MAIL_SECRET, jwt
from app.utils.crypto import generate_nonce, generate_salt
from app.utils.time import ensure_aware, get_now, get_now_plus_two_minutes

_logger: Logger = logging.getLogger(__name__)

########################################################################
# Register New User
########################################################################


async def register_user(
    request: Request,
    payload: AuthRegisterRequest,
    user_repo: UserRepository,
) -> AuthRegisterResponse:
    """Register new user."""
    _logger.info(f"Registering new user with email: {payload.email}")
    await validate_email_available(request, payload.email)

    new_user = User(
        email=payload.email,
        auth_salt=payload.auth_salt,
        auth_verifier=payload.auth_verifier,
        mfa_enabled=payload.mfa_enabled | False,
        mfa_secret=payload.mfa_secret,
        shamir_enabled=payload.shamir_enabled,
        vault_salt=payload.vault_salt,
        vault=payload.vault,
        argon2_parameters=payload.argon2_parameters,
        email_verified=False,
    )

    verification_token: str = create_email_verification_access_token(new_user.id)

    try:
        created_user: User = await user_repo.insert(new_user)
    except Exception as e:
        _logger.error(f"Failed to create user: {payload.email}: {e}")
        raise UserCreationFailedException from e

    try:
        await send_verification_email(payload.email, verification_token)
        _logger.info(f"Verification email sent to: {payload.email}")
    except Exception as e:
        _logger.error(f"Failed to send verification email: {e}")

    _logger.info(f"User registered successfully: {payload.email}")

    return AuthRegisterResponse(
        id=created_user.id,
        email=created_user.email,
        created_at_utc=created_user.created_at_utc,
    )


########################################################################
# Verify User Email
########################################################################


async def verify_email(token: str, user_repo: UserRepository) -> dict:
    try:
        payload: dict[str, str] = jwt.decode(
            token,
            MAIL_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "iss"]},
        )
    except Exception:
        return {"success": False, "message": "Invalid or expired verification token."}

    if payload.get("iss") != ISSUER:
        return {"success": False, "message": "Invalid token issuer."}
    if payload.get("purpose") != "email_verification":
        return {"success": False, "message": "Invalid token purpose."}

    user_id = UUID(payload.get("sub"))
    user = await user_repo.find_by_id(user_id)
    if user is None:
        return {"success": False, "message": "User not found."}
    if user.email_verified:
        return {"success": True, "message": "Email already verified."}

    await user_repo.mark_email_verified(user.id)
    return {"success": True, "message": "Email successfully verified."}


########################################################################
# Initiate User Authentication
########################################################################


async def init_auth(
    payload: AuthInitRequest,
    user_repo: UserRepository,
    nonce_repo: NonceRepository,
) -> AuthInitResponse:
    _logger.info(f"Auth init requested for email: {payload.email}")

    user = await user_repo.find_by_email(payload.email)
    nonce: bytes = generate_nonce()

    # Return fake response if user not found
    if user is None:
        _logger.warning(f"User not found for auth init: {payload.email}")
        return AuthInitResponse(
            id=uuid.uuid4(),
            auth_salt=generate_salt(),
            nonce=nonce,
            mfa_enabled=False,
            shamir_enabled=False,
        )

    nonce_record = NonceModel(
        user_id=user.id,
        nonce=nonce,
        created_at_utc=get_now(),
        expires_at_utc=get_now_plus_two_minutes(),
    )
    await nonce_repo.insert(nonce_record)

    _logger.info(f"Auth init successful for user: {user.id}")
    return AuthInitResponse(
        id=user.id,
        auth_salt=user.auth_salt,
        nonce=nonce,
        mfa_enabled=user.mfa_enabled,
        shamir_enabled=user.shamir_enabled,
    )


########################################################################
# Verify User Authentication
########################################################################


async def verify_auth(
    payload: AuthVerifyRequest,
    user_repo: UserRepository,
    nonce_repo: NonceRepository,
    refresh_repo: RefreshTokenRepository,
) -> AuthVerifyResponse:
    _logger.info(f"Auth verification requested for user: {payload.id}")

    # Find user
    user = await user_repo.find_by_id(payload.id)
    if user is None:
        _logger.warning(f"User not found during verification: {payload.id}")
        raise CredentialsException

    # Check if email is verified
    if not user.email_verified:
        _logger.warning(f"User {payload.id} tried to login without verifying email")
        raise EmailNotVerifiedException

    # Find the most recent valid nonce for this user
    stored_nonce = await nonce_repo.find_latest_for_user(payload.id)
    if stored_nonce is None:
        _logger.warning(f"No nonce found for user: {payload.id}")
        raise CredentialsException

    # Consume the nonce immediately to prevent replay
    await nonce_repo.delete(stored_nonce.id)

    # Check if nonce is expired (double check, though TTL index should handle it eventually)
    if ensure_aware(stored_nonce.expires_at_utc) < get_now():
        _logger.warning(f"Nonce expired for user: {payload.id}")
        raise CredentialsException

    expected_proof: bytes = hmac.new(
        key=user.auth_verifier, msg=stored_nonce.nonce, digestmod=sha256
    ).digest()

    # Compare proofs
    if not hmac.compare_digest(payload.proof, expected_proof):
        _logger.warning(f"Invalid proof provided for user: {payload.id}")
        raise CredentialsException

    # Handle MFA
    if user.mfa_enabled:
        if not payload.mfa_code:
            _logger.warning(f"MFA code required but not provided for user: {payload.id}")
            raise CredentialsException
        if not verify_mfa(payload.mfa_code, user.mfa_secret):
            _logger.warning(f"Invalid MFA code for user: {payload.id}")
            raise InvalidMfaCodeException

    # Issue token
    token: str = create_access_token(payload.id)
    raw_refresh: str = create_refresh_token()
    await store_refresh_token(refresh_repo, payload.id, raw_refresh)

    _logger.info(f"Auth verification successful for user: {payload.id}")
    return AuthVerifyResponse(access_token=token, refresh_token=raw_refresh)


########################################################################
# Rotate Refresh Token
########################################################################


async def new_refresh_token(
    payload: AuthRefreshRequest,
    refresh_repo: RefreshTokenRepository,
) -> AuthRefreshResponse:
    rec = await verify_refresh_token(refresh_repo, payload.refresh_token)
    if rec is None:
        _logger.warning("Invalid or expired refresh token used")
        raise InvalidRefreshTokenException

    rotation = await rotate_refresh_token(refresh_repo, payload.refresh_token, rec.user_id)
    if rotation is None:
        _logger.warning(f"Refresh token rotation failed for user: {rec.user_id}")
        raise InvalidRefreshTokenException

    access: str = create_access_token(rotation.record.user_id)
    _logger.info(f"Token refreshed successfully for user: {rec.user_id}")
    return AuthRefreshResponse(access_token=access, refresh_token=rotation.raw)


########################################################################
# Logout User
########################################################################


async def logout_user(
    payload: AuthRefreshRequest,
    refresh_repo: RefreshTokenRepository,
) -> AuthLogoutResponse:
    raw_refresh: str = payload.refresh_token
    if not raw_refresh:
        _logger.warning("Logout attempted without refresh token")
        raise InvalidRefreshTokenException

    await revoke_refresh_token(refresh_repo, raw_refresh)
    _logger.info("Logout successful (refresh token revoked)")
    return AuthLogoutResponse(status="ok")
