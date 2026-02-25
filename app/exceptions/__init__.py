"""GoatVaultServer exceptions"""

from app.exceptions.exceptions import (
    CredentialsException,
    EmailAlreadyInUseException,
    EmailNotVerifiedException,
    ForbiddenException,
    InvalidJWTException,
    InvalidMfaCodeException,
    InvalidRefreshTokenException,
    NoFieldsToUpdateException,
    UserAlreadyExistsException,
    UserCreationFailedException,
    UserUpdateFailedException,
)

__all__ = [
    CredentialsException,
    EmailAlreadyInUseException,
    EmailNotVerifiedException,
    ForbiddenException,
    InvalidJWTException,
    InvalidMfaCodeException,
    InvalidRefreshTokenException,
    NoFieldsToUpdateException,
    UserAlreadyExistsException,
    UserCreationFailedException,
    UserUpdateFailedException,
]
