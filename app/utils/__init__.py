from app.utils.auth import create_jwt_token, verify_mfa, verify_token, verify_user_access
from app.utils.exceptions import (
    EmailAlreadyInUseException,
    InvalidAuthVerifierException,
    InvalidMfaCodeException,
    MfaCodeRequiredException,
    NoFieldsToUpdateException,
    UserAlreadyExistsException,
    UserCreationFailedException,
    UserNotFoundByEmailException,
    UserNotFoundException,
    UserUpdateFailedException,
)
from app.utils.validators import (
    sanitize_validation_error,
    validate_email_available,
    validate_email_available_for_user,
    validation_exception_handler,
)

__all__: list[str] = [
    "create_jwt_token",
    "verify_token",
    "verify_mfa",
    "verify_user_access",
    "EmailAlreadyInUseException",
    "InvalidAuthVerifierException",
    "InvalidMfaCodeException",
    "MfaCodeRequiredException",
    "NoFieldsToUpdateException",
    "UserAlreadyExistsException",
    "UserCreationFailedException",
    "UserNotFoundByEmailException",
    "UserNotFoundException",
    "UserUpdateFailedException",
    "sanitize_validation_error",
    "validate_email_available",
    "validate_email_available_for_user",
    "validation_exception_handler",
]
