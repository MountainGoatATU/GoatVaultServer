from fastapi import HTTPException, status


class NoFieldsToUpdateException(HTTPException):
    """Raised when an update request has no fields to update."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )


class UserAlreadyExistsException(HTTPException):
    """Raised when attempting to create a user with an existing email."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )


class EmailAlreadyInUseException(HTTPException):
    """Raised when attempting to update to an email that's already taken."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already in use by another user",
        )


class UserCreationFailedException(HTTPException):
    """Raised when user creation fails at database level."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )


class UserUpdateFailedException(HTTPException):
    """Raised when user update fails at database level."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user",
        )


class CredentialsException(HTTPException):
    """Raised when the provided credentials are invalid."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvalidJWTException(HTTPException):
    """Raised when the provided JWT is invalid."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired JWT",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ForbiddenException(HTTPException):
    """Raised when the user attempts to access a resource they are not allowed to."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only access your own resources",
        )


class InvalidRefreshTokenException(HTTPException):
    """Raised when the provided refresh token is invalid."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvalidMfaCodeException(HTTPException):
    """Raised when the provided MFA code doesn't match."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

class EmailNotVerifiedException(HTTPException):
    """Raised when a user tries to log in without verifying their email."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email address not verified. Please verify your email before logging in.",
        )
