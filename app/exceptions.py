from uuid import UUID

from fastapi import HTTPException, status


class NoFieldsToUpdateException(HTTPException):
    """Raised when an update request has no fields to update."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )


class UserNotFoundException(HTTPException):
    """Raised when a user cannot be found."""

    def __init__(self, user_id: UUID):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )


class VaultNotFoundException(HTTPException):
    """Raised when a vault cannot be found."""

    def __init__(self, vault_id: UUID):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault {vault_id} not found",
        )


class UserAlreadyExistsException(HTTPException):
    """Raised when attempting to create a user with an existing email."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )


class EmailAlreadyInUseException(HTTPException):
    """Raised when attempting to update to an email that's already taken."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already in use by another user",
        )


class UserCreationFailedException(HTTPException):
    """Raised when user creation fails at database level."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )


class UserUpdateFailedException(HTTPException):
    """Raised when user update fails at database level."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user",
        )


class VaultCreationFailedException(HTTPException):
    """Raised when vault creation fails at database level."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create vault",
        )
