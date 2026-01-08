import base64
import json
import logging
from uuid import UUID

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from app.database import get_user_collection
from app.utils import EmailAlreadyInUseException, UserAlreadyExistsException

logger = logging.getLogger(__name__)


async def validate_email_available(email: str) -> None:
    """Validate that an email is not already registered.

    Raises:
        UserAlreadyExistsException: If email is already in use.

    """
    
    user_collection = get_user_collection()
    existing = await user_collection.find_one({"email": email})
    if existing:
        raise UserAlreadyExistsException


async def validate_email_available_for_user(email: str, user_id: UUID) -> None:
    """Validate that an email is available for a specific user to use.

    Allows the user to keep their own email, but prevents using
    another user's email.

    Raises:
        EmailAlreadyInUseException: If email is in use by another user.

    """
    
    user_collection = get_user_collection()
    existing = await user_collection.find_one({"email": email, "_id": {"$ne": user_id}})
    if existing:
        raise EmailAlreadyInUseException


def sanitize_validation_error(error_dict: dict) -> dict:
    """Sanitize validation errors to handle bytes that can't be encoded as UTF-8.

    Converts any bytes in the error 'input' field to base64 strings so they can
    be safely serialized to JSON.
    """
    sanitized: dict = error_dict.copy()

    if "input" in sanitized and isinstance(sanitized["input"], bytes):
        try:
            sanitized["input"] = sanitized["input"].decode("utf-8")
        except UnicodeDecodeError:
            sanitized["input"] = f"<bytes: {base64.b64encode(sanitized['input']).decode('utf-8')}>"

    for key, value in sanitized.items():
        if isinstance(value, dict):
            sanitized[key] = sanitize_validation_error(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_validation_error(item) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, bytes):
            try:
                sanitized[key] = value.decode("utf-8")
            except UnicodeDecodeError:
                sanitized[key] = f"<bytes: {base64.b64encode(value).decode('utf-8')}>"

    return sanitized


async def validation_exception_handler(
    request: Request,  # noqa: ARG001
    exc: RequestValidationError,
) -> JSONResponse:
    """Custom handler for RequestValidationError that safely handles bytes in error details."""
    errors = exc.errors()
    sanitized_errors = [sanitize_validation_error(error) for error in errors]

    # Log detailed validation error information
    logger.error("=" * 80)
    logger.error(f"VALIDATION ERROR on {request.method} {request.url.path}")
    logger.error(f"Number of validation errors: {len(errors)}")
    logger.error(f"Validation errors: {json.dumps(sanitized_errors, indent=2)}")
    logger.error("=" * 80)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": sanitized_errors},
    )
