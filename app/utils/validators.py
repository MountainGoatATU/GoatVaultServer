import base64
import json
import logging
from uuid import UUID

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from app.database import get_user_collection
from app.exceptions import UserAlreadyExistsException
from app.exceptions.exceptions import EmailAlreadyInUseException
from app.models import User

_logger = logging.getLogger(__name__)


########################################################################
# Email Validation
########################################################################


async def validate_email_available(
    request: Request, email: str, user_id: UUID | None = None
) -> None:
    """Validate that an email is not already registered."""
    user_collection = get_user_collection(request)

    if not user_id:
        existing: User | None = await user_collection.find_one({"email": email})
        if existing:
            raise UserAlreadyExistsException
    else:
        existing: User | None = await user_collection.find_one(
            {"email": email, "_id": {"$ne": user_id}}
        )
        if existing:
            raise EmailAlreadyInUseException


########################################################################
# Validation Error Sanitization
########################################################################


def sanitize_validation_error(error_dict: dict) -> dict:
    """Sanitize validation errors to handle bytes that can't be encoded as UTF-8."""
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
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Custom handler for RequestValidationError that safely handles bytes in error details."""
    errors = exc.errors()
    sanitized_errors = [sanitize_validation_error(error) for error in errors]

    # Log detailed validation error information
    _logger.error("=" * 80)
    _logger.error(f"VALIDATION ERROR on {request.method} {request.url.path}")
    _logger.error(f"Number of validation errors: {len(errors)}")
    _logger.error(f"Validation errors: {json.dumps(sanitized_errors, indent=2)}")
    _logger.error("=" * 80)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": sanitized_errors},
    )
