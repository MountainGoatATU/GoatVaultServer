import logging
import os

from fastapi.responses import JSONResponse
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType, NameEmail
from pydantic import SecretStr

_logger = logging.getLogger(__name__)

_BASE_URL: str | None = os.environ.get("SERVER_URL")

_CONFIG: ConnectionConfig = ConnectionConfig(
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME") or "",
    MAIL_PASSWORD=SecretStr(os.environ.get("MAIL_PASSWORD") or ""),
    MAIL_FROM=os.environ.get("MAIL_FROM") or "",
    MAIL_PORT=int(os.environ.get("MAIL_PORT") or 587),
    MAIL_SERVER=os.environ.get("MAIL_SERVER") or "",
    MAIL_FROM_NAME="Mountain Goat",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)


async def send_verification_email(recipient: str, token: str) -> JSONResponse:
    verification_link: str = f"{_BASE_URL}/v1/auth/email/{token}"

    html: str = f"""
    <html>
        <body>
            <h2>Welcome to <b>GoatVault</b>!</h2>
            <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
            <p><a href='{verification_link}'>Verify Email</a></p>
            <br>
            <p>If you did not register, you can ignore this email.</p>
            <br>
            <p>Best regards,<br>GoatVault Team</p>
        </body>
    </html>
    """

    message = MessageSchema(
        subject="GoatVault - Verify your email",
        recipients=[NameEmail(recipient, recipient)],
        body=html,
        subtype=MessageType.html,
    )

    fm = FastMail(_CONFIG)
    await fm.send_message(message)
    _logger.info("Verification email sent")
    return JSONResponse(status_code=200, content={"message": "verification email has been sent"})
