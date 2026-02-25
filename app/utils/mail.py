import os

from fastapi.responses import JSONResponse
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType, NameEmail
from pydantic import SecretStr

BASE_URL = os.environ.get("SERVER_URL")

conf = ConnectionConfig(
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
    verification_link = f"{BASE_URL}/v1/auth/email/{token}"

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
    fm = FastMail(conf)
    await fm.send_message(message)  #
    return JSONResponse(status_code=200, content={"message": "verification email has been sent"})
