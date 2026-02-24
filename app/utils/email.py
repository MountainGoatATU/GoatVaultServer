from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import os

BASE_URL = os.environ.get("LOCAL_SERVER_URL")

conf = ConnectionConfig(
    MAIL_USERNAME=os.environ.get("EMAIL_USERNAME"),
    MAIL_PASSWORD=os.environ.get("EMAIL_PASSWORD"),
    MAIL_FROM=os.environ.get("EMAIL_USERNAME"),
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

async def send_verification(to_email: str, token: str):
    verification_link = f"{BASE_URL}/v1/auth/email/{token}"
    message = MessageSchema(
        subject="GoatVault - Verify your email",
        recipients=[to_email],
        body=f"""
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
        """,
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)
