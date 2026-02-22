from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import os

conf = ConnectionConfig(
    MAIL_USERNAME=os.environ.get("EMAIL_USER"),
    MAIL_PASSWORD=os.environ.get("EMAIL_PASSWORD"),
    MAIL_FROM=os.environ.get("EMAIL_USER"),
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

async def send_confirmation(to_email: str):
    message = MessageSchema(
        subject="Welcome to GoatVault – Registration Confirmed",
        recipients=[to_email],
        body="""
        <html>
            <body>
                <h2>Welcome to <b>GoatVault</b>!</h2>
                <p>Thank you for registering. Your account has been successfully created.</p>
                <p>You can now log in and start using GoatVault.</p>
                <br>
                <p>Best regards,<br>GoatVault Team</p>
            </body>
        </html>
        """,
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)
