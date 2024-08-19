import os
from datetime import datetime, timedelta

import jwt
from fastapi import Header, HTTPException
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType


async def get_refresh_token_from_headers(authorization: str = Header(None)):
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token
    raise HTTPException(status_code=403, detail="Could not validate credentials")


def create_reset_password_token(email: str):
    data = {"sub": email, "exp": datetime.utcnow() + timedelta(minutes=10)}
    token = jwt.encode(
        data,
        os.getenv("JWT_FORGET_PWD_SECRET_KEY"),
        algorithm=os.getenv("JWT_ALGORITHM"),
    )
    return token


def decode_reset_password_token(token: str) -> str | None:
    try:
        payload = jwt.decode(
            token,
            os.getenv("JWT_FORGET_PWD_SECRET_KEY"),
            algorithms=[os.getenv("JWT_ALGORITHM")],
        )
        email: str = payload.get("sub")
        return email
    except jwt.PyJWTError:
        return None


async def send_password_reset_email(email: str, email_body: dict):

    message = MessageSchema(
        subject="Password Reset Instructions",
        recipients=[email],
        template_body=email_body,
        subtype=MessageType.plain,
    )

    mail_conf = ConnectionConfig(
        MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
        MAIL_FROM=os.getenv("MAIL_USERNAME"),
        MAIL_PORT=587,
        MAIL_SERVER=os.getenv("MAIL_SERVER"),
        MAIL_STARTTLS=True,
        MAIL_SSL_TLS=False,
    )

    email_agent = FastMail(mail_conf)

    await email_agent.send_message(message)
