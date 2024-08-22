import os
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas import ResetForgetPassword, UserCreate, UserData
from db.dals import TokenDAL, UserDAL
from db.models import RefreshToken, User


class UserService:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_users_with_emails(self, users_ids: list[int]):
        async with self.db_session.begin():
            user_dal = UserDAL(self.db_session)
            users = await user_dal.get_users_emails_for_notification(users_ids)
            return users

    async def register(self, body: UserCreate) -> UserData:
        async with self.db_session.begin():
            user_dal = UserDAL(self.db_session)
            email_check = await user_dal.get_user_by_email(body.email)
            if email_check is not None:
                raise HTTPException(
                    detail='Email is already registered',
                    status_code=status.HTTP_400_BAD_REQUEST,
                )

            user = await user_dal.create_user(
                first_name=body.first_name,
                last_name=body.last_name,
                email=body.email,
                password=body.password,
            )
            return UserData(
                user_pk=user.user_pk,
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
            )

    async def get_user_by_pk(self, user_pk: int) -> User | None:
        async with self.db_session.begin():
            user_dal = UserDAL(self.db_session)
            return await user_dal.get_user_by_pk(user_pk=user_pk)


class AuthenticationService:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    _oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/token")

    @property
    def _credentials_exception(self):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    async def get_user_by_email(self, email: str) -> User | None:
        async with self.db_session.begin():
            user_dal = UserDAL(self.db_session)
            return await user_dal.get_user_by_email(email=email)

    async def authenticate_user(self, email: str, password: str) -> User | None:
        user = await self.get_user_by_email(email=email)
        if user is None or not user.verify_password(password):
            return None
        return user

    async def get_user_from_token(
        self, token: str = Depends(_oauth2_scheme)
    ) -> User | None:
        try:
            payload = jwt.decode(
                token,
                os.getenv("JWT_SECRET_KEY"),
                algorithms=os.getenv("JWT_ALGORITHM"),
            )
            user_pk: str = payload.get("user_pk")
            if user_pk is None:
                raise self._credentials_exception
        except jwt.PyJWTError:
            raise self._credentials_exception
        user_dal = UserDAL(self.db_session)

        return await user_dal.get_user_by_pk(user_pk=user_pk)


class TokenService:
    def __init__(self, db_session: AsyncSession, data: dict):
        self.db_session = db_session
        self.data = data

    def create_access_token(self, expires_delta: Optional[timedelta] = None) -> dict:
        to_encode = self.data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=int(os.getenv("ACCESS_TOKEN_EXPIRATION_TIME"))
            )
        to_encode.update({"exp": expire})
        token = jwt.encode(
            to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
        )
        return {"access_token": token, "access_token_expires_at": expire}

    def _create_refresh_token(self) -> dict:
        to_encode = self.data.copy()
        expire = datetime.utcnow() + timedelta(
            days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_TIME"))
        )
        to_encode.update({"exp": expire})
        token = jwt.encode(
            to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
        )
        return {"refresh_token": token, "expires_at": expire}

    async def add_refresh_token_to_db(self) -> str:
        refresh_token_data = self._create_refresh_token()
        refresh_token = refresh_token_data["refresh_token"]
        expires_at = refresh_token_data["expires_at"]
        db_refresh_token = RefreshToken(
            user_pk=self.data["user_pk"], token=refresh_token, expires_at=expires_at
        )
        try:
            self.db_session.add(db_refresh_token)
            await self.db_session.flush()
        except SQLAlchemyError as e:
            await self.db_session.rollback()
            raise HTTPException(status_code=500, detail=str(e))

        return refresh_token

    async def update_refresh_token_in_db(self) -> str:
        refresh_token_data = self._create_refresh_token()
        refresh_token = refresh_token_data["refresh_token"]
        expires_at = refresh_token_data["expires_at"]
        token_dal = TokenDAL(self.db_session)
        try:
            db_refresh_token = await token_dal.get_refresh_token(self.data["user_pk"])
            if not db_refresh_token:
                raise HTTPException(status_code=404, detail="Refresh token not found")

            db_refresh_token.token = refresh_token
            db_refresh_token.expires_at = expires_at

            await self.db_session.flush()
            await self.db_session.refresh(db_refresh_token)
        except SQLAlchemyError as e:
            await self.db_session.rollback()
            raise HTTPException(status_code=500, detail=str(e))

        return refresh_token


class EmailTokenService:
    def __init__(
        self,
        subject: str,
        action: str,
        endpoint: str,
        email: str,
    ):
        self.subject = subject
        self.action = action
        self.endpoint = endpoint
        self.email = email
        self.mail_conf = ConnectionConfig(
            MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
            MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
            MAIL_FROM=os.getenv("MAIL_USERNAME"),
            MAIL_PORT=587,
            MAIL_SERVER=os.getenv("MAIL_SERVER"),
            MAIL_STARTTLS=True,
            MAIL_SSL_TLS=False,
        )
        self.email_agent = FastMail(self.mail_conf)
        self._secret_token = self._create_token_for_link()
        self._link = f"{os.getenv("APP_HOST")}{self.endpoint}/{self._secret_token}"
        self.email_body = f"""
                        Please {self.action} by clicking the link below (valid for {int(os.getenv("LINK_EXPIRE_MINUTES"))} minutes): 
                        {self._link}
                        Thank you,
                        {os.getenv("MAIL_FROM_NAME")}"""

    def _create_token_for_link(self) -> str:
        data = {
            "sub": self.email,
            "exp": datetime.utcnow()
            + timedelta(minutes=int(os.getenv("LINK_EXPIRE_MINUTES"))),
        }
        token = jwt.encode(
            data,
            os.getenv("JWT_FOR_LINK_SECRET_KEY"),
            algorithm=os.getenv("JWT_ALGORITHM"),
        )
        return token

    @classmethod
    def _decode_token_from_link(cls, token: str) -> str | None:
        try:
            payload = jwt.decode(
                token,
                os.getenv("JWT_FOR_LINK_SECRET_KEY"),
                algorithms=[os.getenv("JWT_ALGORITHM")],
            )
            email: str = payload.get("sub")
            return email
        except jwt.PyJWTError:
            return

    async def send_email_with_link(self):
        message = MessageSchema(
            subject=self.subject,
            recipients=[self.email],
            template_body=self.email_body,
            subtype=MessageType.plain,
        )

        await self.email_agent.send_message(message)


class ResetPasswordService(EmailTokenService):
    @classmethod
    async def reset_password(
        cls,
        db: AsyncSession,
        secret_token: str,
        reset_forget_password: ResetForgetPassword,
    ):
        email = cls._decode_token_from_link(token=secret_token)
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password reset token or the reset link has expired.",
            )

        if reset_forget_password.new_password != reset_forget_password.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password and password confirmation do not match.",
            )

        user_service = AuthenticationService(db)
        user = await user_service.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        if user.verify_password(reset_forget_password.new_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You have entered an old password.",
            )

        user.password = reset_forget_password.new_password

        try:
            db.add(user)
            await db.flush()
        except SQLAlchemyError as err:
            await db.rollback()
            raise HTTPException(status_code=500, detail=str(err))


class ConfirmRegistrationService(EmailTokenService):
    @classmethod
    async def confirm_registration(
        cls,
        db: AsyncSession,
        secret_token: str,
    ):
        email = cls._decode_token_from_link(token=secret_token)
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password reset token or the reset link has expired.",
            )

        user_service = AuthenticationService(db)
        user = await user_service.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        user.is_verified = True

        try:
            db.add(user)
            await db.flush()
        except SQLAlchemyError as err:
            await db.rollback()
            raise HTTPException(status_code=500, detail=str(err))
