import os
from typing import Union

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas import UserCreate, UserData
from db.dals import UserDAL
from db.models import User


class UserService:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_users_with_emails(self, users_ids: list[int]):
        async with self.db_session.begin():
            user_dal = UserDAL(self.db_session)
            users = await user_dal.get_users_emails_for_notification(users_ids)
            return users

    async def create_new_user(self, body: UserCreate) -> UserData:
        async with self.db_session.begin():
            user_dal = UserDAL(self.db_session)
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

    async def _get_user_by_email(self, email: str):
        async with self.db_session.begin():
            user_dal = UserDAL(self.db_session)
            return await user_dal.get_user_by_email(email=email)

    async def authenticate_user(self, email: str, password: str) -> Union[User, None]:
        user = await self._get_user_by_email(email=email)
        if user is None or not user.verify_password(password):
            return
        return user

    async def get_user_email_from_token(
        self, token: str = Depends(_oauth2_scheme)
    ) -> str:
        try:
            payload = jwt.decode(
                token,
                os.getenv("JWT_SECRET_KEY"),
                algorithms=os.getenv("JWT_ALGORITHM"),
            )
            email: str = payload.get("sub")
            if email is None:
                raise self._credentials_exception
        except JWTError:
            raise self._credentials_exception
        return email
