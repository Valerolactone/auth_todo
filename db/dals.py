from typing import Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import User


class UserDAL:
    """Data Access Layer for operating user info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def create_user(
        self,
        first_name: str,
        last_name: str,
        email: str,
        hashed_password: str,
    ) -> User:
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            hashed_password=hashed_password,
        )
        self.db_session.add(new_user)
        await self.db_session.flush()
        return new_user

    async def get_user_by_email(self, email: str) -> Union[User, None]:
        query = select(User).where(User.email == email)
        result = await self.db_session.execute(query)
        user_row = result.fetchone()
        if user_row is not None:
            return user_row[0]

    async def get_users_emails_for_notification(
        self, users_ids: list[int]
    ) -> dict[int:str]:
        query = select(User.user_pk, User.email).filter(User.user_pk.in_(users_ids))
        result = await self.db_session.execute(query)
        users_emails = result.fetchall()
        return users_emails
