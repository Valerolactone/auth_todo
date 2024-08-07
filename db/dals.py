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
        password: str,
    ) -> User:
        new_user = User(
            first_name=first_name, last_name=last_name, email=email, password=password
        )
        self.db_session.add(new_user)
        await self.db_session.flush()
        return new_user

    async def get_user_by_email(self, email: str) -> Union[User, None]:
        query = select(User).where(User.email == email)
        result = await self.db_session.execute(query)
        user_row = result.fetchone()
        if user_row is None:
            return
        return user_row[0]

    async def get_users_emails_for_notification(self, users_ids: list[int]):
        query = select(User).filter(User.user_pk.in_(users_ids))
        result = await self.db_session.execute(query)
        users = result.fetchall()
        return users
