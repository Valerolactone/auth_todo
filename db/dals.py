from typing import Sequence

from sqlalchemy import Row, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import RefreshToken, User


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

    async def get_user_by_email(self, email: str) -> User | None:
        query = select(User).where(User.email == email)
        result = await self.db_session.execute(query)
        user_row = result.fetchone()
        if user_row is None:
            return
        return user_row[0]

    async def get_user_by_pk(self, user_pk: int) -> User | None:
        query = select(User).where(User.user_pk == user_pk)
        result = await self.db_session.execute(query)
        user_row = result.fetchone()
        if user_row is None:
            return
        return user_row[0]

    async def get_users_emails_for_notification(
        self, users_ids: list[int]
    ) -> Sequence[Row[tuple[User]]] | None:
        query = select(User).filter(User.user_pk.in_(users_ids))
        result = await self.db_session.execute(query)
        users = result.fetchall()
        if users is None:
            return
        return users


class TokenDAL:
    """Data Access Layer for operating refresh token info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_user_refresh_token(self, user_pk: int) -> RefreshToken | None:
        query = select(RefreshToken).where(
            RefreshToken.user_pk == user_pk, RefreshToken.is_revoked == False
        )
        result = await self.db_session.execute(query)
        refresh_token_row = result.fetchone()
        if refresh_token_row is None:
            return
        return refresh_token_row[0]
