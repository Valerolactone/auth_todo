from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import User


class UserDAL:
    """Data Access Layer for operating user info"""
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_users_emails_for_notification(self, users_ids: list[int]):
        query = select(User.email).filter(User.user_pk.in_(users_ids))
        result = await self.db_session.execute(query)
        emails = result.fetchall()
        return emails
