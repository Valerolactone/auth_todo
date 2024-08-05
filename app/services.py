from sqlalchemy.ext.asyncio import AsyncSession

from db.dals import UserDAL


async def _get_users_with_emails(users_ids: list[int], session: AsyncSession):
    async with session.begin():
        user_dal = UserDAL(session)
        users_emails = await user_dal.get_users_emails_for_notification(users_ids)
        return users_emails
