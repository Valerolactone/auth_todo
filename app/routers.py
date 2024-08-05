from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_db
from schemas import UserIds
from app.services import _get_users_with_emails

user_router = APIRouter()


@user_router.get("/notification_emails/")
async def get_users_emails(users_ids: UserIds, db: AsyncSession = Depends(get_db)):
    emails = await _get_users_with_emails(users_ids, db)
    return emails
