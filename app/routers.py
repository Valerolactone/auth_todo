from logging import getLogger

from fastapi import APIRouter, Depends, HTTPException, status
from schemas import UserCreate, UserData, UserIds, UsersWithEmails
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import UserService
from db.session import get_db

logger = getLogger(__name__)
user_router = APIRouter()
login_router = APIRouter()


@user_router.post(
    "/notification_emails",
    response_model=UsersWithEmails,
    status_code=status.HTTP_200_OK,
)
async def get_users_emails(users_ids: UserIds, db: AsyncSession = Depends(get_db)):
    users_with_emails = {}
    service = UserService(db)
    users = await service.get_users_with_emails(users_ids.ids)

    if not users:
        raise HTTPException(status_code=404, detail="Users not found")

    for user_row in users:
        users_with_emails[user_row[0].user_pk] = user_row[0].email

    return {"users": users_with_emails}


@user_router.post(
    "/create", response_model=UserData, status_code=status.HTTP_201_CREATED
)
async def create_user(body: UserCreate, db: AsyncSession = Depends(get_db)):
    service = UserService(db)
    try:
        return await service.create_new_user(body)
    except IntegrityError as err:
        logger.error(err)
        raise HTTPException(status_code=503, detail=f"Database error: {err}")

