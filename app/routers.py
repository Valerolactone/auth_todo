from logging import getLogger

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from schemas import Token, UserCreate, UserData, UserIds, UsersWithEmails
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from utils import create_access_token, create_refresh_token

from app.services import AuthenticationService, UserService
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


@login_router.post("/token", response_model=Token, status_code=status.HTTP_201_CREATED)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
):
    service = AuthenticationService(db)
    user = await service.authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    user_data = {"sub": user.email}
    access_token = create_access_token(data=user_data)
    refresh_token = create_refresh_token(data=user_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@login_router.post(
    "/token/refresh", response_model=Token, status_code=status.HTTP_201_CREATED
)
async def refresh_access_token(refresh_token: str, db: AsyncSession = Depends(get_db)):
    services = AuthenticationService(db)
    user_email = await services.get_user_email_from_token(refresh_token)
    user_data = {"sub": user_email}
    access_token = create_access_token(data=user_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
