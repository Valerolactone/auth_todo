import os
from datetime import timedelta
from logging import getLogger

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from models import User
from schemas import UserCreate, UserData, UserIds, UsersWithEmails, Token
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import UserService, AuthenticationService
from db.session import get_db
from utils import create_access_token

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
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
):
    service = AuthenticationService(db)
    user = await service.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(
        hours=int(os.getenv("ACCESS_TOKEN_EXPIRATION_TIME"))
    )
    access_token = create_access_token(
        data={
            "sub": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "user_pk": user.user_pk,
        },
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


# TODO: figure out how to implement user dependency if AuthenticationService depends on AsyncSession (this endpoint doesn't work)
@login_router.get("/test_auth_endpoint")
async def test_auth_endpoint(
        current_user: User = Depends(AuthenticationService.get_current_user_from_token),
):
    return {"Success": True, "current_user": current_user}
