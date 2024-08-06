import os
from datetime import timedelta
from logging import getLogger

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from schemas import Token, UserCreate, UserData, UserIds, UsersWithEmails
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from utils import create_access_token

from app.services import AuthenticationService, UserService
from db.models import User
from db.session import get_db

logger = getLogger(__name__)
user_router = APIRouter()
login_router = APIRouter()


@user_router.get(
    "/notification_emails",
    response_model=UsersWithEmails,
    status_code=status.HTTP_200_OK,
)
async def get_users_emails(users_ids: UserIds, db: AsyncSession = Depends(get_db)):
    service = UserService(db)
    emails = await service.get_users_with_emails(users_ids)
    return emails


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
        data={"sub": user.email},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@login_router.get("/test_auth_endpoint")
async def test_auth_endpoint(
    current_user: User = Depends(AuthenticationService.get_current_user_from_token),
):
    return {"Success": True, "current_user": current_user}
