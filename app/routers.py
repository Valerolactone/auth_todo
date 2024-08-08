from datetime import datetime, timezone
from logging import getLogger

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from schemas import Token, UserCreate, UserData, UserIds, UsersWithEmails
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from utils import (
    add_refresh_token_to_db,
    create_access_token,
    update_refresh_token_in_db,
)

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
        return await service.register(body)
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

    user_data = {"sub": user.email, "user_pk": user.user_pk}
    access_token = create_access_token(data=user_data)
    refresh_token = await add_refresh_token_to_db(data=user_data, db=db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@login_router.get(
    "/token/refresh/{user_pk}", response_model=Token, status_code=status.HTTP_200_OK
)
async def refresh_access_token(user_pk: int, db: AsyncSession = Depends(get_db)):
    result = {"token_type": "bearer"}
    user_service = UserService(db)
    user = await user_service.get_user_by_pk(user_pk)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = {"sub": user.email, "user_pk": user.user_pk}

    auth_service = AuthenticationService(db)
    refresh_token = await auth_service.get_user_refresh_token(user_pk)
    result.update({"refresh_token": refresh_token.token})

    if not refresh_token:
        raise HTTPException(status_code=404, detail="Refresh token not found")

    if refresh_token.expires_at < datetime.now(timezone.utc):
        updated_refresh_token = await update_refresh_token_in_db(data=user_data, db=db)
        result.update({"refresh_token": updated_refresh_token})

    access_token = create_access_token(data=user_data)
    result.update({"access_token": access_token})

    return result
