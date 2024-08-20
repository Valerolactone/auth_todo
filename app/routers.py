from datetime import datetime, timezone
from logging import getLogger

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from schemas import (
    ForgetPasswordRequest,
    ResetForgetPassword,
    Token,
    UserCreate,
    UserData,
    UserIds,
    UsersWithEmails,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from utils import get_refresh_token_from_headers

from app.services import (
    AuthenticationService,
    ResetPasswordService,
    TokenService,
    UserService,
)
from db.dals import TokenDAL
from db.session import get_db

logger = getLogger(__name__)
user_router = APIRouter()
login_router = APIRouter()


@user_router.post(
    "/notification_emails",
    response_model=UsersWithEmails,
    status_code=status.HTTP_200_OK,
)
async def get_users_emails(body: UserIds, db: AsyncSession = Depends(get_db)):
    users_with_emails = {}
    service = UserService(db)
    users = await service.get_users_with_emails(body.ids)

    if not users:
        raise HTTPException(status_code=404, detail="Users not found")

    for user_row in users:
        users_with_emails[user_row[0].user_pk] = user_row[0].email

    return {"users": users_with_emails}


@user_router.post(
    "/create", response_model=UserData, status_code=status.HTTP_201_CREATED
)
async def register(body: UserCreate, db: AsyncSession = Depends(get_db)):
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
    result = {
        "token_type": "bearer",
    }
    service = AuthenticationService(db)
    user = await service.authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    user_data = {"sub": user.email, "user_pk": user.user_pk}
    token_service = TokenService(db_session=db, data=user_data)
    access_token_data = token_service.create_access_token()
    result.update(access_token_data)

    refresh_token = await token_service.add_refresh_token_to_db()
    result.update({"refresh_token": refresh_token})

    return result


@login_router.post(
    "/token/refresh", response_model=Token, status_code=status.HTTP_200_OK
)
async def refresh_access_token(
    refresh_token: str = Depends(get_refresh_token_from_headers),
    db: AsyncSession = Depends(get_db),
):
    result = {"token_type": "bearer"}

    token_dal = TokenDAL(db)
    is_refresh_token_in_db = await token_dal.validate_refresh_token(refresh_token)
    if not is_refresh_token_in_db:
        raise HTTPException(status_code=404, detail="Refresh token not found")
    result.update({"refresh_token": refresh_token})

    auth_service = AuthenticationService(db)
    user = await auth_service.get_user_from_token(refresh_token)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = {"sub": user.email, "user_pk": user.user_pk}

    db_refresh_token = await token_dal.get_refresh_token(refresh_token)

    token_service = TokenService(db_session=db, data=user_data)

    if db_refresh_token.expires_at < datetime.now(timezone.utc):
        updated_refresh_token = await token_service.update_refresh_token_in_db()
        result.update({"refresh_token": updated_refresh_token})

    access_token_data = token_service.create_access_token()
    result.update(access_token_data)

    return result


@login_router.post("/forget-password")
async def forget_password(
    background_tasks: BackgroundTasks,
    forget_password_request: ForgetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    user_service = AuthenticationService(db)
    reset_password_service = ResetPasswordService()

    user = await user_service.get_user_by_email(forget_password_request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No user with this email was found.",
        )

    background_tasks.add_task(
        reset_password_service.send_password_reset_email, user.email
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "message": "Password reset instructions have been sent to your email."
        },
    )


@login_router.post("/reset-password/{secret_token}")
async def reset_password(
    reset_forget_password: ResetForgetPassword,
    db: AsyncSession = Depends(get_db),
    secret_token: str = Path(...),
):
    reset_password_service = ResetPasswordService()
    await reset_password_service.reset_password(db, secret_token, reset_forget_password)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Password has been successfully reset!"},
    )
