import os
from datetime import datetime, timezone
from logging import getLogger
from typing import List

import utils
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from schemas import (
    PermissionCreate,
    PermissionOut,
    PermissionUpdate,
    PermissionWithRoleOut,
    ResetForgetPassword,
    RoleCreate,
    RoleOut,
    RolePermissionData,
    RolePermissionOut,
    RoleUpdate,
    RoleWithPermissionOut,
    Token,
    UserCreate,
    UserEmail,
    UserIds,
    UserOut,
    UsersWithEmails,
)
from sqlalchemy.ext.asyncio import AsyncSession
from utils import get_refresh_token_from_headers

from app.services import (
    AuthenticationService,
    ConfirmRegistrationService,
    EmailTokenService,
    PermissionService,
    ResetPasswordService,
    RolePermissionService,
    RoleService,
    TokenService,
    UserService,
)
from db.dals import TokenDAL
from db.models import User
from db.session import get_db

logger = getLogger(__name__)
user_router = APIRouter()
login_router = APIRouter()
permission_router = APIRouter()
role_router = APIRouter()

role_permissions_router = APIRouter()


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


@user_router.post("/create", response_model=UserOut)
async def register(
    background_tasks: BackgroundTasks,
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    user_service = UserService(db)
    await user_service.register(body)
    email_registration_confirmation_service = EmailTokenService(
        subject="Confirm Registration Instructions",
        action="confirm your email",
        endpoint=os.getenv("CONFIRM_REGISTRATION_URL"),
        email=body.email,
    )

    background_tasks.add_task(
        email_registration_confirmation_service.send_email_with_link
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "message": "Registration confirmation instructions have been sent to your email."
        },
    )


@user_router.post("/resend-confirmation-link")
async def send_new_confirmation_link(
    background_tasks: BackgroundTasks, confirm_registration_request: UserEmail
):
    email_registration_confirmation_service = EmailTokenService(
        subject="Confirm Registration Instructions",
        action="confirm your email",
        endpoint=os.getenv("CONFIRM_REGISTRATION_URL"),
        email=confirm_registration_request.email,
    )

    background_tasks.add_task(
        email_registration_confirmation_service.send_email_with_link
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "message": "Registration confirmation instructions have been sent to your email."
        },
    )


@user_router.get("/confirm-registration/{secret_token}")
async def confirm_email(
    db: AsyncSession = Depends(get_db),
    secret_token: str = Path(...),
):
    await ConfirmRegistrationService.confirm_registration(db, secret_token)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Registration has been successfully confirmed!"},
    )


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

    user_data = {"sub": user.email, "user_pk": user.user_pk, "role_id": user.role_id}
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
    forget_password_request: UserEmail,
    db: AsyncSession = Depends(get_db),
):
    user_service = AuthenticationService(db)

    user = await user_service.get_user_by_email(forget_password_request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No user with this email was found.",
        )

    email_password_reset_service = EmailTokenService(
        subject="Password Reset Instructions",
        action="reset your password",
        endpoint=os.getenv("RESET_PASSWORD_URL"),
        email=user.email,
    )

    background_tasks.add_task(email_password_reset_service.send_email_with_link)

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
    await ResetPasswordService.reset_password(db, secret_token, reset_forget_password)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Password has been successfully reset!"},
    )


@permission_router.post(
    "/", response_model=PermissionOut, status_code=status.HTTP_201_CREATED
)
async def create_permission(
    permission: PermissionCreate,
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    permission_service = PermissionService(db)
    return await permission_service.create_permission(permission)


@permission_router.get(
    "/", response_model=List[PermissionOut], status_code=status.HTTP_200_OK
)
async def read_permissions(db: AsyncSession = Depends(get_db)):
    permission_service = PermissionService(db)
    return await permission_service.read_permissions()


@permission_router.get(
    "/{permission_pk}", response_model=PermissionOut, status_code=status.HTTP_200_OK
)
async def read_permission(
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    permission_service = PermissionService(db)
    return await permission_service.read_permission(int(permission_pk))


@permission_router.put(
    "/{permission_pk}", response_model=PermissionOut, status_code=status.HTTP_200_OK
)
async def update_permission(
    permission: PermissionUpdate,
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    permission_service = PermissionService(db)
    return await permission_service.update_permission(int(permission_pk), permission)


@permission_router.delete(
    "/{permission_pk}", response_model=PermissionOut, status_code=status.HTTP_200_OK
)
async def delete_permission(
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    permission_service = PermissionService(db)
    return await permission_service.delete_permission(int(permission_pk))


@role_router.post("/", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def create_role(
    role: RoleCreate,
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    role_service = RoleService(db)
    return await role_service.create_role(role)


@role_router.get("/", response_model=List[RoleOut], status_code=status.HTTP_200_OK)
async def read_roles(db: AsyncSession = Depends(get_db)):
    role_service = RoleService(db)
    return await role_service.read_roles()


@role_router.get("/{role_pk}", response_model=RoleOut, status_code=status.HTTP_200_OK)
async def read_role(
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_service = RoleService(db)
    return await role_service.read_role(int(role_pk))


@role_router.put("/{role_pk}", response_model=RoleOut, status_code=status.HTTP_200_OK)
async def update_role(
    role: RoleUpdate,
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_service = RoleService(db)
    return await role_service.update_role(int(role_pk), role)


@role_router.delete(
    "/{role_pk}", response_model=RoleOut, status_code=status.HTTP_200_OK
)
async def delete_role(
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_service = RoleService(db)
    return await role_service.delete_role(int(role_pk))


@role_permissions_router.post(
    "/", response_model=RolePermissionOut, status_code=status.HTTP_201_CREATED
)
async def assign_permission_to_role(
    role_and_permission: RolePermissionData,
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.create_role_permission(role_and_permission)


@role_permissions_router.get(
    "/role/{role_pk}/permissions/",
    response_model=RoleWithPermissionOut,
    status_code=status.HTTP_200_OK,
)
async def read_permissions_for_role(
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.get_role_with_permissions(int(role_pk))


@role_permissions_router.get(
    "/permission/{permission_pk}/roles/",
    response_model=PermissionWithRoleOut,
    status_code=status.HTTP_200_OK,
)
async def read_roles_for_permission(
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.get_permission_with_roles(int(permission_pk))


@role_permissions_router.delete(
    "/", response_model=RolePermissionOut, status_code=status.HTTP_200_OK
)
async def remove_permission_from_role(
    role_and_permission: RolePermissionData,
    admin_user: User = Depends(utils.get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.delete_role_permission(role_and_permission)
