import os
from logging import getLogger
from typing import List, Optional

import utils
from exceptions import AuthenticationError, PasswordsError
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Path,
    Query,
    status,
)
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import ExpiredSignatureError, PyJWTError
from schemas import (
    AdminUserUpdate,
    ExpandUserData,
    PaginatedResponse,
    PermissionCreate,
    PermissionOut,
    PermissionUpdate,
    ResetForgetPassword,
    RoleCreate,
    RoleOut,
    RolePermission,
    RoleUpdate,
    Token,
    UserCreate,
    UserEmail,
    UserIds,
    UserOut,
    UsersWithEmails,
    UserUpdate,
)
from sqlalchemy.exc import NoResultFound, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import (
    AdminUserService,
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
from db.models import User
from db.session import get_db

logger = getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/token")

admin_router = APIRouter()
user_router = APIRouter()
login_router = APIRouter()
permission_router = APIRouter()
role_router = APIRouter()

role_permissions_router = APIRouter()


@admin_router.get("/", response_model=PaginatedResponse, status_code=status.HTTP_200_OK)
async def admin_read_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1),
    sort_by: str = Query('user_pk', alias='sortBy'),
    sort_order: str = Query('asc', alias='sortOrder', regex='^(asc|desc)$'),
    filter_by: Optional[str] = Query(None, alias='filterBy'),
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
):
    try:
        user_service = AdminUserService(db)
        return await user_service.admin_get_paginated_users(
            page, page_size, sort_by, sort_order, filter_by
        )
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except SQLAlchemyError as err:
        logger.error("Error during fetching users: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users",
        )


@admin_router.get(
    "/{user_pk}", response_model=ExpandUserData, status_code=status.HTTP_200_OK
)
async def admin_read_user(
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    user_pk: int = Path(...),
):
    try:
        user_service = AdminUserService(db)
        return await user_service.admin_read_user(user_pk)
    except NoResultFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with pk {user_pk} not found.",
        )
    except SQLAlchemyError as err:
        logger.error("Error during getting user by pk: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user by pk",
        )


@admin_router.put(
    "/{user_pk}", response_model=ExpandUserData, status_code=status.HTTP_200_OK
)
async def admin_update_user(
    user_data: AdminUserUpdate,
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    user_pk: int = Path(...),
):
    try:
        user_service = AdminUserService(db)
        return await user_service.admin_update_user(user_pk, user_data)
    except NoResultFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with pk {user_pk} not found.",
        )
    except SQLAlchemyError as err:
        logger.error("Error during getting user by pk: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user by pk",
        )


@admin_router.delete("/{user_pk}")
async def admin_delete_user(
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    user_pk: int = Path(...),
):
    try:
        user_service = AdminUserService(db)
        await user_service.admin_delete_user(user_pk)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except NoResultFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with pk {user_pk} not found.",
        )
    except SQLAlchemyError as err:
        logger.error("Error during getting user by pk: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user by pk",
        )


@user_router.post(
    "/notification_emails",
    response_model=UsersWithEmails,
    status_code=status.HTTP_200_OK,
)
async def get_users_emails(body: UserIds, db: AsyncSession = Depends(get_db)):
    try:
        service = UserService(db)
        users = await service.get_users_with_emails(body.ids)
        return users
    except SQLAlchemyError as err:
        logger.error("Error during getting list of users by pks: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get list of users by pks",
        )


@user_router.post("/register", response_model=UserOut, status_code=status.HTTP_200_OK)
async def create_user(
    background_tasks: BackgroundTasks,
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    try:
        user_service = UserService(db)
        user = await user_service.create_user(body)
        email_registration_confirmation_service = EmailTokenService(
            subject="Confirm Registration Instructions",
            action="confirm your email",
            endpoint=os.getenv("CONFIRM_REGISTRATION_URL"),
            email=body.email,
        )

        background_tasks.add_task(
            email_registration_confirmation_service.send_email_with_link
        )
        return user
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except SQLAlchemyError as err:
        logger.error("Error during user creation: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create a user.",
        )


@user_router.get("/", response_model=PaginatedResponse, status_code=status.HTTP_200_OK)
async def read_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1),
    sort_by: str = Query('user_pk', alias='sortBy'),
    sort_order: str = Query('asc', alias='sortOrder', regex='^(asc|desc)$'),
    filter_by: Optional[str] = Query(None, alias='filterBy'),
    db: AsyncSession = Depends(get_db),
):
    try:
        user_service = UserService(db)
        return await user_service.get_paginated_users(
            page, page_size, sort_by, sort_order, filter_by
        )
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except SQLAlchemyError as err:
        logger.error("Error during fetching users: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users",
        )


@user_router.get("/{user_pk}", response_model=UserOut, status_code=status.HTTP_200_OK)
async def read_user(
    db: AsyncSession = Depends(get_db),
    user_pk: int = Path(...),
):
    try:
        user_service = UserService(db)
        return await user_service.read_user(user_pk)
    except NoResultFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with pk {user_pk} not found.",
        )
    except SQLAlchemyError as err:
        logger.error("Error during getting user by pk: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user by pk",
        )


@user_router.put("/my_profile", response_model=UserOut, status_code=status.HTTP_200_OK)
async def update_user(
    user_data: UserUpdate,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    try:
        user_service = UserService(db)
        return await user_service.update_user(token, user_data)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    except SQLAlchemyError as err:
        logger.error("Error during updating user: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user",
        )


@user_router.delete("/my_profile", response_model=UserOut)
async def delete_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    try:
        user_service = UserService(db)
        await user_service.delete_user(token)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    except SQLAlchemyError as err:
        logger.error("Error during deleting user: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user",
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

    return Response(status_code=status.HTTP_200_OK)


@user_router.get("/confirm-registration/{secret_token}")
async def confirm_email(
    db: AsyncSession = Depends(get_db),
    secret_token: str = Path(...),
):
    try:
        await ConfirmRegistrationService.confirm_registration(db, secret_token)
        return Response(status_code=status.HTTP_200_OK)
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Link has expired",
        )
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid link",
        )
    except NoResultFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with not found.",
        )
    except SQLAlchemyError as err:
        logger.error("Error during verifying user: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify user",
        )


@login_router.post("/token", response_model=Token, status_code=status.HTTP_201_CREATED)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
):
    try:
        token_service = TokenService(db_session=db, form_data=form_data)
        token_data = await token_service.create_access_token()
        refresh_token = await token_service.add_refresh_token_to_db()
        return token_data.update(refresh_token)
    except AuthenticationError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err))
    except SQLAlchemyError as err:
        logger.error("Error during authentication user: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to authenticate user",
        )


@login_router.post(
    "/token/refresh", response_model=Token, status_code=status.HTTP_200_OK
)
async def refresh_access_token(
    refresh_token: str = Depends(utils.get_refresh_token_from_headers),
    db: AsyncSession = Depends(get_db),
):
    try:
        token_service = TokenService(db)
        access_token = await token_service.update_access_token(refresh_token)
        return access_token
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    except SQLAlchemyError as err:
        logger.error("Error during updating access token user: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update access token user",
        )


@login_router.post("/forget-password")
async def forget_password(
    background_tasks: BackgroundTasks,
    forget_password_request: UserEmail,
    db: AsyncSession = Depends(get_db),
):
    try:
        user_service = AuthenticationService(db)
        user = await user_service.get_user_by_email(forget_password_request.email)

        email_password_reset_service = EmailTokenService(
            subject="Password Reset Instructions",
            action="reset your password",
            endpoint=os.getenv("RESET_PASSWORD_URL"),
            email=user.email,
        )

        background_tasks.add_task(email_password_reset_service.send_email_with_link)
        return Response(status_code=status.HTTP_200_OK)
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))


@login_router.post("/reset-password/{secret_token}")
async def reset_password(
    reset_forget_password: ResetForgetPassword,
    db: AsyncSession = Depends(get_db),
    secret_token: str = Path(...),
):
    try:
        await ResetPasswordService.reset_password(
            db, secret_token, reset_forget_password
        )
        return Response(status_code=status.HTTP_200_OK)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except PasswordsError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except SQLAlchemyError as err:
        logger.error("Error during reseting user password: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset user password",
        )


@permission_router.post(
    "/", response_model=PermissionOut, status_code=status.HTTP_201_CREATED
)
async def create_permission(
    permission: PermissionCreate,
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
):
    permission_service = PermissionService(db)
    return await permission_service.create_permission(permission)


@permission_router.get("/", response_model=List[PermissionOut])
async def read_permissions(db: AsyncSession = Depends(get_db)):
    permission_service = PermissionService(db)
    return await permission_service.read_permissions()


@permission_router.get("/{permission_pk}", response_model=PermissionOut)
async def read_permission(
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    permission_service = PermissionService(db)
    return await permission_service.read_permission(int(permission_pk))


@permission_router.put("/{permission_pk}", response_model=PermissionOut)
async def update_permission(
    permission: PermissionUpdate,
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    permission_service = PermissionService(db)
    return await permission_service.update_permission(int(permission_pk), permission)


@permission_router.delete("/{permission_pk}", response_model=PermissionOut)
async def delete_permission(
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    permission_service = PermissionService(db)
    return await permission_service.delete_permission(int(permission_pk))


@role_router.post("/", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def create_role(
    role: RoleCreate,
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
):
    role_service = RoleService(db)
    return await role_service.create_role(role)


@role_router.get("/", response_model=List[RoleOut])
async def read_roles(db: AsyncSession = Depends(get_db)):
    role_service = RoleService(db)
    return await role_service.read_roles()


@role_router.get("/{role_pk}", response_model=RoleOut)
async def read_role(
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_service = RoleService(db)
    return await role_service.read_role(int(role_pk))


@role_router.put("/{role_pk}", response_model=RoleOut)
async def update_role(
    role: RoleUpdate,
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_service = RoleService(db)
    return await role_service.update_role(int(role_pk), role)


@role_router.delete("/{role_pk}", response_model=RoleOut)
async def delete_role(
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_service = RoleService(db)
    return await role_service.delete_role(int(role_pk))


@role_permissions_router.post("/")
async def assign_permission_to_role(
    role_and_permission: RolePermission,
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.create_role_permission(role_and_permission)


@role_permissions_router.get("/role/{role_pk}/permissions/")
async def read_permissions_for_role(
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    role_pk: str = Path(...),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.get_permissions_for_role(int(role_pk))


@role_permissions_router.get("/permission/{permission_pk}/roles/")
async def read_roles_for_permission(
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
    permission_pk: str = Path(...),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.get_permissions_for_role(int(permission_pk))


@role_permissions_router.delete("/")
async def remove_permission_from_role(
    role_and_permission: RolePermission,
    admin_user: User = Depends(utils.is_admin),
    db: AsyncSession = Depends(get_db),
):
    role_permission_service = RolePermissionService(db)
    return await role_permission_service.delete_role_permission(role_and_permission)
