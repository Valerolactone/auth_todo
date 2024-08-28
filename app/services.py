import os
from datetime import datetime, timedelta
from typing import Optional, Sequence

import jwt
from fastapi import HTTPException, status
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas import (
    AdminUserUpdate,
    ExpandUserData,
    PaginatedResponse,
    PermissionCreate,
    PermissionUpdate,
    ResetForgetPassword,
    RoleCreate,
    RolePermission,
    RoleUpdate,
    UserCreate,
    UserOut,
    UsersWithEmails,
    UserUpdate,
)
from db.dals import PermissionDAL, RoleDAL, RolePermissionDAL, TokenDAL, UserDAL
from db.models import Permission, RefreshToken, Role, User


class UserService:
    def __init__(self, db_session: AsyncSession):
        self.user_dal = UserDAL(db_session)
        self.auth_service = AuthenticationService(db_session)

    async def get_users_with_emails(self, users_ids: list[int]) -> UsersWithEmails:
        users = await self.user_dal.get_users_emails_for_notification(users_ids)
        return UsersWithEmails(
            users={user.user_pk: user.email for user in users} if users else {}
        )

    async def create_user(self, user_data: UserCreate) -> UserOut:
        email_check = await self.user_dal.get_user_by_email(user_data.email)
        if email_check:
            raise HTTPException(
                detail='Email is already registered',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = await self.user_dal.create_user(user_data)
        return UserOut(
            user_pk=user.user_pk,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=user.role.name,
        )

    async def get_paginated_users(
        self,
        page: int,
        page_size: int,
        sort_by: str = 'user_pk',
        sort_order: str = 'asc',
        filter_by: Optional[str] = None,
    ) -> PaginatedResponse | None:
        try:
            total_users = await self.user_dal.count_users(filter_by=filter_by)
            users = await self.user_dal.fetch_users(
                page, page_size, sort_by, sort_order, filter_by
            )
            mapped_users = [
                UserOut(
                    user_pk=user.user_pk,
                    first_name=user.first_name,
                    last_name=user.last_name,
                    email=user.email,
                    role=user.role.name,
                )
                for user in users
            ]

            total_pages = (
                total_users // page_size
                if total_users % page_size == 0
                else total_users // page_size + 1
            )
            has_next = page < total_pages
            has_prev = page > 1
            return PaginatedResponse(
                users=mapped_users,
                total=total_users,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
                has_next=has_next,
                has_prev=has_prev,
            )
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)
            )

    async def read_user(self, user_pk: int) -> UserOut:
        user = await self.user_dal.get_user_by_pk(user_pk)
        return UserOut(
            user_pk=user.user_pk,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=user.role.name,
        )

    async def update_user(self, token: str, user_data: UserUpdate) -> UserOut:
        db_user = self.auth_service.get_user_from_token(token)
        user = await self.user_dal.update_user(db_user.user_pk, user_data)
        return UserOut(
            user_pk=user.user_pk,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=user.role.name,
        )

    async def delete_user(self, token: str):
        db_user = self.auth_service.get_user_from_token(token)
        return await self.user_dal.delete_user(db_user.user_pk)


class AdminUserService:
    def __init__(self, db_session: AsyncSession):
        self.user_dal = UserDAL(db_session)

    async def admin_get_paginated_users(
        self,
        page: int,
        page_size: int,
        sort_by: str = 'user_pk',
        sort_order: str = 'asc',
        filter_by: Optional[str] = None,
    ) -> PaginatedResponse:
        try:
            total_users = await self.user_dal.count_users(filter_by=filter_by)
            users = await self.user_dal.fetch_users(
                page, page_size, sort_by, sort_order, filter_by
            )
            total_pages = (
                total_users // page_size
                if total_users % page_size == 0
                else total_users // page_size + 1
            )
            mapped_users = [
                ExpandUserData(
                    user_pk=user.user_pk,
                    first_name=user.first_name,
                    last_name=user.last_name,
                    email=user.email,
                    role=user.role.name,
                    role_id=user.role_id,
                    created_at=user.created_at,
                    deleted_at=user.deleted_at,
                    is_active=user.is_active,
                    is_verified=user.is_verified,
                )
                for user in users
            ]
            has_next = page < total_pages
            has_prev = page > 1

            return PaginatedResponse(
                users=mapped_users,
                total=total_users,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
                has_next=has_next,
                has_prev=has_prev,
            )
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)
            )

    async def admin_read_user(self, user_pk: int) -> ExpandUserData:
        user = await self.user_dal.get_user_by_pk(user_pk)
        return ExpandUserData(
            user_pk=user.user_pk,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=user.role.name,
            role_id=user.role_id,
            created_at=user.created_at,
            deleted_at=user.deleted_at,
            is_active=user.is_active,
            is_verified=user.is_verified,
        )

    async def admin_update_user(
        self, user_pk: int, user_data: AdminUserUpdate
    ) -> ExpandUserData:
        user = await self.user_dal.update_user(user_pk, user_data)
        return ExpandUserData(
            user_pk=user.user_pk,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=user.role.name,
            role_id=user.role_id,
            created_at=user.created_at,
            deleted_at=user.deleted_at,
            is_active=user.is_active,
            is_verified=user.is_verified,
        )

    async def admin_delete_user(self, user_pk: int):
        return await self.user_dal.delete_user(user_pk)


class AuthenticationService:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.user_dal = UserDAL(self.db_session)

    @property
    def _credentials_exception(self):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    async def get_user_by_email(self, email: str) -> User | None:
        async with self.db_session.begin():
            return await self.user_dal.get_user_by_email(email=email)

    async def authenticate_user(self, email: str, password: str) -> User | None:
        user = await self.get_user_by_email(email=email)
        if user is None or not user.verify_password(password):
            return None
        return user

    async def get_user_from_token(self, token: str) -> User | None:
        try:
            payload = jwt.decode(
                token,
                os.getenv("JWT_SECRET_KEY"),
                algorithms=os.getenv("JWT_ALGORITHM"),
            )
            user_pk: str = payload.get("user_pk")
            if user_pk is None:
                raise self._credentials_exception
        except jwt.PyJWTError:
            raise self._credentials_exception
        user_dal = UserDAL(self.db_session)

        return await user_dal.get_user_by_pk(user_pk=user_pk)


class TokenService:
    def __init__(self, db_session: AsyncSession, data: dict):
        self.db_session = db_session
        self.data = data

    def create_access_token(self, expires_delta: Optional[timedelta] = None) -> dict:
        to_encode = self.data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=int(os.getenv("ACCESS_TOKEN_EXPIRATION_TIME"))
            )
        to_encode.update({"exp": expire})
        token = jwt.encode(
            to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
        )
        return {"access_token": token, "access_token_expires_at": expire}

    def _create_refresh_token(self) -> dict:
        to_encode = self.data.copy()
        expire = datetime.utcnow() + timedelta(
            days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_TIME"))
        )
        to_encode.update({"exp": expire})
        token = jwt.encode(
            to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
        )
        return {"refresh_token": token, "expires_at": expire}

    async def add_refresh_token_to_db(self) -> str:
        refresh_token_data = self._create_refresh_token()
        refresh_token = refresh_token_data["refresh_token"]
        expires_at = refresh_token_data["expires_at"]
        db_refresh_token = RefreshToken(
            user_pk=self.data["user_pk"], token=refresh_token, expires_at=expires_at
        )
        try:
            self.db_session.add(db_refresh_token)
            await self.db_session.flush()
        except SQLAlchemyError as e:
            await self.db_session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            )

        return refresh_token

    async def update_refresh_token_in_db(self) -> str:
        refresh_token_data = self._create_refresh_token()
        refresh_token = refresh_token_data["refresh_token"]
        expires_at = refresh_token_data["expires_at"]
        token_dal = TokenDAL(self.db_session)
        try:
            db_refresh_token = await token_dal.get_refresh_token(self.data["user_pk"])
            if not db_refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Refresh token not found",
                )

            db_refresh_token.token = refresh_token
            db_refresh_token.expires_at = expires_at

            await self.db_session.flush()
            await self.db_session.refresh(db_refresh_token)
        except SQLAlchemyError as e:
            await self.db_session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            )

        return refresh_token


class EmailTokenService:
    def __init__(
        self,
        subject: str,
        action: str,
        endpoint: str,
        email: str,
    ):
        self.subject = subject
        self.action = action
        self.endpoint = endpoint
        self.email = email
        self.mail_conf = ConnectionConfig(
            MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
            MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
            MAIL_FROM=os.getenv("MAIL_USERNAME"),
            MAIL_PORT=587,
            MAIL_SERVER=os.getenv("MAIL_SERVER"),
            MAIL_STARTTLS=True,
            MAIL_SSL_TLS=False,
        )
        self.email_agent = FastMail(self.mail_conf)
        self._secret_token = self._create_token_for_link()
        self._link = f"{os.getenv("APP_HOST")}{self.endpoint}/{self._secret_token}"
        self.email_body = f"""
                        Please {self.action} by clicking the link below (valid for {int(os.getenv("LINK_EXPIRE_MINUTES"))} minutes): 
                        {self._link}
                        Thank you,
                        {os.getenv("MAIL_FROM_NAME")}"""

    def _create_token_for_link(self) -> str:
        data = {
            "sub": self.email,
            "exp": datetime.utcnow()
            + timedelta(minutes=int(os.getenv("LINK_EXPIRE_MINUTES"))),
        }
        token = jwt.encode(
            data,
            os.getenv("JWT_FOR_LINK_SECRET_KEY"),
            algorithm=os.getenv("JWT_ALGORITHM"),
        )
        return token

    @classmethod
    def _decode_token_from_link(cls, token: str) -> str | None:
        try:
            payload = jwt.decode(
                token,
                os.getenv("JWT_FOR_LINK_SECRET_KEY"),
                algorithms=[os.getenv("JWT_ALGORITHM")],
            )
            email: str = payload.get("sub")
            return email
        except jwt.PyJWTError:
            return

    async def send_email_with_link(self):
        message = MessageSchema(
            subject=self.subject,
            recipients=[self.email],
            template_body=self.email_body,
            subtype=MessageType.plain,
        )

        await self.email_agent.send_message(message)


class ResetPasswordService(EmailTokenService):
    @classmethod
    async def reset_password(
        cls,
        db: AsyncSession,
        secret_token: str,
        reset_forget_password: ResetForgetPassword,
    ):
        email = cls._decode_token_from_link(token=secret_token)
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password reset token or the reset link has expired.",
            )

        if reset_forget_password.new_password != reset_forget_password.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password and password confirmation do not match.",
            )

        user_service = AuthenticationService(db)
        user = await user_service.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        if user.verify_password(reset_forget_password.new_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You have entered an old password.",
            )

        user.password = reset_forget_password.new_password

        try:
            db.add(user)
            await db.flush()
        except SQLAlchemyError as err:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )


class ConfirmRegistrationService(EmailTokenService):
    @classmethod
    async def confirm_registration(
        cls,
        db: AsyncSession,
        secret_token: str,
    ):
        email = cls._decode_token_from_link(token=secret_token)
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password reset token or the reset link has expired.",
            )

        user_service = AuthenticationService(db)
        user = await user_service.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        user.is_verified = True

        try:
            db.add(user)
            await db.flush()
        except SQLAlchemyError as err:
            await db.rollback()
            raise HTTPException(status_code=500, detail=str(err))


class PermissionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_permission_by_pk(self, permission_pk: int) -> Permission:
        permission_dal = PermissionDAL(self.db)
        permission = await permission_dal.get_permission_by_pk(permission_pk)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found."
            )

        return permission

    async def create_permission(self, permission_data: PermissionCreate) -> Permission:
        db_permission = Permission(**permission_data.dict())
        try:
            self.db.add(db_permission)
            await self.db.flush()
            await self.db.refresh(db_permission)
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )
        return db_permission

    async def read_permissions(self) -> Sequence[Permission] | None:
        permission_dal = PermissionDAL(self.db)
        return await permission_dal.get_permissions()

    async def read_permission(self, permission_pk: int) -> Permission:
        return await self._get_permission_by_pk(permission_pk)

    async def update_permission(self, permission_pk: int, permission: PermissionUpdate):
        db_permission = await self._get_permission_by_pk(permission_pk)
        update_data = permission.dict(exclude_unset=True)
        try:
            for key, value in update_data.items():
                setattr(db_permission, key, value)
            await self.db.flush()
            await self.db.refresh(db_permission)
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )

        return db_permission

    async def delete_permission(self, permission_pk: int):
        db_permission = await self._get_permission_by_pk(permission_pk)
        try:
            await self.db.delete(db_permission)
            await self.db.flush()
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )

        return db_permission


class RoleService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_role_by_pk(self, role_pk: int) -> Role:
        role_dal = RoleDAL(self.db)
        role = await role_dal.get_role_by_pk(role_pk)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found."
            )

        return role

    async def create_role(self, role_data: RoleCreate) -> Role:
        db_role = Role(**role_data.dict())
        try:
            self.db.add(db_role)
            await self.db.flush()
            await self.db.refresh(db_role)
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )
        return db_role

    async def read_roles(self) -> Sequence[Role] | None:
        role_dal = RoleDAL(self.db)
        return await role_dal.get_roles()

    async def read_role(self, role_pk: int) -> Role:
        return await self._get_role_by_pk(role_pk)

    async def update_role(self, role_pk: int, role: RoleUpdate):
        db_role = await self._get_role_by_pk(role_pk)
        update_data = role.dict(exclude_unset=True)
        try:
            for key, value in update_data.items():
                setattr(db_role, key, value)
            await self.db.flush()
            await self.db.refresh(db_role)
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )

        return db_role

    async def delete_role(self, role_pk: int):
        db_role = await self._get_role_by_pk(role_pk)
        try:
            await self.db.delete(db_role)
            await self.db.flush()
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )

        return db_role


class RolePermissionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_role_permission(self, data: RolePermission):
        role_dal = RoleDAL(self.db)
        role = role_dal.get_role_by_pk(data.role_pk)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with id {data.role_pk} not found",
            )
        permission_dal = PermissionDAL(self.db)
        permission = permission_dal.get_permission_by_pk(data.permission_pk)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission with id {data.permission_pk} not found",
            )
        db_role_permission = RolePermission(**data.dict())
        try:
            self.db.add(db_role_permission)
            await self.db.flush()
            await self.db.refresh(db_role_permission)
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )
        return db_role_permission

    async def get_permissions_for_role(self, role_pk: int):
        role_dal = RoleDAL(self.db)
        role = role_dal.get_role_by_pk(role_pk)

        return role.permissions

    async def get_roles_for_permission(self, permission_pk: int):
        permission_dal = PermissionDAL(self.db)
        permission = permission_dal.get_permission_by_pk(permission_pk)

        return permission.roles

    async def delete_role_permission(self, data: RolePermission):
        role_permission_dal = RolePermissionDAL(self.db)
        db_role_permission = await role_permission_dal.get_role_permission(
            role_pk=data.role_pk, permission_pk=data.permission_pk
        )
        if not db_role_permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No relationship found between Role {data.role_pk} and Permission {data.permission_pk}",
            )
        try:
            await self.db.delete(db_role_permission)
            await self.db.flush()
        except SQLAlchemyError as err:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
            )

        return db_role_permission
