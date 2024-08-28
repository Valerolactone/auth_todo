import os
from datetime import datetime, timedelta
from typing import Optional, Sequence

import jwt
from exceptions import AuthenticationError, PasswordsError
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
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
    Token,
    UserCreate,
    UserOut,
    UsersWithEmails,
    UserUpdate,
)
from db.dals import PermissionDAL, RoleDAL, RolePermissionDAL, TokenDAL, UserDAL
from db.models import Permission, Role, User


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
            raise ValueError('Email is already registered')

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
        await self.user_dal.delete_user(db_user.user_pk)

    async def verify_user(self, user_pk: int):
        await self.user_dal.verify_user(user_pk)

    async def reset_password(self, user_pk: int, new_password: str):
        await self.user_dal.reset_password(user_pk, new_password)


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
        await self.user_dal.delete_user(user_pk)


class AuthenticationService:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.user_dal = UserDAL(self.db_session)

    async def get_user_by_email(self, email: str) -> User:
        user = await self.user_dal.get_user_by_email(email=email)
        if user is None:
            raise ValueError(f'User with the email {email} not found')
        return user

    async def authenticate_user(self, email: str, password: str) -> User:
        user = await self.get_user_by_email(email=email)
        if not user.verify_password(password):
            raise AuthenticationError("Incorrect username or password")
        return user

    async def get_user_from_token(self, token: str) -> User:
        payload = jwt.decode(
            token,
            os.getenv("JWT_SECRET_KEY"),
            algorithms=os.getenv("JWT_ALGORITHM"),
        )
        user_pk: str = payload.get("user_pk")
        return await self.user_dal.get_user_by_pk(user_pk=user_pk)


class TokenService:
    def __init__(
        self, db_session: AsyncSession, form_data: OAuth2PasswordRequestForm = None
    ):
        self.token_dal = TokenDAL(db_session)
        self.auth_service = AuthenticationService(db_session)
        self.user_dal = UserDAL(db_session)
        if form_data:
            self.form_data = form_data

    async def _set_jwt_payload(self) -> dict:
        user = await self.auth_service.authenticate_user(
            self.form_data.username, self.form_data.password
        )
        return {
            "sub": user.email,
            "user_pk": user.user_pk,
            "role": user.role.name,
            "first_name": user.first_name,
            "last_name": user.last_name,
        }

    async def create_access_token(
        self, user_data: dict = None, expires_delta: Optional[timedelta] = None
    ) -> Token:
        if user_data is None:
            user_data = await self._set_jwt_payload()
        to_encode = user_data.copy()
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
        return Token(
            access_token=token, access_token_expires_at=expire, token_type="Bearer"
        )

    async def update_access_token(self, refresh_token: str) -> Token:
        try:
            payload = jwt.decode(
                refresh_token,
                os.getenv("JWT_SECRET_KEY"),
                algorithms=[os.getenv("JWT_ALGORITHM")],
            )
            user_pk = payload.get("user_pk")
            user = await self.user_dal.get_user_by_pk(user_pk=user_pk)
            user_data = {
                "sub": user.email,
                "user_pk": user.user_pk,
                "role": user.role.name,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
            stored_refresh_token = self.token_dal.get_refresh_token(refresh_token)
            return await self.create_access_token(user_data)
        except jwt.ExpiredSignatureError:
            stored_refresh_token = await self.token_dal.get_refresh_token(refresh_token)
            user = await self.user_dal.get_user_by_pk(
                user_pk=stored_refresh_token.user_pk
            )
            user_data = {
                "sub": user.email,
                "user_pk": user.user_pk,
                "role": user.role.name,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
            new_refresh_token = await self.update_refresh_token_in_db(
                old_refresh_token=stored_refresh_token.token, user_data=user_data
            )
            access_token = await self.create_access_token(user_data)
            return Token(access_token=access_token, refresh_token=new_refresh_token)

    async def _create_refresh_token(self, user_data: dict = None) -> dict:
        if user_data is None:
            user_data = await self._set_jwt_payload()
        to_encode = user_data.copy()
        expire = datetime.utcnow() + timedelta(
            days=int(os.getenv("REFRESH_TOKEN_EXPIRATION_TIME"))
        )
        to_encode.update({"exp": expire})
        token = jwt.encode(
            to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM")
        )
        return {
            "user_pk": user_data["user_pk"],
            "refresh_token": token,
            "expires_at": expire,
        }

    async def add_refresh_token_to_db(self) -> dict:
        data = await self._create_refresh_token()
        await self.token_dal.add_refresh_token(data=data)
        return {"refresh_token": data["refresh_token"]}

    async def update_refresh_token_in_db(
        self, old_refresh_token: str, user_data: dict
    ) -> str:
        data = await self._create_refresh_token(user_data=user_data)
        await self.token_dal.update_refresh_token(
            old_refresh_token=old_refresh_token, data=data
        )
        return data["refresh_token"]


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
        payload = jwt.decode(
            token,
            os.getenv("JWT_FOR_LINK_SECRET_KEY"),
            algorithms=[os.getenv("JWT_ALGORITHM")],
        )
        email: str = payload.get("sub")
        return email

    async def send_email_with_link(self):
        message = MessageSchema(
            subject=self.subject,
            recipients=[self.email],
            template_body=self.email_body,
            subtype=MessageType.plain,
        )

        await self.email_agent.send_message(message)


# TODO:
class ResetPasswordService(EmailTokenService):
    @classmethod
    async def reset_password(
        cls,
        db: AsyncSession,
        secret_token: str,
        reset_forget_password: ResetForgetPassword,
    ):
        email = cls._decode_token_from_link(token=secret_token)
        auth_service = AuthenticationService(db)
        user = await auth_service.get_user_by_email(email)

        if reset_forget_password.new_password != reset_forget_password.confirm_password:
            raise PasswordsError("New password and password confirmation do not match.")
        if user.verify_password(reset_forget_password.new_password):
            raise PasswordsError("You have entered an old password.")

        user_service = UserService(db)
        await user_service.reset_password(
            user.user_pk, reset_forget_password.new_password
        )


class ConfirmRegistrationService(EmailTokenService):
    @classmethod
    async def confirm_registration(
        cls,
        db: AsyncSession,
        secret_token: str,
    ):
        email = cls._decode_token_from_link(token=secret_token)
        auth_service = AuthenticationService(db)
        user = await auth_service.get_user_by_email(email)
        user_service = UserService(db)
        await user_service.verify_user(user.user_pk)


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
