from datetime import datetime
from logging import getLogger
from typing import Optional, Sequence

from fastapi import HTTPException, status
from schemas import AdminUserUpdate, UserCreate, UserUpdate
from sqlalchemy import and_, asc, desc, func, select
from sqlalchemy.exc import NoResultFound, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from db.models import Permission, RefreshToken, Role, RolePermission, User

logger = getLogger(__name__)

ALLOWED_SORT_FIELDS = [
    'user_pk',
    'created_at',
    'role_id',
    'first_name',
]
ALLOWED_FILTER_FIELDS = [
    'role_id',
]


class UserDAL:
    """Data Access Layer for operating user info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def _get_role_pk(self, role_name: str) -> int:
        query = select(Role.role_pk).where(Role.name == role_name)
        try:
            result = await self.db_session.execute(query)
            role_pk = result.scalar_one()
            return role_pk
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with name '{role_name}' not found.",
            )
        except SQLAlchemyError as err:
            logger.error("Error during getting role_pk from name: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get role_pk from name",
            )

    async def create_user(self, user_data: UserCreate) -> User:
        async with self.db_session.begin():
            default_role_name = "user"
            try:
                role_pk = self._get_role_pk(role_name=default_role_name)
                db_user = User(role_id=role_pk, **user_data.dict())
                self.db_session.add(db_user)
                await self.db_session.flush()
                await self.db_session.refresh(db_user)
                return db_user
            except SQLAlchemyError as err:
                logger.error("Error during user creation: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create a user.",
                )

    async def get_user_by_email(self, email: str) -> User | None:
        query = select(User).where(User.email == email).options(joinedload(User.role))
        try:
            result = await self.db_session.execute(query)
            user = result.scalar_one_or_none()
            return user
        except SQLAlchemyError as err:
            logger.error("Error during getting user by email: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get user by email",
            )

    async def get_user_by_pk(self, user_pk: int) -> User:
        query = (
            select(User).where(User.user_pk == user_pk).options(joinedload(User.role))
        )
        try:
            result = await self.db_session.execute(query)
            user = result.scalar_one()
            return user
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

    async def get_users_emails_for_notification(
        self, users_ids: list[int]
    ) -> Sequence[User]:
        query = select(User).filter(User.user_pk.in_(users_ids))
        try:
            result = await self.db_session.execute(query)
            users = result.scalars().all()
            return users
        except SQLAlchemyError as err:
            logger.error("Error during getting list of users by pks: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get list of users by pks",
            )

    async def count_users(self, filter_by: Optional[str] = None) -> int:
        query = select(func.count()).select_from(User)
        if filter_by and filter_by in ALLOWED_FILTER_FIELDS:
            query = query.where(User.name.ilike(f"%{filter_by}%"))
        try:
            result = await self.db_session.execute(query)
            total_users = result.scalar_one()
            return total_users
        except SQLAlchemyError as err:
            logger.error("Error during getting total amount of users: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get total amount of users",
            )

    async def fetch_users(
        self,
        page: int,
        page_size: int,
        sort_by: str,
        sort_order: str,
        filter_by: Optional[str] = None,
    ) -> Sequence[User]:
        skip = (page - 1) * page_size
        if sort_by not in ALLOWED_SORT_FIELDS:
            raise ValueError(f"Invalid sort field: {sort_by}")

        if sort_order not in ['asc', 'desc']:
            raise ValueError(f"Invalid sort order: {sort_order}")

        query = select(User).options(joinedload(User.role))
        if filter_by:
            if filter_by not in ALLOWED_FILTER_FIELDS:
                raise ValueError(f"Invalid filter field: {filter_by}")
            query = query.where(User.name.ilike(f"%{filter_by}%"))

        if sort_order == 'desc':
            query = query.order_by(desc(sort_by))
        else:
            query = query.order_by(asc(sort_by))
        query = query.offset(skip).limit(page_size)
        try:
            result = await self.db_session.execute(query)
            users = result.scalars().all()
            return users
        except SQLAlchemyError as err:
            logger.error("Error during fetching users: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to fetch users",
            )

    async def update_user(
        self, user_pk: int, user_data: UserUpdate | AdminUserUpdate
    ) -> User:
        async with self.db_session.begin():
            update_data = user_data.dict(exclude_unset=True)
            try:
                db_user = await self.get_user_by_pk(user_pk)
                if isinstance(user_data, UserUpdate):
                    for key, value in update_data.items():
                        setattr(db_user, key, value)
                else:
                    role_pk = await self._get_role_pk(role_name=user_data.role_name)
                    db_user.role_id = role_pk
                    db_user.is_active = user_data.is_active
                await self.db_session.flush()
                await self.db_session.refresh(db_user)
                return db_user
            except SQLAlchemyError as err:
                logger.error("Error during updating user: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update user",
                )

    async def delete_user(self, user_pk: int):
        async with self.db_session.begin():
            db_user = await self.get_user_by_pk(user_pk)
            db_user.is_active = False
            db_user.deleted_at = datetime.utcnow()
            try:
                self.db_session.add(db_user)
                await self.db_session.flush()
            except SQLAlchemyError as err:
                logger.error("Error during deleting user: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to delete user",
                )


class TokenDAL:
    """Data Access Layer for operating refresh token info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def add_refresh_token(self, data: dict):
        async with self.db_session.begin():
            db_refresh_token = RefreshToken(
                user_pk=data["user_pk"],
                token=data["refresh_token"],
                expires_at=data["expires_at"],
            )
            try:
                self.db_session.add(db_refresh_token)
                await self.db_session.flush()
            except SQLAlchemyError as err:
                logger.error("Error during addition refresh token: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to add refresh token",
                )

    async def get_refresh_token(self, token: str) -> RefreshToken:
        query = select(RefreshToken).where(
            and_(RefreshToken.token == token, RefreshToken.is_revoked == False)
        )
        try:
            result = await self.db_session.execute(query)
            refresh_token = result.scalar_one()
            return refresh_token
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Refresh token {token} not found.",
            )
        except SQLAlchemyError as err:
            logger.error("Error during getting refresh token: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get refresh token",
            )

    async def update_refresh_token(self, old_refresh_token: str, data: dict):
        async with self.db_session.begin():
            try:
                db_refresh_token = await self.get_refresh_token(old_refresh_token)
                db_refresh_token.token = data["refresh_token"]
                db_refresh_token.expires_at = data["expires_at"]
                self.db_session.add(db_refresh_token)
                await self.db_session.flush()
            except SQLAlchemyError as err:
                logger.error("Error during updating refresh token: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update refresh token",
                )


class PermissionDAL:
    """Data Access Layer for operating permission info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_permissions(self) -> Sequence[Permission] | None:
        query = select(Permission)
        result = await self.db_session.execute(query)
        permissions = result.scalars().all()
        if permissions is None:
            return
        return permissions

    async def get_permission_by_pk(self, permission_pk: int) -> Permission | None:
        query = select(Permission).where(Permission.permission_pk == permission_pk)
        result = await self.db_session.execute(query)
        permission_row = result.scalar_one_or_none()
        if permission_row is None:
            return
        return permission_row


class RoleDAL:
    """Data Access Layer for operating role info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_roles(self) -> Sequence[Role] | None:
        query = select(Role)
        result = await self.db_session.execute(query)
        roles = result.scalars().all()
        if roles is None:
            return
        return roles

    async def get_role_by_pk(self, role_pk: int) -> Role | None:
        query = select(Role).where(Role.role_pk == role_pk)
        result = await self.db_session.execute(query)
        role_row = result.scalar_one_or_none()
        if role_row is None:
            return
        return role_row

    async def get_role_pk_by_name(self, role_name: str) -> int:
        query = select(Role.role_pk).where(Role.name == role_name)
        try:
            result = await self.db_session.execute(query)
            role_pk = result.scalar_one()
            return role_pk
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with name '{role_name}' not found.",
            )
        except SQLAlchemyError as err:
            logger.error("Error during getting role_pk from name: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get role_pk from name",
            )


class RolePermissionDAL:
    """Data Access Layer for operating role_permission info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_role_permission(
        self, role_pk: int, permission_pk: int
    ) -> RolePermission | None:
        query = select(RolePermission).where(
            and_(
                RolePermission.role_pk == role_pk,
                RolePermission.permission_pk == permission_pk,
            )
        )
        result = await self.db_session.execute(query)
        role_permission_row = result.scalar_one_or_none()
        if role_permission_row is None:
            return
        return role_permission_row
