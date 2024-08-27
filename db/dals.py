from logging import getLogger
from typing import List, Sequence

from fastapi import HTTPException, status
from schemas import (
    PermissionCreate,
    PermissionUpdate,
    RoleCreate,
    RolePermissionData,
    RoleUpdate,
)
from sqlalchemy import Row, and_, select
from sqlalchemy.exc import NoResultFound, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from db.models import Permission, RefreshToken, Role, RolePermission, User

logger = getLogger(__name__)


class UserDAL:
    """Data Access Layer for operating user info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def create_user(
        self,
        first_name: str,
        last_name: str,
        email: str,
        password: str,
    ) -> User:
        new_user = User(
            first_name=first_name, last_name=last_name, email=email, password=password
        )
        self.db_session.add(new_user)
        await self.db_session.flush()
        return new_user

    async def get_user_by_email(self, email: str) -> User | None:
        query = select(User).where(User.email == email)
        result = await self.db_session.execute(query)
        user_row = result.fetchone()
        if user_row is None:
            return
        return user_row[0]

    async def get_user_by_pk(self, user_pk: int) -> User | None:
        query = select(User).where(User.user_pk == user_pk)
        result = await self.db_session.execute(query)
        user_row = result.fetchone()
        if user_row is None:
            return
        return user_row[0]

    async def get_users_emails_for_notification(
        self, users_ids: list[int]
    ) -> Sequence[Row[tuple[User]]] | None:
        query = select(User).filter(User.user_pk.in_(users_ids))
        result = await self.db_session.execute(query)
        users = result.fetchall()
        if users is None:
            return
        return users


class TokenDAL:
    """Data Access Layer for operating refresh token info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        query = select(RefreshToken).where(
            and_(RefreshToken.token == token, RefreshToken.is_revoked == False)
        )
        result = await self.db_session.execute(query)
        refresh_token_row = result.fetchone()
        if refresh_token_row is None:
            return
        return refresh_token_row[0]

    async def validate_refresh_token(self, token: str) -> bool:
        refresh_token = await self.get_refresh_token(token)
        return False if refresh_token is None else True


class PermissionDAL:
    """Data Access Layer for operating permission info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def create_permission(self, permission_data: PermissionCreate) -> Permission:
        async with self.db_session.begin():
            try:
                db_permission = Permission(**permission_data.dict())
                self.db_session.add(db_permission)
                await self.db_session.flush()
                await self.db_session.refresh(db_permission)
                return db_permission
            except SQLAlchemyError as err:
                logger.error("Error during permission creation: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create a permission.",
                )

    async def get_permissions(self) -> Sequence[Permission]:
        query = select(Permission)
        try:
            result = await self.db_session.execute(query)
            permissions = result.scalars().all()
            return permissions
        except SQLAlchemyError as err:
            logger.error("Error during getting all permissions: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get all permissions",
            )

    async def get_permission_by_pk(self, permission_pk: int) -> Permission:
        query = select(Permission).where(Permission.permission_pk == permission_pk)
        try:
            result = await self.db_session.execute(query)
            permission = result.scalar_one()
            return permission
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission with pk {permission_pk} not found.",
            )
        except SQLAlchemyError as err:
            logger.error("Error during getting permission by pk: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get permission by pk",
            )

    async def update_permission(
        self, permission_pk: int, permission_data: PermissionUpdate
    ) -> Permission:
        async with self.db_session.begin():
            db_permission = await self.get_permission_by_pk(permission_pk)
            update_data = permission_data.dict(exclude_unset=True)
            try:
                for key, value in update_data.items():
                    setattr(db_permission, key, value)
                await self.db_session.flush()
                await self.db_session.refresh(db_permission)
                return db_permission
            except SQLAlchemyError as err:
                logger.error("Error during updating permission: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to update permission with pk {permission_pk}",
                )

    async def delete_permission(self, permission_pk: int) -> Permission:
        async with self.db_session.begin():
            db_permission = await self.get_permission_by_pk(permission_pk)
            try:
                await self.db_session.delete(db_permission)
                await self.db_session.flush()
                return db_permission
            except SQLAlchemyError as err:
                logger.error("Error during deleting permission: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to delete permission with pk {permission_pk}",
                )


class RoleDAL:
    """Data Access Layer for operating role info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def create_role(self, role_data: RoleCreate) -> Role:
        async with self.db_session.begin():
            try:
                db_role = Role(**role_data.dict())
                self.db_session.add(db_role)
                await self.db_session.flush()
                await self.db_session.refresh(db_role)
                return db_role
            except SQLAlchemyError as err:
                logger.error("Error during role creation: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create a role.",
                )

    async def get_roles(self) -> Sequence[Role]:
        query = select(Role)
        try:
            result = await self.db_session.execute(query)
            roles = result.scalars().all()
            return roles
        except SQLAlchemyError as err:
            logger.error("Error during getting all roles: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get all roles",
            )

    async def get_role_by_pk(self, role_pk: int) -> Role:
        query = select(Role).where(Role.role_pk == role_pk)
        try:
            result = await self.db_session.execute(query)
            role = result.scalar_one()
            return role
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with pk {role_pk} not found.",
            )
        except SQLAlchemyError as err:
            logger.error("Error during getting role by pk: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get role by pk",
            )

    async def update_role(self, role_pk: int, role_data: RoleUpdate) -> Role:
        async with self.db_session.begin():
            db_role = await self.get_role_by_pk(role_pk)
            update_data = role_data.dict(exclude_unset=True)
            try:
                for key, value in update_data.items():
                    setattr(db_role, key, value)
                await self.db_session.flush()
                await self.db_session.refresh(db_role)
                return db_role
            except SQLAlchemyError as err:
                logger.error("Error during updating role: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to update role with pk {role_pk}",
                )

    async def delete_role(self, role_pk: int) -> Role:
        async with self.db_session.begin():
            db_role = await self.get_role_by_pk(role_pk)
            try:
                await self.db_session.delete(db_role)
                await self.db_session.flush()
                return db_role
            except SQLAlchemyError as err:
                logger.error("Error during deleting role: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to delete role with pk {role_pk}",
                )


class RolePermissionDAL:
    """Data Access Layer for operating role_permission info"""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def _get_role_by_name(self, role_name: str) -> Role:
        query = select(Role).where(Role.name == role_name)
        try:
            result = await self.db_session.execute(query)
            role = result.scalar_one()
            return role
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with name {role_name} not found.",
            )
        except SQLAlchemyError as err:
            logger.error("Error during getting role by name: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get role by name",
            )

    async def _get_permission_by_name(self, permission_name: str) -> Permission:
        query = select(Permission).where(Permission.name == permission_name)
        try:
            result = await self.db_session.execute(query)
            permission = result.scalar_one()
            return permission
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission with name {permission_name} not found.",
            )
        except SQLAlchemyError as err:
            logger.error("Error during getting permission by name: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get permission by name",
            )

    async def _get_role_permission(
        self, role_pk: int, permission_pk: int
    ) -> RolePermission:
        query = select(RolePermission).where(
            and_(
                RolePermission.role_pk == role_pk,
                RolePermission.permission_pk == permission_pk,
            )
        )
        try:
            result = await self.db_session.execute(query)
            role_permission = result.scalar_one()
            return role_permission
        except NoResultFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with pk {role_pk} doesn't have permission with pk {permission_pk}.",
            )
        except SQLAlchemyError as err:
            logger.error(
                f"Error during getting role-permission pair with pks {role_pk}-{permission_pk}: %s",
                str(err),
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get a role-permission pair.",
            )

    async def create_role_permission(self, data: RolePermissionData) -> RolePermission:
        async with self.db_session.begin():
            role = await self._get_role_by_name(data.role)
            permission = await self._get_permission_by_name(data.permission)
            try:
                db_role_permission = RolePermission(
                    permission_pk=permission.permission_pk, role_pk=role.role_pk
                )
                self.db_session.add(db_role_permission)
                await self.db_session.flush()
                await self.db_session.refresh(db_role_permission)
                return db_role_permission
            except SQLAlchemyError as err:
                logger.error("Error during role permission creation: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create a role permission.",
                )

    async def get_role_with_permissions(self, role_pk: int) -> Role:
        query = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.role_pk == role_pk)
        )
        async with self.db_session.begin():
            try:
                result = await self.db_session.execute(query)
                role = result.scalar_one()
                return role
            except NoResultFound:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Role with pk {role_pk} not found.",
                )
            except SQLAlchemyError as err:
                logger.error("Error during getting role with permissions: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to get a role with permissions.",
                )

    async def get_permission_with_roles(self, permission_pk: int) -> Permission:
        query = (
            select(Permission)
            .options(selectinload(Permission.roles))
            .where(Permission.permission_pk == permission_pk)
        )
        async with self.db_session.begin():
            try:
                result = await self.db_session.execute(query)
                permission = result.scalar_one()
                return permission
            except NoResultFound:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Permission with pk {permission_pk} not found.",
                )
            except SQLAlchemyError as err:
                logger.error("Error during getting permission with roles: %s", str(err))
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to get a permission with roles.",
                )

    async def delete_role_permission(self, data: RolePermissionData) -> RolePermission:
        async with self.db_session.begin():
            role = await self._get_role_by_name(data.role)
            permission = await self._get_permission_by_name(data.permission)
            db_role_permission = await self._get_role_permission(
                role_pk=role.role_pk, permission_pk=permission.permission_pk
            )
            try:
                await self.db_session.delete(db_role_permission)
                await self.db_session.flush()
                return db_role_permission
            except SQLAlchemyError as err:
                logger.error(
                    f"Error during deleting role-permission pair {data.role}-{data.permission}: %s",
                    str(err),
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to delete a role-permission pair.",
                )
