from typing import Sequence

from sqlalchemy import Row, and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Permission, RefreshToken, Role, User


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
