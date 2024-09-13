from sqlalchemy import and_, select

from db.models import RolePermission
from tests.conftest import *


async def test_assign_permission_to_role_as_admin(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    role_for_test: Role,
    permission_for_test: Permission,
):
    response = await async_client.post(
        "/rp/",
        json={"role": role_for_test.name, "permission": permission_for_test.name},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = response.json()

    assert response.status_code == status.HTTP_201_CREATED
    assert data["role_pk"] == role_for_test.role_pk
    assert data["permission_pk"] == permission_for_test.permission_pk
    assert data["role"] == role_for_test.name
    assert data["permission"] == permission_for_test.name

    role_permission = await async_session.execute(
        select(RolePermission).where(
            and_(
                RolePermission.role_pk == role_for_test.role_pk,
                RolePermission.permission_pk == permission_for_test.permission_pk,
            )
        )
    )
    assert role_permission.scalar() is not None


async def test_assign_permission_to_role_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    role_for_test: Role,
    permission_for_test: Permission,
):
    response = await async_client.post(
        "/rp/",
        json={"role": role_for_test.name, "permission": permission_for_test.name},
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_assign_permission_to_role_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    role_for_test: Role,
    permission_for_test: Permission,
):
    response = await async_client.post(
        "/rp/",
        json={"role": role_for_test.name, "permission": permission_for_test.name},
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_assign_permission_to_role_unauthorized(
    async_client: AsyncClient, role_for_test: Role, permission_for_test: Permission
):
    response = await async_client.post(
        "/rp/",
        json={"role": role_for_test.name, "permission": permission_for_test.name},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_assign_permission_to_role_invalid_data(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    invalid_role_permission_data = {"role": "admin"}
    response = await async_client.post(
        "/rp/",
        json=invalid_role_permission_data,
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
