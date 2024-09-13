from sqlalchemy import and_, select

from db.models import RolePermission
from tests.conftest import *


@pytest.fixture
async def assign_permission_to_role(
    async_session: AsyncSession, role_for_test: Role, permission_for_test: Permission
):
    role_permission = RolePermission(
        role_pk=role_for_test.role_pk, permission_pk=permission_for_test.permission_pk
    )
    async_session.add(role_permission)
    await async_session.flush()


async def test_remove_permission_from_role_as_admin(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    assign_permission_to_role,
    role_for_test: Role,
    permission_for_test: Permission,
):
    response = await async_client.delete(
        f"/rp/{role_for_test.name}/{permission_for_test.name}/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    deleted_role_permission = await async_session.execute(
        select(RolePermission).where(
            and_(
                RolePermission.role_pk == role_for_test.role_pk,
                RolePermission.permission_pk == permission_for_test.permission_pk,
            )
        )
    )

    assert deleted_role_permission.scalar() is None


async def test_remove_permission_from_role_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_role = "role"
    not_existent_permission = "permission"
    response = await async_client.delete(
        f"/rp/{not_existent_role}/{not_existent_permission}/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == f"Role '{not_existent_role}' or permission '{not_existent_permission}' not found."
    )


async def test_remove_permission_from_role_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    assign_permission_to_role,
    role_for_test: Role,
    permission_for_test: Permission,
):
    response = await async_client.delete(
        f"/rp/{role_for_test.name}/{permission_for_test.name}/",
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_remove_permission_from_role_unauthorized(
    async_client: AsyncClient,
    assign_permission_to_role,
    role_for_test: Role,
    permission_for_test: Permission,
):
    response = await async_client.delete(
        f"/rp/{role_for_test.name}/{permission_for_test.name}/",
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
