from db.models import RolePermission
from tests.conftest import *


@pytest.fixture
async def assign_roles_to_permission(
    async_session: AsyncSession, permission_for_test: Permission, role_for_test: Role
):
    role1 = Role(name="test_role_1", description="A test role 1")
    async_session.add(role1)
    await async_session.flush()
    await async_session.refresh(role1)

    permission_role1 = RolePermission(
        role_pk=role_for_test.role_pk, permission_pk=permission_for_test.permission_pk
    )
    permission_role2 = RolePermission(
        role_pk=role1.role_pk, permission_pk=permission_for_test.permission_pk
    )
    async_session.add_all([permission_role1, permission_role2])
    await async_session.flush()


async def test_read_roles_for_permission_as_admin(
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    role_for_test: Role,
    permission_for_test: Permission,
    assign_roles_to_permission,
):
    response = await async_client.get(
        f"/rp/permission/{permission_for_test.permission_pk}/roles/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data["permission_pk"] == permission_for_test.permission_pk
    assert len(data["roles"]) == 2
    assert any(role["role_pk"] == role_for_test.role_pk for role in data["roles"])


async def test_read_roles_for_permission_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_permission_pk = 0
    response = await async_client.get(
        f"/rp/permission/{not_existent_permission_pk}/roles/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == f"Permission with pk {not_existent_permission_pk} not found."
    )


async def test_read_roles_for_permission_unauthorized(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    permission_for_test: Permission,
):
    response = await async_client.get(
        f"/rp/permission/{permission_for_test.permission_pk}/roles/",
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
