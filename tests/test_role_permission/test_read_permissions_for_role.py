from db.models import RolePermission
from tests.conftest import *


@pytest.fixture
async def assign_permissions_to_role(
    async_session: AsyncSession, role_for_test: Role, permission_for_test: Permission
):
    permission1 = Permission(
        name="test_permission_1", description="A test permission 1"
    )
    async_session.add(permission1)
    await async_session.flush()
    await async_session.refresh(permission1)

    role_permission1 = RolePermission(
        role_pk=role_for_test.role_pk, permission_pk=permission1.permission_pk
    )
    role_permission2 = RolePermission(
        role_pk=role_for_test.role_pk, permission_pk=permission_for_test.permission_pk
    )
    async_session.add_all([role_permission1, role_permission2])
    await async_session.flush()


async def test_read_permissions_for_role_as_admin(
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    role_for_test: Role,
    permission_for_test: Permission,
    assign_permissions_to_role,
):
    response = await async_client.get(
        f"/rp/role/{role_for_test.role_pk}/permissions/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data["role_pk"] == role_for_test.role_pk
    assert len(data["permissions"]) == 2
    assert any(
        permission["permission_pk"] == permission_for_test.permission_pk
        for permission in data["permissions"]
    )


async def test_read_permissions_for_role_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_role_pk = 0
    response = await async_client.get(
        f"/rp/role/{not_existent_role_pk}/permissions/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"] == f"Role with pk {not_existent_role_pk} not found."
    )


async def test_read_permissions_for_role_unauthorized(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    role_for_test: Role,
):
    response = await async_client.get(
        f"/rp/role/{role_for_test.role_pk}/permissions/",
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
