from sqlalchemy import select

from tests.conftest import *


async def test_update_permission_existing(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    permission_for_test: Permission,
):
    update_data = {"name": "read_updated", "description": "Read Permission Updated"}
    response = await async_client.put(
        f"/permissions/{permission_for_test.permission_pk}",
        json=update_data,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == status.HTTP_200_OK

    updated_permission = await async_session.execute(
        select(Permission).filter_by(permission_pk=permission_for_test.permission_pk)
    )
    result = updated_permission.scalar_one()

    assert result.name == update_data["name"]
    assert result.description == update_data["description"]


async def test_update_permission_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    update_data = {"name": "non_existent", "description": "Non Existent Permission"}

    response = await async_client.put(
        f"/permissions/{not_existent_pk}",
        json=update_data,
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": f"Permission with pk {not_existent_pk} not found."
    }


async def test_update_permission_unauthorized(
    async_client: AsyncClient, permission_for_test: Permission
):
    update_data = {"name": "write_updated", "description": "Write Permission Updated"}

    response = await async_client.put(
        f"/permissions/{permission_for_test.permission_pk}", json=update_data
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_update_permission_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    permission_for_test: Permission,
):
    update_data = {"name": "write_updated", "description": "Write Permission Updated"}

    response = await async_client.put(
        f"/permissions/{permission_for_test.permission_pk}",
        json=update_data,
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
