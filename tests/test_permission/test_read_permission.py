from tests.conftest import *


async def test_read_permission_existing(
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    permission_for_test: Permission,
):
    response = await async_client.get(
        f"/permissions/{permission_for_test.permission_pk}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data["name"] == permission_for_test.name
    assert data["description"] == permission_for_test.description


async def test_read_permission_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    response = await async_client.get(
        f"/permissions/{not_existent_pk}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": f"Permission with pk {not_existent_pk} not found."
    }


async def test_read_permission_unauthorized(
    async_client: AsyncClient, permission_for_test: Permission
):
    response = await async_client.get(
        f"/permissions/{permission_for_test.permission_pk}"
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data["name"] == permission_for_test.name
    assert data["description"] == permission_for_test.description
