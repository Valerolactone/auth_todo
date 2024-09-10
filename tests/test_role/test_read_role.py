from tests.conftest import *


async def test_read_role_existing(
    async_client: AsyncClient, admin_user: User, admin_token: str, role_for_test: Role
):
    response = await async_client.get(
        f"/roles/{role_for_test.role_pk}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data["name"] == role_for_test.name
    assert data["description"] == role_for_test.description


async def test_read_role_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    response = await async_client.get(
        f"/roles/{not_existent_pk}", headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"Role with pk {not_existent_pk} not found."}


async def test_read_role_unauthorized(async_client: AsyncClient, role_for_test: Role):
    response = await async_client.get(f"/roles/{role_for_test.role_pk}")
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data["name"] == role_for_test.name
    assert data["description"] == role_for_test.description
