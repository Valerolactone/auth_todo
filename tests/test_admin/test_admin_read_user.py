from tests.conftest import *


async def test_admin_read_user(
    async_client: AsyncClient, admin_user: User, admin_token: str, user_for_test: User
):
    response = await async_client.get(
        f"/admin/{user_for_test.user_pk}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data["created_at"] == user_for_test.created_at.isoformat().replace(
        "+00:00", "Z"
    )
    assert data["is_active"] == user_for_test.is_active


async def test_read_user_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    response = await async_client.get(
        f"/admin/{not_existent_pk}", headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"User with pk {not_existent_pk} not found."}


async def test_admin_read_user_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    user_for_test: User,
):
    response = await async_client.get(
        f"/admin/{user_for_test.user_pk}",
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_admin_read_user_unauthorized(
    async_client: AsyncClient, user_for_test: User
):
    response = await async_client.get(f"/admin/{user_for_test.user_pk}")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
