from tests.conftest import *


async def test_read_user(
    async_client: AsyncClient,
    user_for_test: User,
    not_admin_user: User,
    not_admin_token: str,
):
    response = await async_client.get(
        f"/users/{user_for_test.user_pk}",
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()

    assert "created_at" not in response_data
    assert "is_active" not in response_data

    assert response_data["first_name"] == user_for_test.first_name
    assert response_data["last_name"] == user_for_test.last_name


async def test_read_user_not_existent(async_client: AsyncClient):
    not_existent_pk = 0
    response = await async_client.get(f"/users/{not_existent_pk}")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"User with pk {not_existent_pk} not found."}


async def test_read_user_unauthorized(async_client: AsyncClient, user_for_test: User):
    response = await async_client.get(f"/users/{user_for_test.user_pk}")

    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()

    assert "created_at" not in response_data
    assert "is_active" not in response_data

    assert response_data["first_name"] == user_for_test.first_name
    assert response_data["last_name"] == user_for_test.last_name
