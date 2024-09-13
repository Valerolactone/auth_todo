from tests.conftest import *


async def test_admin_update_user(
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    user_for_test: User,
    role_for_test: Role,
    user_role: Role,
):
    response1 = await async_client.put(
        f'/admin/{user_for_test.user_pk}',
        json={"role_name": role_for_test.name},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    response1_data = response1.json()

    assert response1.status_code == status.HTTP_200_OK
    assert response1_data['role'] == role_for_test.name

    response2 = await async_client.put(
        f'/admin/{user_for_test.user_pk}',
        json={"role_name": user_role.name},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    response2_data = response2.json()

    assert response2.status_code == status.HTTP_200_OK
    assert response2_data['role'] == user_role.name


async def test_admin_update_user_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str, role_for_test: Role
):
    not_existent_pk = 0
    response = await async_client.put(
        f'/admin/{not_existent_pk}',
        json={"role_name": role_for_test.name},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"User with pk {not_existent_pk} not found."}


async def test_admin_update_user_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    user_for_test: User,
    role_for_test: Role,
):
    response = await async_client.put(
        f'/admin/{user_for_test.user_pk}',
        json={"role_name": role_for_test.name},
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_admin_update_user_unauthorized(
    async_client: AsyncClient, user_for_test: User, role_for_test: Role
):
    response = await async_client.put(
        f'/admin/{user_for_test.user_pk}',
        json={"role_name": role_for_test.name},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
