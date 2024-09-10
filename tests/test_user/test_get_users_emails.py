from starlette.testclient import TestClient

from tests.conftest import *


async def test_get_users_emails(
    async_client: AsyncClient,
    not_admin_user: User,
    admin_user: User,
    user_for_test: User,
):
    request_data = {
        "ids": [not_admin_user.user_pk, admin_user.user_pk, user_for_test.user_pk]
    }
    response = await async_client.post('/users/notification_emails', json=request_data)

    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()
    assert response_data['users'] == {
        f"{not_admin_user.user_pk}": not_admin_user.email,
        f"{admin_user.user_pk}": admin_user.email,
        f"{user_for_test.user_pk}": user_for_test.email,
    }


async def test_get_users_emails_incorrect_ids(async_client: AsyncClient):
    request_data = {"ids": [9, 10]}
    response = await async_client.post('/users/notification_emails', json=request_data)

    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()
    assert response_data['users'] == {}
