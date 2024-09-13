from unittest.mock import patch

from jwt import ExpiredSignatureError

from tests.conftest import *


async def test_update_user(
    async_client: AsyncClient, not_admin_user: User, not_admin_token: str
):
    request_data = {"password": "123456789", "first_name": "New first name"}
    response = await async_client.put(
        '/users/my_profile',
        json=request_data,
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()

    assert response_data['first_name'] == request_data["first_name"]


async def test_update_user_unauthorized(async_client: AsyncClient):
    request_data = {"password": "123456789", "first_name": "New first name"}
    response = await async_client.put('/users/my_profile', json=request_data)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_update_user_invalid_token(async_client: AsyncClient):
    request_data = {"password": "123456789", "first_name": "New first name"}
    response = await async_client.put(
        '/users/my_profile',
        json=request_data,
        headers={"Authorization": f"Bearer invalid_token"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND

    response_data = response.json()
    assert response_data['detail'] == "Invalid token"


@patch('app.services.AuthenticationService.get_user_from_token')
async def test_update_user_expired_token(
    mock_get_user_from_token, async_client: AsyncClient
):
    mock_get_user_from_token.side_effect = ExpiredSignatureError

    request_data = {"password": "123456789", "first_name": "New first name"}
    response = await async_client.put(
        '/users/my_profile',
        json=request_data,
        headers={"Authorization": f"Bearer expired_token"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response_data = response.json()
    assert response_data['detail'] == "Token has expired"
