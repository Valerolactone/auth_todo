from unittest.mock import patch

from jwt import ExpiredSignatureError
from sqlalchemy import select

from tests.conftest import *


async def test_delete_user(
    async_session: AsyncSession,
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
):
    response = await async_client.delete(
        '/users/my_profile', headers={"Authorization": f"Bearer {not_admin_token}"}
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    deleted_user = await async_session.execute(
        select(User).filter_by(user_pk=not_admin_user.user_pk)
    )
    result = deleted_user.scalar_one()

    assert result.is_active == False
    assert result.deleted_at is not None


async def test_delete_user_unauthorized(async_client: AsyncClient):
    response = await async_client.delete('/users/my_profile')

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_delete_user_invalid_token(async_client: AsyncClient):
    response = await async_client.delete(
        '/users/my_profile', headers={"Authorization": f"Bearer invalid_token"}
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND

    response_data = response.json()
    assert response_data['detail'] == "Invalid token"


@patch('app.services.AuthenticationService.get_user_from_token')
async def test_delete_user_expired_token(
    mock_get_user_from_token, async_client: AsyncClient
):
    mock_get_user_from_token.side_effect = ExpiredSignatureError

    response = await async_client.delete(
        '/users/my_profile', headers={"Authorization": f"Bearer expired_token"}
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response_data = response.json()
    assert response_data['detail'] == "Token has expired"
