from unittest.mock import patch

from sqlalchemy import select

from tests.conftest import *


@patch('app.services.EmailTokenService.send_email_with_link')
async def test_create_user(
    mock_send_email,
    async_session: AsyncSession,
    async_client: AsyncClient,
    user_role: Role,
):
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "password": "securepassword",
    }
    response = await async_client.post("/users/register", json=user_data)

    assert response.status_code == status.HTTP_201_CREATED
    response_data = response.json()

    assert response_data["first_name"] == user_data["first_name"]
    assert response_data["last_name"] == user_data["last_name"]
    assert response_data["email"] == user_data["email"]

    user = await async_session.execute(select(User).filter_by(email=user_data["email"]))

    assert user.scalar() is not None
    mock_send_email.assert_called_once()


@patch('app.services.EmailTokenService.send_email_with_link')
async def test_create_user_email_already_registered(
    mock_send_email,
    async_session: AsyncSession,
    async_client: AsyncClient,
    user_role: Role,
    user_for_test: User,
):
    user_data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": user_for_test.email,
        "password": "securepassword",
    }
    response = await async_client.post("/users/register", json=user_data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    response_data = response.json()

    assert response_data["detail"] == "Email is already registered"

    mock_send_email.assert_not_called()
