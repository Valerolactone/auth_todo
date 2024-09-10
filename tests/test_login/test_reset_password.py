from unittest.mock import AsyncMock, patch

from jwt import ExpiredSignatureError, PyJWTError

from tests.conftest import *


@patch('app.services.ResetPasswordService.reset_password')
async def test_reset_password_success(
    mock_reset_password, async_session: AsyncSession, async_client: AsyncClient
):
    mock_reset_password.return_value = AsyncMock()

    reset_data = {
        "new_password": "new_secure_password",
        "confirm_password": "new_secure_password",
    }

    response = await async_client.post(
        "/login/reset-password/some_valid_token", json=reset_data
    )

    assert response.status_code == status.HTTP_200_OK
    mock_reset_password.assert_called_once()


@patch('app.services.ResetPasswordService.reset_password')
async def test_reset_password_expired_token(
    mock_reset_password, async_client: AsyncClient
):
    mock_reset_password.side_effect = ExpiredSignatureError

    reset_data = {
        "new_password": "new_secure_password",
        "confirm_password": "new_secure_password",
    }

    response = await async_client.post(
        "/login/reset-password/expired_token", json=reset_data
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Refresh token has expired"


@patch('app.services.ResetPasswordService.reset_password')
async def test_reset_password_invalid_token(
    mock_reset_password, async_client: AsyncClient
):
    mock_reset_password.side_effect = PyJWTError

    reset_data = {
        "new_password": "new_secure_password",
        "confirm_password": "new_secure_password",
    }

    response = await async_client.post(
        "/login/reset-password/invalid_token", json=reset_data
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Invalid refresh token"
