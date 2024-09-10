from unittest.mock import ANY, patch

from jwt import ExpiredSignatureError, PyJWTError
from sqlalchemy.exc import NoResultFound

from tests.conftest import *


@patch('app.services.ConfirmRegistrationService.confirm_registration')
async def test_confirm_registration_success(
    mock_confirm_registration, async_client: AsyncClient
):
    response = await async_client.get("/users/confirm-registration/valid_token")

    assert response.status_code == status.HTTP_200_OK
    mock_confirm_registration.assert_called_once_with(ANY, 'valid_token')


@patch('app.services.ConfirmRegistrationService.confirm_registration')
async def test_confirm_registration_expired_token(
    mock_confirm_registration, async_client: AsyncClient
):
    mock_confirm_registration.side_effect = ExpiredSignatureError

    response = await async_client.get("/users/confirm-registration/expired_token")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Link has expired"


@patch('app.services.ConfirmRegistrationService.confirm_registration')
async def test_confirm_registration_invalid_token(
    mock_confirm_registration, async_client: AsyncClient
):
    mock_confirm_registration.side_effect = PyJWTError

    response = await async_client.get("/users/confirm-registration/invalid_token")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid link"


@patch('app.services.ConfirmRegistrationService.confirm_registration')
async def test_confirm_registration_user_not_found(
    mock_confirm_registration, async_client: AsyncClient
):
    mock_confirm_registration.side_effect = NoResultFound

    response = await async_client.get(
        "/users/confirm-registration/non_existent_user_token"
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "User not found."


@patch('app.services.ConfirmRegistrationService.confirm_registration')
async def test_confirm_registration_value_error(
    mock_confirm_registration, async_client: AsyncClient
):
    mock_confirm_registration.side_effect = ValueError("Invalid token data")

    response = await async_client.get("/users/confirm-registration/invalid_token_data")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Invalid token data"
