from unittest.mock import patch

from tests.conftest import *


@patch('app.services.EmailTokenService.send_email_with_link')
async def test_send_new_confirmation_link(
    mock_send_email, async_client: AsyncClient, not_admin_user: User
):
    request_data = {
        "email": not_admin_user.email,
    }

    response = await async_client.post(
        "/users/resend-confirmation-link", json=request_data
    )
    assert response.status_code == status.HTTP_200_OK
    mock_send_email.assert_called_once()


@patch('app.services.EmailTokenService.send_email_with_link')
async def test_resend_confirmation_link_invalid_email(
    mock_send_email, async_client: AsyncClient
):
    request_data = {"email": "invalid-email"}

    response = await async_client.post("/resend-confirmation-link", json=request_data)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    mock_send_email.assert_not_called()
