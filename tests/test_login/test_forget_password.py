from unittest.mock import ANY, patch

from tests.conftest import *


@patch('app.services.EmailTokenService.send_email_with_link')
async def test_forget_password(
    mock_send_email, async_client: AsyncClient, user_for_test: User
):
    response = await async_client.post(
        "/login/forget-password", json={"email": user_for_test.email}
    )

    assert response.status_code == status.HTTP_200_OK
    mock_send_email.assert_called_once()


@patch('app.services.EmailTokenService.send_email_with_link')
async def test_forget_password_user_not_found(
    mock_send_email, async_client: AsyncClient
):
    with patch('app.services.AuthenticationService.get_user_by_email') as mock_get_user:
        mock_get_user.side_effect = ValueError(
            "User with the email non_existent@example.com not found"
        )

        response = await async_client.post(
            "/login/forget-password", json={"email": "non_existent@example.com"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()

        assert (
            data["detail"] == "User with the email non_existent@example.com not found"
        )
        mock_send_email.assert_not_called()
