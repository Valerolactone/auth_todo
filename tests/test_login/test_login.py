from tests.conftest import *


async def test_login(async_client: AsyncClient, user_for_test: User):
    login_data = {
        "username": user_for_test.email,
        "password": "123456",
    }
    response = await async_client.post("/login/token", data=login_data)

    assert response.status_code == status.HTTP_201_CREATED
    response_data = response.json()

    assert "access_token" in response_data
    assert "refresh_token" in response_data
    assert response_data["token_type"] == "Bearer"


async def test_login_invalid_password(async_client: AsyncClient, user_for_test: User):
    login_data = {
        "username": user_for_test.email,
        "password": "invalid_password",
    }

    response = await async_client.post("/login/token", data=login_data)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response_data = response.json()

    assert "detail" in response_data
    assert response_data["detail"] == "Incorrect username or password"


async def test_login_nonexistent_user(
    async_client: AsyncClient,
):
    login_data = {
        "username": "nonexistent@example.com",
        "password": "some_password",
    }

    response = await async_client.post("/login/token", data=login_data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    response_data = response.json()

    assert "detail" in response_data
    assert (
        response_data["detail"]
        == f"User with the email {login_data["username"]} not found"
    )
