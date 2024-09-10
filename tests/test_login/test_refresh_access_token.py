from services import TokenService

from tests.conftest import *

# async def test_refresh_access_token(async_session: AsyncSession, async_client: AsyncClient, admin_user: User,
#                                     admin_token: str):
#     refresh_token_data = await TokenService(db_session=async_session)._create_refresh_token()
#     valid_refresh_token = refresh_token_data.get('refresh_token')
#
#     headers = {
#         "Authorization": f"Bearer {admin_token}",
#         "X-Refresh-Token": valid_refresh_token,
#     }
#
#     response = await async_client.post("login/token/refresh", headers=headers)
#
#     assert response.status_code == status.HTTP_201_CREATED
#     response_data = response.json()
#
#     assert "access_token" in response_data
#     assert response_data["token_type"] == "Bearer"
#
#
# async def test_refresh_access_token_expired(async_client: AsyncClient, expired_refresh_token: str, admin_user: User,
#                                             admin_token: str):
#     headers = {
#         "Authorization": f"Bearer {admin_token}",
#         "X-Refresh-Token": expired_refresh_token,
#     }
#
#     response = await async_client.post("/login/token/refresh", headers=headers)
#
#     assert response.status_code == status.HTTP_401_UNAUTHORIZED
#     response_data = response.json()
#
#     assert "detail" in response_data
#     assert response_data["detail"] == "Refresh token has expired"
#
#
# async def test_refresh_access_token_invalid(async_client: AsyncClient, admin_user: User,
#                                             admin_token: str):
#     headers = {
#         "Authorization": f"Bearer {admin_token}",
#         "X-Refresh-Token": "invalid_refresh_token",
#     }
#
#     response = await async_client.post("/login/token/refresh", headers=headers)
#
#     assert response.status_code == status.HTTP_200_OK
#     response_data = response.json()
#
#     assert "detail" in response_data
#     assert response_data["detail"] == "Invalid refresh token"
