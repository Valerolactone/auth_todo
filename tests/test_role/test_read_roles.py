# from fastapi import status
# from tests.conftest import *
#
#
# async def test_read_roles_without_roles(async_client: AsyncClient):
#     response = await async_client.get("/roles/")
#
#     assert response.status_code == status.HTTP_200_OK
#     assert response.json() == []
#
#
# async def test_read_roles_with_roles_as_admin(async_session: AsyncSession, async_client: AsyncClient, admin_user: User,
#                                               admin_token: str):
#     roles = [
#         Role(name="moderator", description="Moderator role"),
#         Role(name="assistant", description="Assistant role")
#     ]
#     async_session.add_all(roles)
#     await async_session.flush()
#
#     response = await async_client.get("/roles/", headers={"Authorization": f"Bearer {admin_token}"})
#     data = response.json()
#
#     assert response.status_code == status.HTTP_200_OK
#     assert len(data) == 3
#     assert any(role['name'] == "moderator" for role in data)
#     assert any(role['name'] == "assistant" for role in data)
#     assert any(role['name'] == "admin" for role in data)
#
#
# async def test_read_roles_no_auth(async_client: AsyncClient):
#     response = await async_client.get("/roles/")
#     data = response.json()
#
#     assert response.status_code == status.HTTP_200_OK
#     assert isinstance(data, list)
