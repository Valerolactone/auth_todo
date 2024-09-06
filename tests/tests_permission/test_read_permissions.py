# from fastapi import status
# from db.models import Permission
# from tests.conftest import *
#
#
# async def test_read_permissions_without_permissions(async_client: AsyncClient):
#     response = await async_client.get("/permissions/")
#
#     assert response.status_code == status.HTTP_200_OK
#     assert response.json() == []
#
#
# async def test_read_permissions_with_permissions_as_admin(async_session: AsyncSession, async_client: AsyncClient,
#                                                           admin_user: User, admin_token: str):
#     permissions = [
#         Permission(name="read", description="Read Permission"),
#         Permission(name="write", description="Write Permission")
#     ]
#     async_session.add_all(permissions)
#     await async_session.flush()
#
#     response = await async_client.get("/permissions/", headers={"Authorization": f"Bearer {admin_token}"})
#     data = response.json()
#
#     assert response.status_code == status.HTTP_200_OK
#     assert len(data) == 2
#     assert any(permission['name'] == "read" for permission in data)
#     assert any(permission['name'] == "write" for permission in data)
#
#
# async def test_read_permissions_no_auth(async_client: AsyncClient):
#     response = await async_client.get("/permissions/")
#     data = response.json()
#
#     assert response.status_code == status.HTTP_200_OK
#     assert isinstance(data, list)
