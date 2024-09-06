# from sqlalchemy import select
# from fastapi import status
#
# from db.models import Permission
# from tests.conftest import *
#
#
# @pytest.fixture()
# async def update_permission(async_session: AsyncSession) -> Permission:
#     permission = Permission(name="Update me", description="Update me permission")
#     async_session.add(permission)
#     await async_session.flush()
#     await async_session.refresh(permission)
#     return permission
#
#
# async def test_update_permission_existing(async_session: AsyncSession, async_client: AsyncClient, admin_user: User,
#                                           admin_token: str, update_permission: Permission):
#     update_data = {"name": "read_updated", "description": "Read Permission Updated"}
#     response = await async_client.put(
#         f"/permissions/{update_permission.permission_pk}",
#         json=update_data,
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#     assert response.status_code == status.HTTP_200_OK
#
#     updated_permission = await async_session.execute(
#         select(Permission).filter_by(permission_pk=update_permission.permission_pk)
#     )
#     result = updated_permission.scalar_one()
#
#     assert result.name == update_data["name"]
#     assert result.description == update_data["description"]
#
#
# async def test_update_permission_non_existent(async_client: AsyncClient, admin_user: User, admin_token: str):
#     non_existent_pk = 0
#     update_data = {"name": "non_existent", "description": "Non Existent Permission"}
#
#     response = await async_client.put(
#         f"/permissions/{non_existent_pk}",
#         json=update_data,
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json() == {"detail": f"Permission with pk {non_existent_pk} not found."}
#
#
# async def test_update_permission_no_auth(async_client: AsyncClient, update_permission: Permission):
#     update_data = {"name": "write_updated", "description": "Write Permission Updated"}
#
#     response = await async_client.put(
#         f"/permissions/{update_permission.permission_pk}",
#         json=update_data
#     )
#
#     assert response.status_code == status.HTTP_401_UNAUTHORIZED
#
#
# async def test_update_permission_as_non_admin(async_client: AsyncClient, non_admin_user: User, non_admin_token: str,
#                                               update_permission: Permission):
#     update_data = {"name": "write_updated", "description": "Write Permission Updated"}
#
#     response = await async_client.put(
#         f"/permissions/{update_permission.permission_pk}",
#         json=update_data,
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_403_FORBIDDEN
