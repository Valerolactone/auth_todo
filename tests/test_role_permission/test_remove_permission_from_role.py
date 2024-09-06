# from sqlalchemy import select
# from fastapi import status
#
# from db.models import Permission, RolePermission
# from tests.conftest import *
# @pytest.mark.asyncio
# async def test_remove_permission_from_role_success(
#         async_client: AsyncClient,
#         admin_token: str,
#         async_session_maker
# ):
#     # Setup: Create a role and a permission, then assign the permission to the role
#     async with async_session_maker() as session:
#         async with session.begin():
#             role = Role(name="test_role", description="A test role")
#             session.add(role)
#             await session.flush()
#             await session.refresh(role)
#
#             permission = Permission(name="test_permission", description="A test permission")
#             session.add(permission)
#             await session.flush()
#             await session.refresh(permission)
#
#             role_permission = RolePermission(role_id=role.role_pk, permission_id=permission.permission_pk)
#             session.add(role_permission)
#             await session.flush()
#
#     # Act: Remove the permission from the role
#     response = await async_client.delete(
#         "/role_permissions/",
#         json={
#             "role": role.role_pk,
#             "permission": permission.permission_pk
#         },
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     # Assert: Check response status
#     assert response.status_code == status.HTTP_204_NO_CONTENT
#
#     # Verify the permission is removed
#     async with async_session_maker() as session:
#         result = await session.execute(
#             "SELECT * FROM role_permissions WHERE role_id = :role_id AND permission_id = :permission_id",
#             {"role_id": role.role_pk, "permission_id": permission.permission_pk}
#         )
#         assert result.rowcount == 0
#
#
# @pytest.mark.asyncio
# async def test_remove_permission_from_role_not_found(
#         async_client: AsyncClient,
#         admin_token: str
# ):
#     # Act: Try to remove a permission from a role that does not exist
#     response = await async_client.delete(
#         "/role_permissions/",
#         json={
#             "role": 9999,  # Assuming 9999 is a non-existent role_id
#             "permission": 9999  # Assuming 9999 is a non-existent permission_id
#         },
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     # Assert: Should return 404 Not Found
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json()["detail"] == "Role '9999' or permission '9999' not found."
#
#
# @pytest.mark.asyncio
# async def test_remove_permission_from_role_unauthorized(
#         async_client: AsyncClient,
#         non_admin_token: str
# ):
#     # Setup: Create a role and a permission, then assign the permission to the role
#     async with async_session_maker() as session:
#         async with session.begin():
#             role = Role(name="test_role_unauth", description="A test role for unauthorized test")
#             session.add(role)
#             await session.flush()
#             await session.refresh(role)
#
#             permission = Permission(name="test_permission_unauth",
#                                     description="A test permission for unauthorized test")
#             session.add(permission)
#             await session.flush()
#             await session.refresh(permission)
#
#             role_permission = RolePermission(role_id=role.role_pk, permission_id=permission.permission_pk)
#             session.add(role_permission)
#             await session.flush()
#
#     # Act: Try to remove the permission from the role with a non-admin token
#     response = await async_client.delete(
#         "/role_permissions/",
#         json={
#             "role": role.role_pk,
#             "permission": permission.permission_pk
#         },
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     # Assert: Should return 403 Forbidden
#     assert response.status_code == status.HTTP_403_FORBIDDEN
