# from sqlalchemy import select
# from fastapi import status
#
# from db.models import Permission, RolePermission
# from tests.conftest import *
# @pytest.mark.asyncio
# async def test_read_roles_for_permission_success(
#     async_client: AsyncClient,
#     admin_token: str,
#     async_session_maker
# ):
#     # Setup: Create a permission and assign roles
#     async with async_session_maker() as session:
#         async with session.begin():
#             permission = Permission(name="test_permission", description="A test permission")
#             session.add(permission)
#             await session.flush()
#             await session.refresh(permission)
#
#             role1 = Role(name="test_role_1", description="A test role 1")
#             role2 = Role(name="test_role_2", description="A test role 2")
#             session.add_all([role1, role2])
#             await session.flush()
#             await session.refresh(role1)
#             await session.refresh(role2)
#
#             role_permission1 = RolePermission(role_id=role1.role_pk, permission_id=permission.permission_pk)
#             role_permission2 = RolePermission(role_id=role2.role_pk, permission_id=permission.permission_pk)
#             session.add_all([role_permission1, role_permission2])
#             await session.flush()
#
#     # Act: Retrieve roles for the permission
#     response = await async_client.get(
#         f"/role_permissions/permission/{permission.permission_pk}/roles/",
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     # Assert: Check response status and data
#     assert response.status_code == status.HTTP_200_OK
#     response_data = response.json()
#     assert response_data["permission_id"] == permission.permission_pk
#     assert len(response_data["roles"]) == 2
#     assert any(r["role_id"] == role1.role_pk for r in response_data["roles"])
#     assert any(r["role_id"] == role2.role_pk for r in response_data["roles"])
#
#
# @pytest.mark.asyncio
# async def test_read_roles_for_permission_not_found(
#     async_client: AsyncClient,
#     admin_token: str
# ):
#     # Act: Try to retrieve roles for a non-existent permission
#     response = await async_client.get(
#         "/role_permissions/permission/9999/roles/",  # Assuming 9999 is a non-existent permission_pk
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     # Assert: Should return 404 Not Found
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json()["detail"] == "Permission with pk 9999 not found."
#
#
# @pytest.mark.asyncio
# async def test_read_roles_for_permission_unauthorized(
#     async_client: AsyncClient,
#     non_admin_token: str
# ):
#     # Setup: Create a permission and assign roles
#     async with async_session_maker() as session:
#         async with session.begin():
#             permission = Permission(name="test_permission_unauth", description="A test permission for unauthorized test")
#             session.add(permission)
#             await session.flush()
#             await session.refresh(permission)
#
#             role = Role(name="test_role_unauth", description="A test role for unauthorized test")
#             session.add(role)
#             await session.flush()
#             await session.refresh(role)
#
#             role_permission = RolePermission(role_id=role.role_pk, permission_id=permission.permission_pk)
#             session.add(role_permission)
#             await session.flush()
#
#     # Act: Try to retrieve roles with a non-admin token
#     response = await async_client.get(
#         f"/role_permissions/permission/{permission.permission_pk}/roles/",
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     # Assert: Should return 403 Forbidden
#     assert response.status_code == status.HTTP_403_FORBIDDEN
