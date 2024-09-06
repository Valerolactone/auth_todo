# from fastapi import status
#
# from db.models import Permission, RolePermission
# from tests.conftest import *
#
#
# @pytest.fixture(scope="module")
# async def assign_permissions_to_role():
#     async with async_session_maker() as session:
#         async with session.begin():
#             role = Role(name="test_role", description="A test role")
#             session.add(role)
#             await session.flush()
#             await session.refresh(role)
#
#             permission1 = Permission(name="test_permission_1", description="A test permission 1")
#             permission2 = Permission(name="test_permission_2", description="A test permission 2")
#             session.add_all([permission1, permission2])
#             await session.flush()
#             await session.refresh(permission1)
#             await session.refresh(permission2)
#
#             role_permission1 = RolePermission(role_pk=role.role_pk, permission_pk=permission1.permission_pk)
#             role_permission2 = RolePermission(role_pk=role.role_pk, permission_pk=permission2.permission_pk)
#             session.add_all([role_permission1, role_permission2])
#             await session.flush()
#
#             return {"role": role, "permission1": permission1, "permission2": permission2}
#
#
# async def test_read_permissions_for_role_success(
#         async_client: AsyncClient,
#         admin_token: str,
#         assign_permissions_to_role):
#     response = await async_client.get(
#         f"/role_permissions/role/{assign_permissions_to_role.get("role").role_pk}/permissions/",
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_200_OK
#     response_data = response.json()
#     assert response_data["role_pk"] == assign_permissions_to_role.get("role").role_pk
#     assert len(response_data["permissions"]) == 2
#     assert any(p["permission_pk"] == assign_permissions_to_role.get("permission1").permission_pk for p in
#                response_data["permissions"])
#     assert any(p["permission_pk"] == assign_permissions_to_role.get("permission2").permission_pk for p in
#                response_data["permissions"])
#
#
# async def test_read_permissions_for_role_non_existent(
#         async_client: AsyncClient,
#         admin_token: str
# ):
#     nonexistent_role_pk = 9999
#     response = await async_client.get(
#         f"/role_permissions/role/{nonexistent_role_pk}/permissions/",
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json()["detail"] == f"Role with pk {nonexistent_role_pk} not found."
#
#
# async def test_read_permissions_for_role_unauthorized(
#         async_client: AsyncClient,
#         non_admin_token: str,
#         assign_permissions_to_role):
#     response = await async_client.get(
#         f"/role_permissions/role/{assign_permissions_to_role.get("role").role_pk}/permissions/",
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_403_FORBIDDEN
