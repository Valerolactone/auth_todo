# from fastapi import status
# from sqlalchemy import select, and_
#
# from db.models import Permission, RolePermission
# from tests.conftest import *
#
#
# @pytest.fixture(scope="module")
# async def role():
#     async with async_session_maker() as session:
#         async with session.begin():
#             role = Role(name="moderator", description="Moderator role")
#             session.add(role)
#             await session.flush()
#             await session.refresh(role)
#             return role
#
#
# @pytest.fixture(scope="module")
# async def permission():
#     async with async_session_maker() as session:
#         async with session.begin():
#             permission = Permission(name="read", description="Read permission")
#             session.add(permission)
#             await session.flush()
#             await session.refresh(permission)
#             return permission
#
#
# async def test_assign_permission_to_role_as_admin(
#         async_client: AsyncClient,
#         admin_token: str,
#         role, permission):
#     response = await async_client.post(
#         "/role_permissions/",
#         json={"role": role.name, "permission": permission.name},
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_201_CREATED
#     response_data = response.json()
#     assert response_data["role_pk"] == role.role_pk
#     assert response_data["permission_pk"] == permission.permission_pk
#     assert response_data["role"] == role.name
#     assert response_data["permission"] == permission.name
#
#     async with async_session_maker() as session:
#         role_permission = await session.execute(
#             select(RolePermission).filter_by(and_(role_pk=role.role_pk, permission_pk=permission.permission_pk)))
#         assert role_permission is not None
#
#
# async def test_assign_permission_to_role_as_non_admin(
#         async_client: AsyncClient,
#         non_admin_token: str,
#         role, permission):
#     response = await async_client.post(
#         "/role_permissions/",
#         json={"role": role.name, "permission": permission.name},
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_403_FORBIDDEN
#
#
# async def test_assign_permission_to_role_unauthorized(
#         async_client: AsyncClient,
#         non_admin_token: str,
#         role, permission):
#     response = await async_client.post(
#         "/role_permissions/",
#         json={"role": role.name, "permission": permission.name},
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_403_FORBIDDEN
#
#
# async def test_assign_permission_to_role_invalid_data(
#         async_client: AsyncClient,
#         admin_token: str
# ):
#     invalid_role_permission_data = {
#         "role": "admin",
#     }
#
#     response = await async_client.post(
#         "/role_permissions/",
#         json=invalid_role_permission_data,
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_400_BAD_REQUEST
