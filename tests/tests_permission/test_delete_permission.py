# from fastapi import status
# from sqlalchemy import select
#
# from db.models import Permission
# from tests.conftest import *
#
#
# @pytest.fixture(scope="function")
# async def delete_permission(async_session: AsyncSession) -> Permission:
#     permission = Permission(name="Delete me", description="Delete me permission")
#     async_session.add(permission)
#     await async_session.flush()
#     await async_session.refresh(permission)
#     return permission
#
#
# async def test_delete_permission_existing(
#         async_session: AsyncSession,
#         async_client: AsyncClient,
#         admin_user: User,
#         admin_token: str,
#         delete_permission: Permission,
# ):
#     response = await async_client.delete(
#         f"/permissions/{delete_permission.permission_pk}",
#         headers={"Authorization": f"Bearer {admin_token}"},
#     )
#
#     result = await async_session.execute(
#         select(Permission).filter_by(permission_pk=delete_permission.permission_pk)
#     )
#
#     assert response.status_code == status.HTTP_204_NO_CONTENT
#     assert result.scalar() is None
#
#
# async def test_delete_permission_non_existent(
#         async_client: AsyncClient, admin_user: User, admin_token: str
# ):
#     non_existent_pk = 0
#     response = await async_client.delete(
#         f"/permissions/{non_existent_pk}",
#         headers={"Authorization": f"Bearer {admin_token}"},
#     )
#
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json() == {
#         "detail": f"Permission with pk {non_existent_pk} not found."
#     }
#
#
# async def test_delete_permission_no_auth(
#         async_client: AsyncClient, delete_permission: Permission
# ):
#     response = await async_client.delete(
#         f"/permissions/{delete_permission.permission_pk}"
#     )
#
#     assert response.status_code == status.HTTP_401_UNAUTHORIZED
#
#
# async def test_delete_permission_as_not_admin(
#         async_client: AsyncClient,
#         not_admin_user: User,
#         not_admin_token: str,
#         delete_permission: Permission,
# ):
#     response = await async_client.delete(
#         f"/permissions/{delete_permission.permission_pk}",
#         headers={"Authorization": f"Bearer {not_admin_token}"},
#     )
#
#     assert response.status_code == status.HTTP_403_FORBIDDEN
