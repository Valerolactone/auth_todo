# from sqlalchemy import select
# from fastapi import status
# from tests.conftest import *
#
#
# @pytest.fixture(scope="function")
# async def delete_role(async_session: AsyncSession) -> Role:
#     role = Role(name="Delete me", description="Delete me role")
#     async_session.add(role)
#     await async_session.flush()
#     await async_session.refresh(role)
#     return role
#
#
# async def test_delete_role_existing(async_session: AsyncSession, async_client: AsyncClient, admin_user: User,
#                                     admin_token: str, delete_role: Role) -> None:
#     response = await async_client.delete(
#         f"/roles/{delete_role.role_pk}",
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_204_NO_CONTENT
#
#     deleted_role = await async_session.execute(
#         select(Role).filter_by(role_pk=delete_role.role_pk)
#     )
#     assert deleted_role.scalar() is None
#
#
# async def test_delete_role_non_existent(async_client: AsyncClient, admin_user: User, admin_token: str):
#     non_existent_pk = 0
#     response = await async_client.delete(
#         f"/roles/{non_existent_pk}",
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json() == {"detail": f"Role with pk {non_existent_pk} not found."}
#
#
# async def test_delete_role_no_auth(async_client: AsyncClient, delete_role: Role) -> None:
#     response = await async_client.delete(
#         f"/roles/{delete_role.role_pk}"
#     )
#
#     assert response.status_code == status.HTTP_401_UNAUTHORIZED
#
#
# async def test_delete_role_as_non_admin(async_client: AsyncClient, non_admin_user: User, non_admin_token: str,
#                                         delete_role: Role) -> None:
#     response = await async_client.delete(
#         f"/roles/{delete_role.role_pk}",
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_403_FORBIDDEN
