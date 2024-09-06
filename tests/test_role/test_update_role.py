# from sqlalchemy import select
# from fastapi import status
# from tests.conftest import *
#
#
# @pytest.fixture(scope="function")
# async def update_role(async_session: AsyncSession) -> Role:
#     role = Role(name="Update me", description="Update me role")
#     async_session.add(role)
#     await async_session.flush()
#     await async_session.refresh(role)
#     return role
#
#
# async def test_update_role_existing(async_session: AsyncSession, async_client: AsyncClient, admin_user: User,
#                                     admin_token: str, update_role: Role):
#     update_data = {"name": "moderator_updated", "description": "Moderator role Updated"}
#     response = await async_client.put(
#         f"/roles/{update_role.role_pk}",
#         json=update_data,
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#     updated_role = response.json()
#
#     assert response.status_code == status.HTTP_200_OK
#     assert updated_role["name"] == "moderator_updated"
#     assert updated_role["description"] == "Moderator role Updated"
#
#     updated_role = await async_session.execute(
#         select(Role).filter_by(role_pk=update_role.role_pk)
#     )
#     result = updated_role.scalar_one()
#
#     assert result.name == update_data["name"]
#     assert result.description == update_data["description"]
#
#
# async def test_update_role_non_existent(async_client: AsyncClient, admin_user: User, admin_token: str):
#     non_existent_pk = 0
#     update_data = {"name": "non_existent", "description": "Non Existent role"}
#     response = await async_client.put(
#         f"/roles/{non_existent_pk}",
#         json=update_data,
#         headers={"Authorization": f"Bearer {admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json() == {"detail": f"Role with pk {non_existent_pk} not found."}
#
#
# async def test_update_role_no_auth(async_client: AsyncClient, update_role: Role):
#     update_data = {"name": "moderator_updated", "description": "Moderator role Updated"}
#     response = await async_client.put(
#         f"/roles/{update_role.role_pk}",
#         json=update_data
#     )
#
#     assert response.status_code == status.HTTP_401_UNAUTHORIZED
#
#
# async def test_update_role_as_non_admin(async_client: AsyncClient, non_admin_user: User, non_admin_token: str,
#                                         update_role: Role):
#     update_data = {"name": "moderator_updated", "description": "Moderator role Updated"}
#     response = await async_client.put(
#         f"/roles/{update_role.role_pk}",
#         json=update_data,
#         headers={"Authorization": f"Bearer {non_admin_token}"}
#     )
#
#     assert response.status_code == status.HTTP_403_FORBIDDEN
