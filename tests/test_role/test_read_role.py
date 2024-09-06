# from fastapi import status
# from tests.conftest import *
#
#
# @pytest.fixture()
# async def role(async_session: AsyncSession) -> Role:
#     role = Role(name="moderator", description="Moderator role")
#     async_session.add(role)
#     await async_session.flush()
#     await async_session.refresh(role)
#     return role
#
#
# async def test_read_role_existing(async_client: AsyncClient, admin_user: User, admin_token: str, role: Role):
#     response = await async_client.get(f"/roles/{role.role_pk}",
#                                       headers={"Authorization": f"Bearer {admin_token}"})
#     data = response.json()
#
#     assert response.status_code == status.HTTP_200_OK
#     assert data["name"] == role.name
#     assert data["description"] == role.description
#
#
# async def test_read_role_non_existent(async_client: AsyncClient, admin_user: User, admin_token: str):
#     non_existent_pk = 0
#     response = await async_client.get(f"/roles/{non_existent_pk}",
#                                       headers={"Authorization": f"Bearer {admin_token}"})
#
#     assert response.status_code == status.HTTP_404_NOT_FOUND
#     assert response.json() == {"detail": f"Role with pk {non_existent_pk} not found."}
#
#
# async def test_read_role_no_auth(async_client: AsyncClient, role):
#     response = await async_client.get(f"/roles/{role.role_pk}")
#     data = response.json()
#
#     assert response.status_code == status.HTTP_200_OK
#     assert data["name"] == role.name
#     assert data["description"] == role.description
