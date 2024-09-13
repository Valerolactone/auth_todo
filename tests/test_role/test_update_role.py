from sqlalchemy import select

from tests.conftest import *


async def test_update_role_existing(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    role_for_test: Role,
):
    update_data = {"name": "moderator_updated", "description": "Moderator role Updated"}
    response = await async_client.put(
        f"/roles/{role_for_test.role_pk}",
        json=update_data,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    updated_role = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert updated_role["name"] == "moderator_updated"
    assert updated_role["description"] == "Moderator role Updated"

    updated_role = await async_session.execute(
        select(Role).filter_by(role_pk=role_for_test.role_pk)
    )
    result = updated_role.scalar_one()

    assert result.name == update_data["name"]
    assert result.description == update_data["description"]


async def test_update_role_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    update_data = {"name": "not_existent", "description": "Non Existent role"}
    response = await async_client.put(
        f"/roles/{not_existent_pk}",
        json=update_data,
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"Role with pk {not_existent_pk} not found."}


async def test_update_role_unauthorized(async_client: AsyncClient, role_for_test: Role):
    update_data = {"name": "moderator_updated", "description": "Moderator role Updated"}
    response = await async_client.put(
        f"/roles/{role_for_test.role_pk}", json=update_data
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_update_role_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    role_for_test: Role,
):
    update_data = {"name": "moderator_updated", "description": "Moderator role Updated"}
    response = await async_client.put(
        f"/roles/{role_for_test.role_pk}",
        json=update_data,
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
