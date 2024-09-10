from sqlalchemy import select

from tests.conftest import *


async def test_create_role_as_admin(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
):
    role_data = {"name": "moderator", "description": "Moderator role description"}

    response = await async_client.post(
        "/roles/", json=role_data, headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == status.HTTP_201_CREATED
    response_data = response.json()

    assert response_data["name"] == role_data["name"]
    assert response_data["description"] == role_data["description"]

    role = await async_session.execute(select(Role).filter_by(name=role_data["name"]))

    assert role.scalar() is not None


async def test_create_role_as_not_admin(
    async_client: AsyncClient, not_admin_user: User, not_admin_token: str
):
    role_data = {"name": "guest", "description": "Guest role description"}

    response = await async_client.post(
        "/roles/",
        json=role_data,
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_create_role_unauthorized(async_client: AsyncClient):
    role_data = {"name": "guest", "description": "Guest role description"}

    response = await async_client.post("/roles/", json=role_data)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
