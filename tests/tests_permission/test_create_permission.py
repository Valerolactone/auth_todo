from fastapi import status
from sqlalchemy import select

from db.models import Permission
from tests.conftest import *


async def test_create_permission_as_admin(async_session: AsyncSession, async_client: AsyncClient, admin_user: User,
                                          admin_token: str):
    permission_data = {"name": "Test permission", "description": "Test Permission"}
    response = await async_client.post("/permissions/", json=permission_data,
                                       headers={"Authorization": f"Bearer {admin_token}"})
    created_permission = response.json()

    assert response.status_code == status.HTTP_201_CREATED
    assert created_permission["name"] == permission_data["name"]
    assert created_permission["description"] == permission_data["description"]

    permission = await async_session.execute(
        select(Permission).filter_by(name=permission_data["name"])
    )

    assert permission.scalar() is not None


async def test_create_permission_as_non_admin(async_session: AsyncSession, async_client: AsyncClient,
                                              not_admin_user: User, not_admin_token: str):
    permission_data = {"name": "test_permission", "description": "Test Permission"}
    response = await async_client.post("/permissions/", json=permission_data,
                                       headers={"Authorization": f"Bearer {not_admin_token}"})

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_create_permission_no_auth(async_session: AsyncSession, async_client: AsyncClient):
    permission_data = {"name": "test_permission", "description": "Test Permission"}
    response = await async_client.post("/permissions/", json=permission_data)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
