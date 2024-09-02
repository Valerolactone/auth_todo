from fastapi import status
from db.models import Permission
from tests.conftest import *


@pytest.fixture()
async def permission(async_session: AsyncSession):
    async with async_session.begin():
        permission = Permission(name="read", description="Read permission")
        async_session.add(permission)
        await async_session.flush()
        await async_session.refresh(permission)
    return permission


async def test_read_permission_existing(async_client: AsyncClient, admin_token: str, permission):
    response = await async_client.get(f"/permissions/{permission.permission_pk}",
                                      headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == permission.name
    assert data["description"] == permission.description


async def test_read_permission_non_existent(async_client: AsyncClient, admin_token: str):
    non_existent_pk = 999999
    response = await async_client.get(f"/permissions/{non_existent_pk}",
                                      headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"Permission with pk {non_existent_pk} not found."}


async def test_read_permission_no_auth(async_client: AsyncClient, permission):
    response = await async_client.get(f"/permissions/{permission.permission_pk}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == permission.name
    assert data["description"] == permission.description
