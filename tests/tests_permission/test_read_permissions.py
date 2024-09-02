from fastapi import status
from db.models import Permission
from tests.conftest import *


@pytest.fixture()
async def add_permissions(async_session: AsyncSession):
    async with async_session.begin():
        permissions = [
            Permission(name="read", description="Read Permission"),
            Permission(name="write", description="Write Permission")
        ]
        async_session.add_all(permissions)
        await async_session.flush()


async def test_read_permissions_with_permissions(async_client: AsyncClient, admin_token: str, add_permissions):
    response = await async_client.get("/permissions/", headers={"Authorization": f"Bearer {admin_token}"})
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert len(data) == 2
    assert any(permission['name'] == "read" for permission in data)
    assert any(permission['name'] == "write" for permission in data)


async def test_read_permissions_no_auth(async_client: AsyncClient, add_permissions):
    response = await async_client.get("/permissions/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
