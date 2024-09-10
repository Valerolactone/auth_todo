from sqlalchemy import select

from tests.conftest import *


async def test_delete_permission_existing(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    permission_for_test: Permission,
):
    response = await async_client.delete(
        f"/permissions/{permission_for_test.permission_pk}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    result = await async_session.execute(
        select(Permission).filter_by(permission_pk=permission_for_test.permission_pk)
    )

    assert result.scalar() is None


async def test_delete_permission_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    response = await async_client.delete(
        f"/permissions/{not_existent_pk}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": f"Permission with pk {not_existent_pk} not found."
    }


async def test_delete_permission_unauthorized(
    async_client: AsyncClient, permission_for_test: Permission
):
    response = await async_client.delete(
        f"/permissions/{permission_for_test.permission_pk}"
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_delete_permission_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    permission_for_test: Permission,
):
    response = await async_client.delete(
        f"/permissions/{permission_for_test.permission_pk}",
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
