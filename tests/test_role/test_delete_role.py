from sqlalchemy import select

from tests.conftest import *


async def test_delete_role_existing(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    role_for_test: Role,
) -> None:
    response = await async_client.delete(
        f"/roles/{role_for_test.role_pk}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    deleted_role = await async_session.execute(
        select(Role).filter_by(role_pk=role_for_test.role_pk)
    )
    assert deleted_role.scalar() is None


async def test_delete_role_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    response = await async_client.delete(
        f"/roles/{not_existent_pk}", headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"Role with pk {not_existent_pk} not found."}


async def test_delete_role_unauthorized(
    async_client: AsyncClient, role_for_test: Role
) -> None:
    response = await async_client.delete(f"/roles/{role_for_test.role_pk}")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_delete_role_as_not_admin(
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    role_for_test: Role,
) -> None:
    response = await async_client.delete(
        f"/roles/{role_for_test.role_pk}",
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
