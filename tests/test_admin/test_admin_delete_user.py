from sqlalchemy import select

from tests.conftest import *


async def test_admin_delete_user(
    async_session: AsyncSession,
    async_client: AsyncClient,
    admin_user: User,
    admin_token: str,
    user_for_test: User,
) -> None:
    response = await async_client.delete(
        f'/admin/{user_for_test.user_pk}',
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    deleted_user = await async_session.execute(
        select(User).filter_by(user_pk=user_for_test.user_pk)
    )
    result = deleted_user.scalar_one()

    assert result.is_active == False
    assert result.deleted_at is not None


async def test_delete_user_not_existent(
    async_client: AsyncClient, admin_user: User, admin_token: str
):
    not_existent_pk = 0
    response = await async_client.delete(
        f"/admin/{not_existent_pk}", headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": f"User with pk {not_existent_pk} not found."}


async def test_admin_delete_user_as_not_admin(
    async_session: AsyncSession,
    async_client: AsyncClient,
    not_admin_user: User,
    not_admin_token: str,
    user_for_test: User,
) -> None:
    response = await async_client.delete(
        f'/admin/{user_for_test.user_pk}',
        headers={"Authorization": f"Bearer {not_admin_token}"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_admin_delete_user_unauthorized(
    async_session: AsyncSession, async_client: AsyncClient, user_for_test: User
) -> None:
    response = await async_client.delete(f'/admin/{user_for_test.user_pk}')

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
