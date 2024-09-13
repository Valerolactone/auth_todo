from tests.conftest import *


async def test_admin_read_users(
    async_client: AsyncClient,
    user_for_test: User,
    not_admin_user: User,
    admin_user: User,
    admin_token: str,
):
    response = await async_client.get(
        "/admin/", headers={"Authorization": f"Bearer {admin_token}"}
    )
    response_data = response.json()

    assert response.status_code == status.HTTP_200_OK
    users = response_data["users"]
    assert "created_at" in users[0]


async def test_admin_read_users_pagination(
    async_client: AsyncClient, not_admin_user: User, admin_user: User, admin_token: str
):
    response = await async_client.get(
        "/admin/?page=2&page_size=1", headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "users" in data
    assert isinstance(data["users"], list)
    assert len(data["users"]) == 1
    assert "total" in data
    assert data["total"] >= 2


async def test_admin_read_users_sort_by_email_desc(
    async_client: AsyncClient, not_admin_user: User, admin_user: User, admin_token: str
):
    response = await async_client.get(
        "/admin/?sortBy=email&sortOrder=desc",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "users" in data
    assert isinstance(data["users"], list)
    emails = [user["email"] for user in data["users"]]
    assert emails == sorted(emails, reverse=True)


async def test_admin_read_users_filter_by_role(
    async_client: AsyncClient,
    user_for_test: User,
    not_admin_user: User,
    admin_user: User,
    admin_token: str,
    user_role: Role,
):
    response = await async_client.get(
        f"/admin/?filterBy=role&filterValue={user_role.name}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert "users" in data
    assert any(user["role"] == user_role.name for user in data["users"])


async def test_admin_read_users_invalid_sort_order(
    async_client: AsyncClient, not_admin_user: User, admin_user: User, admin_token: str
):
    response = await async_client.get(
        "/admin/?sortOrder=invalid", headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_admin_read_users_unauthorized(async_client: AsyncClient):
    response = await async_client.get("/admin/")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Not authenticated"


async def test_admin_read_users_as_not_admin(
    async_client: AsyncClient, not_admin_user: User, not_admin_token: str
):
    response = await async_client.get(
        "/admin/", headers={"Authorization": f"Bearer {not_admin_token}"}
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
