from tests.conftest import *


async def test_read_users(
    async_client: AsyncClient,
    user_for_test: User,
    not_admin_user: User,
    admin_user: User,
    not_admin_token: str,
):
    response = await async_client.get(
        "/users/", headers={"Authorization": f"Bearer {not_admin_token}"}
    )
    response_data = response.json()

    assert response.status_code == status.HTTP_200_OK
    users = response_data["users"]
    assert "created_at" not in users[0]


async def test_read_users_pagination(
    async_client: AsyncClient, not_admin_user: User, admin_user: User
):
    response = await async_client.get("/users/?page=2&page_size=1")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "users" in data
    assert isinstance(data["users"], list)
    assert len(data["users"]) == 1
    assert "total" in data
    assert data["total"] >= 2


async def test_read_users_sort_by_email_desc(
    async_client: AsyncClient, not_admin_user: User, admin_user: User
):
    response = await async_client.get("/users/?sortBy=email&sortOrder=desc")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "users" in data
    assert isinstance(data["users"], list)
    emails = [user["email"] for user in data["users"]]
    assert emails == sorted(emails, reverse=True)


async def test_read_users_filter_by_role(
    async_client: AsyncClient,
    user_for_test: User,
    not_admin_user: User,
    admin_user: User,
    user_role: Role,
):
    response = await async_client.get(
        f"/users/?filterBy=role&filterValue={user_role.name}"
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert "users" in data
    assert any(user["role"] == user_role.name for user in data["users"])
    for user in data["users"]:
        assert user["role"] == user_role.name


async def test_read_users_invalid_sort_order(
    async_client: AsyncClient, not_admin_user: User, admin_user: User
):
    response = await async_client.get("/users/?sortOrder=invalid")

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_read_users_unauthorized(async_client: AsyncClient):
    response = await async_client.get("/users/")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data["users"], list)
