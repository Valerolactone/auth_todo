import asyncio
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from db.models import Base, Role, User
from db.session import get_async_session
from main import app

TEST_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@127.0.0.1:5434/test_auth_db"
test_engine = create_async_engine(TEST_DATABASE_URL, echo=True)


# async_session_maker = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(scope='session')
async def async_db_engine():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield test_engine

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# @pytest.fixture(scope="session", autouse=True)
# async def setup_test_db() -> AsyncGenerator:
#     async with test_engine.begin() as conn:
#         await conn.run_sync(Base.metadata.create_all)
#
#     yield
#
#     async with test_engine.begin() as conn:
#         await conn.run_sync(Base.metadata.drop_all)
#     await test_engine.dispose()
#
@pytest.fixture(scope='function')
async def async_db(async_db_engine):
    async_session = sessionmaker(
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
        bind=async_db_engine,
        class_=AsyncSession,
    )

    async with async_session() as session:
        try:
            yield session
        finally:
            await session.rollback()
            async with session.begin():
                for table in reversed(Base.metadata.sorted_tables):
                    await session.execute(table.delete())


# @pytest.fixture(scope="function")
# async def override_get_async_session() -> AsyncGenerator[AsyncSession, None]:
#     async def _override_get_async_session():
#         async with async_session_maker() as session:
#             try:
#                 yield session
#             finally:
#                 await session.rollback()
#                 async with session.begin():
#                     for table in reversed(Base.metadata.sorted_tables):
#                         await session.execute(table.delete())
#
#     app.dependency_overrides[get_async_session] = _override_get_async_session
#     yield
#     app.dependency_overrides[get_async_session] = None
@pytest.fixture(scope="session")
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture(scope='session')
def event_loop():
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture()
async def admin_role(async_db: AsyncSession) -> Role:
    admin_role = Role(name="admin", description="test admin")
    async_db.add(admin_role)
    await async_db.flush()
    await async_db.refresh(admin_role)
    return admin_role


@pytest.fixture()
async def user_role(async_db: AsyncSession) -> Role:
    user_role = Role(name="user", description="test user")
    async_db.add(user_role)
    await async_db.flush()
    await async_db.refresh(user_role)
    return user_role


@pytest.fixture()
async def admin_user(async_db: AsyncSession, admin_role: Role) -> User:
    admin = User(
        first_name="Admin",
        last_name="User",
        email="admin@example.com",
        password="adminpass",
        role_id=admin_role.role_pk,
    )
    async_db.add(admin)
    await async_db.flush()
    await async_db.refresh(admin)
    return admin


@pytest.fixture()
async def non_admin_user(async_db: AsyncSession, user_role: Role) -> User:
    user = User(
        first_name="Regular",
        last_name="User",
        email="user@example.com",
        password="userpass",
        role_id=user_role.role_pk,
    )
    async_db.add(user)
    await async_db.flush()
    await async_db.refresh(user)
    return user


@pytest.fixture()
async def admin_token(async_client: AsyncClient) -> str:
    request_data = {"username": "admin@example.com", "password": "adminpass"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = await async_client.post(
        "/login/token", data=request_data, headers=headers
    )
    token_data = response.json()
    return token_data["access_token"]


@pytest.fixture()
async def non_admin_token(async_client: AsyncClient) -> str:
    request_data = {"username": "user@example.com", "password": "userpass"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = await async_client.post(
        "/login/token", data=request_data, headers=headers
    )
    token_data = response.json()
    return token_data["access_token"]
