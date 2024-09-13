import asyncio
import os
from typing import AsyncGenerator

import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from alembic import command
from alembic.config import Config
from db.models import Base, Permission, Role, User
from db.session import get_async_session
from main import app
from settings import settings

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALEMBIC_CONFIG_PATH = os.path.join(ROOT_DIR, 'alembic.ini')

TEST_DATABASE_URL = f"postgresql+asyncpg://{settings.db_user}:{settings.db_password}@{settings.db_host}:{settings.db_port}/{settings.test_db_name}"

async_test_engine = create_async_engine(TEST_DATABASE_URL, echo=True)

AsyncSessionLocal = sessionmaker(
    bind=async_test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest.fixture(scope='session', autouse=True)
def apply_migrations():
    alembic_cfg = Config(ALEMBIC_CONFIG_PATH)
    alembic_cfg.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)

    command.upgrade(alembic_cfg, "head")
    yield

    # command.downgrade(alembic_cfg, "base")


@pytest.fixture(scope='session')
def event_loop():
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope='function')
async def async_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
        await cleanup_tables(session)
    await session.close()


@pytest.fixture(scope='function')
async def async_client(
    async_session: AsyncSession,
) -> AsyncGenerator[AsyncSession, None]:
    async def override_get_db():
        yield async_session

    app.dependency_overrides[get_async_session] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
async def permission_for_test(async_session: AsyncSession) -> Permission:
    permission = Permission(name="test", description="Test permission")
    async_session.add(permission)
    await async_session.flush()
    await async_session.refresh(permission)
    return permission


@pytest.fixture
async def admin_role(async_session: AsyncSession) -> Role:
    admin_role = Role(name="admin", description="test admin")
    async_session.add(admin_role)
    await async_session.flush()
    await async_session.refresh(admin_role)
    return admin_role


@pytest.fixture
async def user_role(async_session: AsyncSession) -> Role:
    user_role = Role(name="user", description="test user")
    async_session.add(user_role)
    await async_session.flush()
    await async_session.refresh(user_role)
    return user_role


@pytest.fixture
async def role_for_test(async_session: AsyncSession) -> Role:
    role = Role(name="test", description="Test role")
    async_session.add(role)
    await async_session.flush()
    await async_session.refresh(role)
    return role


@pytest.fixture
async def admin_user(async_session: AsyncSession, admin_role: Role) -> User:
    admin = User(
        first_name="Admin",
        last_name="User",
        email="admin@example.com",
        password="adminpass",
        role_id=admin_role.role_pk,
    )
    async_session.add(admin)
    await async_session.flush()
    await async_session.refresh(admin)
    return admin


@pytest.fixture
async def not_admin_user(async_session: AsyncSession, user_role: Role) -> User:
    user = User(
        first_name="Regular",
        last_name="User",
        email="user@example.com",
        password="userpass",
        role_id=user_role.role_pk,
    )
    async_session.add(user)
    await async_session.flush()
    await async_session.refresh(user)
    return user


@pytest.fixture
async def user_for_test(async_session: AsyncSession, user_role: Role) -> User:
    user = User(
        first_name="John",
        last_name="Doe",
        email="test@gmail.com",
        password="123456",
        role_id=user_role.role_pk,
    )
    async_session.add(user)
    await async_session.flush()
    await async_session.refresh(user)
    return user


@pytest.fixture
async def admin_token(async_client: AsyncClient) -> str:
    request_data = {"username": "admin@example.com", "password": "adminpass"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = await async_client.post(
        "/login/token", data=request_data, headers=headers
    )
    token_data = response.json()

    assert response.status_code == status.HTTP_201_CREATED
    return token_data["access_token"]


@pytest.fixture
async def not_admin_token(async_client: AsyncClient) -> str:
    request_data = {"username": "user@example.com", "password": "userpass"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = await async_client.post(
        "/login/token", data=request_data, headers=headers
    )
    token_data = response.json()

    assert response.status_code == status.HTTP_201_CREATED
    return token_data["access_token"]


async def cleanup_tables(async_session: AsyncSession):
    for table in reversed(Base.metadata.sorted_tables):
        await async_session.execute(
            text(f'TRUNCATE "{table.name}" RESTART IDENTITY CASCADE;')
        )

    await async_session.commit()
