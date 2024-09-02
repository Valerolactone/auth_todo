import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Generator
import jwt
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from db.models import Base, Role, User
from db.session import get_async_session
from main import app

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default_secret_key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

TEST_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@127.0.0.1:5434/test_auth_db"
test_engine = create_async_engine(TEST_DATABASE_URL)
async_session_maker = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


async def override_get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


app.dependency_overrides[get_async_session] = override_get_async_session


@pytest.fixture(scope="session")
def event_loop(request) -> Generator:
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


@pytest.fixture()
async def async_session() -> AsyncSession:
    async with async_session_maker() as session:
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await test_engine.dispose()


@pytest.fixture()
async def admin_role(async_session: AsyncSession) -> Role:
    async with async_session.begin():
        admin_role = Role(name="admin", description="test admin")
        async_session.add(admin_role)
        await async_session.flush()
        await async_session.refresh(admin_role)
    return admin_role


@pytest.fixture()
async def user_role(async_session: AsyncSession) -> Role:
    async with async_session.begin():
        user_role = Role(name="user", description="test user")
        async_session.add(user_role)
        await async_session.flush()
        await async_session.refresh(user_role)
    return user_role


@pytest.fixture()
async def admin_user(async_session: AsyncSession, admin_role) -> User:
    async with async_session.begin():
        admin = User(
            first_name="Admin",
            last_name="User",
            email="admin@example.com",
            password="adminpass",
            role_id=admin_role.role_pk
        )
        async_session.add(admin)
        await async_session.flush()
        await async_session.refresh(admin)
    return admin


@pytest.fixture()
async def non_admin_user(async_session: AsyncSession, user_role) -> User:
    async with async_session.begin():
        user = User(
            first_name="Regular",
            last_name="User",
            email="user@example.com",
            password="userpass",
            role_id=user_role.role_pk
        )
        async_session.add(user)
        await async_session.flush()
        await async_session.refresh(user)
    return user


@pytest.fixture()
async def admin_token(admin_user: User) -> str:
    payload = {
        "user_pk": admin_user.user_pk,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


@pytest.fixture()
async def non_admin_token(non_admin_user: User) -> str:
    payload = {
        "user_pk": non_admin_user.user_pk,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token
