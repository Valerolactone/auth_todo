from passlib.context import CryptContext
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import declarative_base, relationship

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    user_pk = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    _password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    role_id = Column(Integer, ForeignKey('roles.role_pk'), nullable=True)

    role = relationship('Role', back_populates='users')

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, raw_password: str):
        self._password = pwd_context.hash(raw_password)

    def verify_password(self, raw_password: str) -> bool:
        return pwd_context.verify(raw_password, self._password)


class Role(Base):
    __tablename__ = 'roles'

    role_pk = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=False)

    users = relationship('User', back_populates='role')


class Permission(Base):
    __tablename__ = 'permissions'

    permission_pk = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=False)


class RolePermission(Base):
    __tablename__ = 'role_permissions'

    role_permission_pk = Column(Integer, primary_key=True, autoincrement=True)
    role_pk = Column(Integer, ForeignKey('roles.role_pk'))
    permission_pk = Column(Integer, ForeignKey('permissions.permission_pk'))
