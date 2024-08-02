from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
)

metadata = MetaData()

roles = Table(
    "roles",
    metadata,
    Column("role_pk", Integer, primary_key=True),
    Column("name", String(50), unique=True, nullable=False),
    Column("description", Text, nullable=False),
)

permissions = Table(
    "permissions",
    metadata,
    Column("permission_pk", Integer, primary_key=True),
    Column("name", String(50), unique=True, nullable=False),
    Column("description", Text, nullable=False),
)

role_permissions = Table(
    "role_permissions",
    metadata,
    Column("role", Integer, ForeignKey("roles.role_pk")),
    Column("permission", Integer, ForeignKey("permissions.permission_pk")),
    PrimaryKeyConstraint("role", "permission"),
)
