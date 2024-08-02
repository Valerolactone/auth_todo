from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    sql,
)

from app.models.roles import roles

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("user_pk", Integer, primary_key=True),
    Column("email", String(50), unique=True, nullable=False, index=True),
    Column("first_name", String(50)),
    Column("last_name", String(50)),
    Column("hashed_password", String(), nullable=False),
    Column("created_at", DateTime, default=0),
    Column("deleted_at", DateTime, default=0),
    Column(
        "is_active",
        Boolean(),
        server_default=sql.expression.true(),
        nullable=False,
    ),
    Column("role", ForeignKey(roles.c.role_pk)),
)
