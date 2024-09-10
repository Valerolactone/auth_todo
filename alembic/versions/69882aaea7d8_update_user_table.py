"""Update user table

Revision ID: 69882aaea7d8
Revises: 315dcd420a4f
Create Date: 2024-08-07 17:55:37.399200

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '69882aaea7d8'
down_revision: Union[str, None] = '315dcd420a4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('_password', sa.String(), nullable=False))
    op.drop_column('users', 'hashed_password')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(
        'users',
        sa.Column('hashed_password', sa.VARCHAR(), autoincrement=False, nullable=False),
    )
    op.drop_column('users', '_password')
    # ### end Alembic commands ###
