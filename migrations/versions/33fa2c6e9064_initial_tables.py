"""initial tables

Revision ID: 33fa2c6e9064
Revises: 
Create Date: 2026-03-11 06:10:57.585226

"""
from typing import Sequence, Union

from alembic import op

from app.db.base import Base


# revision identifiers, used by Alembic.
revision: str = '33fa2c6e9064'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
