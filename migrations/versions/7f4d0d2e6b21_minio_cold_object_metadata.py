"""add MinIO cold object metadata

Revision ID: 7f4d0d2e6b21
Revises: 33fa2c6e9064
Create Date: 2026-03-22 18:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7f4d0d2e6b21"
down_revision: Union[str, None] = "33fa2c6e9064"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("cold_stored_blocks", sa.Column("object_bucket", sa.String(), nullable=True))
    op.add_column("cold_stored_blocks", sa.Column("object_key", sa.String(), nullable=True))
    op.add_column("cold_stored_blocks", sa.Column("object_version_id", sa.String(), nullable=True))
    op.add_column("cold_stored_blocks", sa.Column("object_etag", sa.String(), nullable=True))
    op.add_column("cold_stored_blocks", sa.Column("object_sha256_hex", sa.String(), nullable=True))
    op.add_column("cold_stored_blocks", sa.Column("object_size_bytes", sa.BigInteger(), nullable=True))
    op.add_column("cold_stored_blocks", sa.Column("object_retention_mode", sa.String(), nullable=True))
    op.add_column("cold_stored_blocks", sa.Column("object_retention_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "cold_stored_blocks",
        sa.Column("object_legal_hold", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_index(
        "ix_cold_stored_blocks_object_key",
        "cold_stored_blocks",
        ["object_key"],
        unique=False,
    )
    op.create_index(
        "ix_cold_stored_blocks_object_sha256_hex",
        "cold_stored_blocks",
        ["object_sha256_hex"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_cold_stored_blocks_object_sha256_hex", table_name="cold_stored_blocks")
    op.drop_index("ix_cold_stored_blocks_object_key", table_name="cold_stored_blocks")
    op.drop_column("cold_stored_blocks", "object_legal_hold")
    op.drop_column("cold_stored_blocks", "object_retention_until")
    op.drop_column("cold_stored_blocks", "object_retention_mode")
    op.drop_column("cold_stored_blocks", "object_size_bytes")
    op.drop_column("cold_stored_blocks", "object_sha256_hex")
    op.drop_column("cold_stored_blocks", "object_etag")
    op.drop_column("cold_stored_blocks", "object_version_id")
    op.drop_column("cold_stored_blocks", "object_key")
    op.drop_column("cold_stored_blocks", "object_bucket")
