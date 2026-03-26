"""initial_schema

Revision ID: b2c3d4e5f6a7
Revises: 5a4a9f8d935c
Create Date: 2026-03-27 12:46:28.637235

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "5a4a9f8d935c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("forensic_hypotheses", sa.Column("trust_weight", sa.Float(), nullable=True))
    op.add_column("forensic_hypotheses", sa.Column("pattern_severity", sa.Float(), nullable=True))
    op.add_column(
        "forensic_hypotheses",
        sa.Column("rule_trace", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("forensic_hypotheses", sa.Column("fusion_policy_hash", sa.String(length=64), nullable=True))
    op.add_column("forensic_hypotheses", sa.Column("title", sa.String(length=512), nullable=True))
    op.add_column("forensic_hypotheses", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("forensic_hypotheses", sa.Column("hypothesis_uid", sa.String(length=64), nullable=True))
    op.add_column(
        "forensic_hypotheses",
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("forensic_hypotheses", sa.Column("event_trust_tier", sa.String(length=32), nullable=True))
    op.add_column("forensic_hypotheses", sa.Column("event_action", sa.String(length=255), nullable=True))
    op.add_column(
        "forensic_hypotheses",
        sa.Column("event_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("forensic_hypotheses", sa.Column("mitre_technique_id", sa.String(length=20), nullable=True))
    op.add_column("forensic_hypotheses", sa.Column("mitre_technique_name", sa.String(length=200), nullable=True))
    op.add_column("forensic_hypotheses", sa.Column("mitre_tactic", sa.String(length=100), nullable=True))
    op.create_index(
        op.f("ix_forensic_hypotheses_hypothesis_uid"),
        "forensic_hypotheses",
        ["hypothesis_uid"],
        unique=False,
    )

    op.add_column("hypothesis_evidence_map", sa.Column("event_fingerprint", sa.String(), nullable=True))
    op.create_index(
        op.f("ix_hypothesis_evidence_map_event_fingerprint"),
        "hypothesis_evidence_map",
        ["event_fingerprint"],
        unique=False,
    )

    op.add_column(
        "investigator_decisions",
        sa.Column(
            "evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
    )
    op.add_column("investigator_decisions", sa.Column("ai_citation", sa.Text(), nullable=True))

    op.create_table(
        "cold_stored_blocks",
        sa.Column("block_id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.UUID(), nullable=False),
        sa.Column("events", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("leaf_hashes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("merkle_root_hex", sa.String(), nullable=False),
        sa.Column("chain_hash_hex", sa.String(), nullable=False),
        sa.Column("timestamp_proof", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["block_id"], ["sealed_blocks.id"]),
        sa.ForeignKeyConstraint(["source_id"], ["log_sources.id"]),
        sa.PrimaryKeyConstraint("block_id"),
    )
    op.create_index(op.f("ix_cold_stored_blocks_source_id"), "cold_stored_blocks", ["source_id"], unique=False)
    op.create_index(
        op.f("ix_cold_stored_blocks_merkle_root_hex"),
        "cold_stored_blocks",
        ["merkle_root_hex"],
        unique=False,
    )
    op.create_index(
        op.f("ix_cold_stored_blocks_chain_hash_hex"),
        "cold_stored_blocks",
        ["chain_hash_hex"],
        unique=False,
    )

    op.create_table(
        "log_events",
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.UUID(), nullable=True),
        sa.Column("event_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["log_sources.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("event_id"),
    )

    op.create_table(
        "model_snapshots",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("model_type", sa.String(), nullable=False),
        sa.Column("events_seen", sa.BigInteger(), nullable=False),
        sa.Column("is_calibrating", sa.Boolean(), nullable=False),
        sa.Column("checkpoint_path", sa.String(), nullable=True),
        sa.Column("config_hash", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("model_snapshots")
    op.drop_table("log_events")
    op.drop_index(op.f("ix_cold_stored_blocks_chain_hash_hex"), table_name="cold_stored_blocks")
    op.drop_index(op.f("ix_cold_stored_blocks_merkle_root_hex"), table_name="cold_stored_blocks")
    op.drop_index(op.f("ix_cold_stored_blocks_source_id"), table_name="cold_stored_blocks")
    op.drop_table("cold_stored_blocks")

    op.drop_column("investigator_decisions", "ai_citation")
    op.drop_column("investigator_decisions", "evidence_ids")

    op.drop_index(op.f("ix_hypothesis_evidence_map_event_fingerprint"), table_name="hypothesis_evidence_map")
    op.drop_column("hypothesis_evidence_map", "event_fingerprint")

    op.drop_index(op.f("ix_forensic_hypotheses_hypothesis_uid"), table_name="forensic_hypotheses")
    op.drop_column("forensic_hypotheses", "mitre_tactic")
    op.drop_column("forensic_hypotheses", "mitre_technique_name")
    op.drop_column("forensic_hypotheses", "mitre_technique_id")
    op.drop_column("forensic_hypotheses", "event_metadata")
    op.drop_column("forensic_hypotheses", "event_action")
    op.drop_column("forensic_hypotheses", "event_trust_tier")
    op.drop_column("forensic_hypotheses", "evidence_ids")
    op.drop_column("forensic_hypotheses", "hypothesis_uid")
    op.drop_column("forensic_hypotheses", "description")
    op.drop_column("forensic_hypotheses", "title")
    op.drop_column("forensic_hypotheses", "fusion_policy_hash")
    op.drop_column("forensic_hypotheses", "rule_trace")
    op.drop_column("forensic_hypotheses", "pattern_severity")
    op.drop_column("forensic_hypotheses", "trust_weight")
