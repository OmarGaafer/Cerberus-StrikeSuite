"""Add scan tables

Revision ID: 0002_scan_tables
Revises: 0001_initial
Create Date: 2025-01-01

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision = "0002_scan_tables"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():"""Add scan tables

Revision ID: 0002_scan_tables
Revises: 0001_initial
Create Date: 2025-01-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision = "0002_scan_tables"
down_revision = "0001_initial"   # ← change to match your actual last revision
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("target", sa.String(255), nullable=False, index=True),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("command", sa.Text),
        sa.Column("status", sa.String(50), server_default="pending", index=True),
        sa.Column("success", sa.Boolean, server_default=sa.false()),
        sa.Column("error", sa.Text),
        sa.Column("elapsed", sa.Float, server_default="0"),
        sa.Column("nmap_version", sa.String(50)),
        sa.Column("raw_xml", sa.Text),
        sa.Column("raw_text", sa.Text),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=True),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_scans_target_type", "scans", ["target", "scan_type"])

    op.create_table(
        "scan_hosts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("ip", sa.String(45), nullable=False, index=True),
        sa.Column("mac", sa.String(17)),
        sa.Column("vendor", sa.String(255)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("state", sa.String(20), server_default="unknown"),
        sa.Column("uptime", sa.String(50)),
        sa.Column("distance", sa.String(20)),
        sa.Column("os_matches", JSON, server_default="[]"),
        sa.Column("host_scripts", JSON, server_default="{}"),
        sa.Column("traceroute", JSON, server_default="[]"),
    )

    op.create_table(
        "scan_ports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", UUID(as_uuid=True), sa.ForeignKey("scan_hosts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port", sa.Integer, nullable=False, index=True),
        sa.Column("protocol", sa.String(10), nullable=False),
        sa.Column("state", sa.String(20), nullable=False, index=True),
        sa.Column("reason", sa.String(50)),
        sa.Column("service", sa.String(100)),
        sa.Column("product", sa.String(255)),
        sa.Column("version", sa.String(255)),
        sa.Column("extrainfo", sa.String(255)),
        sa.Column("cpe", JSON, server_default="[]"),
        sa.Column("scripts", JSON, server_default="{}"),
    )


def downgrade():
    op.drop_table("scan_ports")
    op.drop_table("scan_hosts")
    op.drop_index("ix_scans_target_type", "scans")
    op.drop_table("scans")
    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("target", sa.String(255), nullable=False, index=True),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("command", sa.Text),
        sa.Column("status", sa.String(50), server_default="pending", index=True),
        sa.Column("success", sa.Boolean, server_default=sa.false()),
        sa.Column("error", sa.Text),
        sa.Column("elapsed", sa.Float, server_default="0"),
        sa.Column("nmap_version", sa.String(50)),
        sa.Column("raw_xml", sa.Text),
        sa.Column("raw_text", sa.Text),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("engagements.id"), nullable=True),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_scans_target_type", "scans", ["target", "scan_type"])

    op.create_table(
        "scan_hosts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("ip", sa.String(45), nullable=False, index=True),
        sa.Column("mac", sa.String(17)),
        sa.Column("vendor", sa.String(255)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("state", sa.String(20), server_default="unknown"),
        sa.Column("uptime", sa.String(50)),
        sa.Column("distance", sa.String(20)),
        sa.Column("os_matches", JSON, server_default="[]"),
        sa.Column("host_scripts", JSON, server_default="{}"),
        sa.Column("traceroute", JSON, server_default="[]"),
    )

    op.create_table(
        "scan_ports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", UUID(as_uuid=True), sa.ForeignKey("scan_hosts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port", sa.Integer, nullable=False, index=True),
        sa.Column("protocol", sa.String(10), nullable=False),
        sa.Column("state", sa.String(20), nullable=False, index=True),
        sa.Column("reason", sa.String(50)),
        sa.Column("service", sa.String(100)),
        sa.Column("product", sa.String(255)),
        sa.Column("version", sa.String(255)),
        sa.Column("extrainfo", sa.String(255)),
        sa.Column("cpe", JSON, server_default="[]"),
        sa.Column("scripts", JSON, server_default="{}"),
    )


def downgrade():
    op.drop_table("scan_ports")
    op.drop_table("scan_hosts")
    op.drop_index("ix_scans_target_type", "scans")
    op.drop_table("scans")
