"""Initial MySQL node schema. Frozen; never import mutable ORM metadata."""
from alembic import op
import sqlalchemy as sa

revision = "node_0001"
down_revision = None
branch_labels = None
depends_on = None

OPTIONS = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_bin"}


def upgrade():
    op.create_table("users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("username"), **OPTIONS)
    op.create_table("access_sessions",
        sa.Column("token_digest", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("revoked_at", sa.BigInteger(), nullable=True), **OPTIONS)
    op.create_index("ix_access_sessions_user_id", "access_sessions", ["user_id"])
    op.create_index("ix_access_sessions_expires_at", "access_sessions", ["expires_at"])
    op.create_table("tunnel_grants",
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("epoch", sa.BigInteger(), nullable=False), **OPTIONS)
    # Deliberately no FK: deleting a user/session must retain anti-replay history.
    op.create_table("tunnel_generations",
        sa.Column("user_id", sa.String(36), primary_key=True),
        sa.Column("sandbox_id", sa.String(36), primary_key=True),
        sa.Column("generation", sa.BigInteger(), nullable=False), **OPTIONS)
    op.create_table("tunnel_tombstones",
        sa.Column("tunnel_id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("session_digest", sa.String(64), nullable=False),
        sa.Column("sandbox_id", sa.String(36), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False), **OPTIONS)


def downgrade():
    # Explicit operator action only; downgrade destroys replay protection history.
    for name in ("tunnel_tombstones", "tunnel_generations", "tunnel_grants", "access_sessions", "users"):
        op.drop_table(name)
