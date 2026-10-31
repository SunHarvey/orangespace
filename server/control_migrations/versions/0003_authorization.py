"""Scoped grant invalidation outbox, not user-session revocation."""
from alembic import op
from orangespace_control.authorization_schema import metadata
revision = 'control_0003'
down_revision = 'control_0002'
branch_labels = None
depends_on = None


def upgrade():
    for table in metadata.sorted_tables:
        table.create(op.get_bind(), checkfirst=False)


def downgrade():
    raise RuntimeError('destructive control-plane downgrade is forbidden')
