"""One-time C1 node possession enrollment, independent of v1 metadata."""
from alembic import op
from orangespace_control.enrollment_schema import metadata
revision = 'control_0002'
down_revision = 'control_0001'
branch_labels = None
depends_on = None


def upgrade():
    for table in metadata.sorted_tables:
        table.create(op.get_bind(), checkfirst=False)


def downgrade():
    raise RuntimeError('destructive control-plane downgrade is forbidden')
