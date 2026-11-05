"""Add inventory evidence without altering v1 tables."""
from alembic import op
from orangespace_control.identity_schema import metadata
revision='control_0004'
down_revision='control_0003'
branch_labels=None
depends_on=None

def upgrade():
    metadata.create_all(op.get_bind(),checkfirst=False)

def downgrade():
    metadata.drop_all(op.get_bind(),checkfirst=False)
