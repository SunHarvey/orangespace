"""Federation local session bindings; frozen node v1 remains unchanged."""
from alembic import op
import sqlalchemy as sa
revision = 'node_0002'
down_revision = 'node_0001'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('federation_bindings',
        sa.Column('exchange_id',sa.String(36),primary_key=True),
        sa.Column('token_digest',sa.String(64),sa.ForeignKey('access_sessions.token_digest',ondelete='RESTRICT'),unique=True,nullable=False),
        sa.Column('cleanup_digest',sa.String(64),nullable=False),
        sa.Column('federation',sa.JSON(),nullable=False),
        mysql_engine='InnoDB',mysql_charset='utf8mb4',mysql_collate='utf8mb4_0900_bin')


def downgrade():
    op.drop_table('federation_bindings')
