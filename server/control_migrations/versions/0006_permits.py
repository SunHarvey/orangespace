"""Add short authority permits; no cascade of replay/ownership history."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import BINARY, JSON
revision='control_0006'
down_revision='control_0005'
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('control_lease_permits',
        sa.Column('id',BINARY(16),primary_key=True),
        sa.Column('node_id',BINARY(16),sa.ForeignKey('control_nodes.id',ondelete='RESTRICT'),nullable=False),
        sa.Column('federation_session_id',BINARY(16),sa.ForeignKey('control_federation_sessions.id',ondelete='RESTRICT'),nullable=False),
        *[sa.Column(k,BINARY(16),nullable=False) for k in ('request_id','tunnel_id','sandbox_id')],
        sa.Column('generation',sa.BigInteger,nullable=False),sa.Column('operation',sa.String(6),nullable=False),
        sa.Column('epochs',JSON,nullable=False),sa.Column('expires_at',sa.BigInteger,nullable=False),
        sa.Column('remaining_ttl_ms',sa.BigInteger,nullable=False),sa.Column('state',sa.String(24),nullable=False),
        sa.UniqueConstraint('node_id','request_id',name='uq_permit_node_request'),
        mysql_engine='InnoDB',mysql_charset='utf8mb4',mysql_collate='utf8mb4_0900_bin')

def downgrade():
    op.drop_table('control_lease_permits')
