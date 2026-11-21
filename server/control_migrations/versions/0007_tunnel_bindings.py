"""Centre-owned tunnel anti-replay: nodes keep no durable lease state."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import BINARY
revision='control_0007'
down_revision='control_0006'
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('control_tunnel_bindings',
        sa.Column('node_id',BINARY(16),sa.ForeignKey('control_nodes.id',ondelete='RESTRICT'),primary_key=True),
        sa.Column('central_user_id',BINARY(16),sa.ForeignKey('control_users.id',ondelete='RESTRICT'),primary_key=True),
        sa.Column('sandbox_id',BINARY(16),primary_key=True),
        sa.Column('generation',sa.BigInteger,nullable=False),
        sa.Column('tunnel_id',BINARY(16),nullable=False),
        sa.Column('federation_session_id',BINARY(16),sa.ForeignKey('control_federation_sessions.id',ondelete='RESTRICT'),nullable=False),
        sa.Column('updated_at',sa.BigInteger,nullable=False),
        sa.CheckConstraint('generation BETWEEN 1 AND 9007199254740991',name='ck_control_tunnel_generation'),
        mysql_engine='InnoDB',mysql_charset='utf8mb4',mysql_collate='utf8mb4_0900_bin')
    op.create_index('ix_permit_tunnel','control_lease_permits',['tunnel_id'])

def downgrade():
    op.drop_index('ix_permit_tunnel','control_lease_permits')
    op.drop_table('control_tunnel_bindings')
