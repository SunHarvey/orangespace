"""Renewable central sessions: one-time rotating refresh credentials."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import BINARY
revision='control_0008'
down_revision='control_0007'
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('control_refresh_tokens',
        sa.Column('id',BINARY(16),primary_key=True),
        sa.Column('session_id',BINARY(16),sa.ForeignKey('control_sessions.id',ondelete='RESTRICT'),nullable=False,index=True),
        sa.Column('token_digest',BINARY(32),nullable=False,unique=True),
        sa.Column('deadline',sa.BigInteger,nullable=False),
        sa.Column('created_at',sa.BigInteger,nullable=False),
        sa.Column('expires_at',sa.BigInteger,nullable=False),
        sa.Column('used_at',sa.BigInteger),
        sa.Column('replaced_by',BINARY(16)),
        sa.CheckConstraint('expires_at <= deadline',name='ck_control_refresh_deadline'),
        mysql_engine='InnoDB',mysql_charset='utf8mb4',mysql_collate='utf8mb4_0900_bin')

def downgrade():
    op.drop_table('control_refresh_tokens')
