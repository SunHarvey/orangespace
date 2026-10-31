"""Explicit additive exchange migration; frozen earlier metadata unchanged."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import BINARY, JSON
revision='control_0005'
down_revision='control_0004'
branch_labels=None
depends_on=None
OPTIONS=dict(mysql_engine='InnoDB',mysql_charset='utf8mb4',mysql_collate='utf8mb4_0900_bin')

def upgrade():
    op.create_table('control_node_exchanges',
        sa.Column('id',BINARY(16),primary_key=True),
        sa.Column('token_digest',BINARY(32),nullable=False,unique=True),
        *[sa.Column(k,BINARY(16),sa.ForeignKey(t+'.id',ondelete='RESTRICT'),nullable=False) for k,t in [('central_session_id','control_sessions'),('central_user_id','control_users'),('node_id','control_nodes'),('mapping_id','control_identity_mappings'),('grant_id','control_grants')]],
        sa.Column('legacy_user_id',BINARY(16),nullable=False),
        *[sa.Column(k,sa.BigInteger,nullable=False) for k in ('user_epoch','node_epoch','mapping_epoch','grant_epoch','config_revision','expires_at','federation_expires_at')],
        *[sa.Column(k,BINARY(32),nullable=False) for k in ('public_key','key_fingerprint','machine_token_digest')],
        sa.Column('request_id',BINARY(16)),sa.Column('result',JSON),
        sa.UniqueConstraint('node_id','request_id',name='uq_exchange_node_request'),**OPTIONS)
    op.create_table('control_federation_sessions',
        sa.Column('id',BINARY(16),primary_key=True),
        sa.Column('exchange_id',BINARY(16),sa.ForeignKey('control_node_exchanges.id',ondelete='RESTRICT'),nullable=False,unique=True),
        sa.Column('result',JSON,nullable=False),sa.Column('expires_at',sa.BigInteger,nullable=False),**OPTIONS)

def downgrade():
    op.drop_table('control_federation_sessions')
    op.drop_table('control_node_exchanges')
