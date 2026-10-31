"""Independent v3 scoped grant invalidation/outbox metadata."""
from sqlalchemy import MetaData, Table, Column, BigInteger, String, ForeignKey, CheckConstraint
from sqlalchemy.dialects.mysql import BINARY
from .schema_v1 import users, nodes, grants, OPTIONS, MAX_INT
metadata = MetaData()
events = Table('control_grant_revocation_outbox', metadata,
    Column('id', BINARY(16), primary_key=True),
    Column('user_id', BINARY(16), ForeignKey(users.c.id, ondelete='RESTRICT'), nullable=False),
    Column('node_id', BINARY(16), ForeignKey(nodes.c.id, ondelete='RESTRICT'), nullable=False),
    Column('grant_id', BINARY(16), ForeignKey(grants.c.id, ondelete='RESTRICT'), nullable=False),
    Column('before_epoch', BigInteger, nullable=False), Column('after_epoch', BigInteger, nullable=False),
    Column('committed_at', BigInteger, nullable=False), Column('enforcement_deadline', BigInteger, nullable=False),
    Column('cleanup_state', String(16), nullable=False), Column('delivery_state', String(16), nullable=False),
    CheckConstraint("cleanup_state IN ('pending','complete')", name='ck_grant_cleanup'),
    CheckConstraint("delivery_state IN ('pending','delivered')", name='ck_grant_delivery'),
    CheckConstraint(f'before_epoch >= 1 AND after_epoch = before_epoch + 1 AND after_epoch <= {MAX_INT}', name='ck_grant_event_epochs'), **OPTIONS)
