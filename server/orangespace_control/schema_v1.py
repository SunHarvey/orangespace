"""Frozen initial MySQL schema; do not edit after migration v1 ships."""
from sqlalchemy import (MetaData, Table, Column, String, BigInteger, Boolean,
                        ForeignKey, UniqueConstraint, CheckConstraint, Text)
from sqlalchemy.dialects.mysql import BINARY, JSON

metadata = MetaData()
MAX_INT = 9007199254740991
OPTIONS = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4', 'mysql_collate': 'utf8mb4_0900_bin'}

def epoch(name, initial=1):
    return Column(name, BigInteger, nullable=False, server_default=str(initial))


def table(name, *columns):
    return Table('control_' + name, metadata, *columns, **OPTIONS)


users = table('users',
    Column('id', BINARY(16), primary_key=True),
    Column('username', String(64), nullable=False, unique=True),
    Column('password_hash', String(255), nullable=False),
    Column('role', String(8), nullable=False),
    Column('enabled', Boolean, nullable=False), epoch('user_epoch'),
    Column('created_at', BigInteger, nullable=False),
    CheckConstraint("role IN ('admin','user')", name='ck_control_user_role'),
    CheckConstraint(f'user_epoch BETWEEN 1 AND {MAX_INT}', name='ck_control_user_epoch'))

sessions = table('sessions',
    Column('id', BINARY(16), primary_key=True),
    Column('user_id', BINARY(16), ForeignKey(users.c.id, ondelete='RESTRICT'), nullable=False, index=True),
    Column('token_digest', BINARY(32), nullable=False, unique=True),
    epoch('user_epoch'), Column('expires_at', BigInteger, nullable=False),
    Column('revoked_at', BigInteger))

nodes = table('nodes',
    Column('id', BINARY(16), primary_key=True), Column('alias', String(64), nullable=False, unique=True),
    Column('display_name', String(128), nullable=False), Column('api_origin', String(512), nullable=False),
    Column('tls_server_name', String(253), nullable=False), Column('public_key', BINARY(32)),
    Column('key_fingerprint', BINARY(32), nullable=False), Column('machine_token_digest', BINARY(32), unique=True),
    Column('state', String(16), nullable=False), epoch('node_epoch'), epoch('config_revision'),
    Column('last_seen_at', BigInteger),
    CheckConstraint("state IN ('pending','active','suspended','revoked')", name='ck_control_node_state'),
    CheckConstraint(f'node_epoch BETWEEN 1 AND {MAX_INT} AND config_revision BETWEEN 1 AND {MAX_INT}', name='ck_control_node_epochs'))

mappings = table('identity_mappings',
    Column('id', BINARY(16), primary_key=True),
    Column('node_id', BINARY(16), ForeignKey(nodes.c.id, ondelete='RESTRICT'), nullable=False),
    Column('legacy_user_id', BINARY(16), nullable=False),
    Column('central_user_id', BINARY(16), ForeignKey(users.c.id, ondelete='RESTRICT'), nullable=False),
    Column('state', String(16), nullable=False), epoch('mapping_epoch'),
    Column('evidence_digest', BINARY(32), nullable=False),
    Column('approved_by', BINARY(16), ForeignKey(users.c.id, ondelete='RESTRICT')),
    Column('reason', String(512), nullable=False),
    UniqueConstraint('node_id', 'legacy_user_id', name='uq_control_mapping_legacy'),
    UniqueConstraint('node_id', 'central_user_id', name='uq_control_mapping_central'),
    CheckConstraint("state IN ('pending','approved','revoked')", name='ck_control_mapping_state'),
    CheckConstraint(f'mapping_epoch BETWEEN 1 AND {MAX_INT}', name='ck_control_mapping_epoch'))

grants = table('grants',
    Column('id', BINARY(16), primary_key=True),
    Column('user_id', BINARY(16), ForeignKey(users.c.id, ondelete='RESTRICT'), nullable=False),
    Column('node_id', BINARY(16), ForeignKey(nodes.c.id, ondelete='RESTRICT'), nullable=False),
    Column('enabled', Boolean, nullable=False), epoch('grant_epoch'),
    Column('scopes', JSON, nullable=False), Column('valid_until', BigInteger),
    UniqueConstraint('user_id', 'node_id', name='uq_control_grant_user_node'),
    CheckConstraint(f'grant_epoch BETWEEN 1 AND {MAX_INT}', name='ck_control_grant_epoch'))

audit = table('audit_events',
    Column('id', BINARY(16), primary_key=True),
    Column('actor_id', BINARY(16), ForeignKey(users.c.id, ondelete='RESTRICT')),
    Column('action', String(64), nullable=False), Column('object_id', BINARY(16), nullable=False),
    Column('before_revision', BigInteger), Column('after_revision', BigInteger),
    Column('created_at', BigInteger, nullable=False), Column('reason', String(512), nullable=False),
    Column('request_id', BINARY(16), nullable=False))

revocations = table('revocations',
    Column('id', BINARY(16), primary_key=True), Column('user_id', BINARY(16), ForeignKey(users.c.id, ondelete='RESTRICT'), nullable=False),
    Column('session_id', BINARY(16), ForeignKey(sessions.c.id, ondelete='RESTRICT')),
    Column('committed_at', BigInteger, nullable=False), Column('enforcement_deadline', BigInteger, nullable=False),
    Column('cleanup_state', String(16), nullable=False),
    CheckConstraint("cleanup_state IN ('pending','complete')", name='ck_control_cleanup_state'))

locks = table('locks', Column('name', String(32), primary_key=True))
rates = table('login_buckets', Column('id', BINARY(32), primary_key=True),
              Column('window_start', BigInteger, nullable=False), Column('attempts', BigInteger, nullable=False))
