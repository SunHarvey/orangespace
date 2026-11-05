"""Additive inventory evidence metadata; frozen v1 remains unchanged."""
from sqlalchemy import MetaData, Table, Column, BigInteger, UniqueConstraint
from sqlalchemy.dialects.mysql import BINARY
from .schema_v1 import OPTIONS
metadata = MetaData()
evidence = Table('control_identity_evidence',metadata,
    Column('id',BINARY(16),primary_key=True),
    Column('node_id',BINARY(16),nullable=False),
    Column('public_key',BINARY(32),nullable=False),
    Column('key_fingerprint',BINARY(32),nullable=False),
    Column('node_epoch',BigInteger,nullable=False),
    Column('config_revision',BigInteger,nullable=False),
    Column('legacy_user_id',BINARY(16),nullable=False),
    Column('request_id',BINARY(16),nullable=False),
    Column('created_at',BigInteger,nullable=False),
    Column('expires_at',BigInteger,nullable=False),
    Column('digest',BINARY(32),nullable=False,unique=True),
    UniqueConstraint('node_id','request_id',name='uq_control_identity_request'),**OPTIONS)
