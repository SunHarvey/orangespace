"""Additive permit records; issued is not transport establishment."""
from sqlalchemy import MetaData, Table, Column, BigInteger, String, UniqueConstraint
from sqlalchemy.dialects.mysql import BINARY, JSON
from .schema_v1 import OPTIONS
metadata=MetaData()
permits=Table('control_lease_permits',metadata,
    Column('id',BINARY(16),primary_key=True),
    *[Column(k,BINARY(16),nullable=False) for k in ('node_id','request_id','federation_session_id','tunnel_id','sandbox_id')],
    Column('generation',BigInteger,nullable=False),
    Column('operation',String(6),nullable=False),
    Column('epochs',JSON,nullable=False),
    Column('expires_at',BigInteger,nullable=False),
    Column('remaining_ttl_ms',BigInteger,nullable=False),
    Column('state',String(24),nullable=False),
    UniqueConstraint('node_id','request_id',name='uq_permit_node_request'),**OPTIONS)
