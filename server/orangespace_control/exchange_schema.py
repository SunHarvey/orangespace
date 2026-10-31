"""Additive exchange authority snapshots, independent of frozen v1 metadata."""
from sqlalchemy import MetaData, Table, Column, BigInteger, UniqueConstraint
from sqlalchemy.dialects.mysql import BINARY, JSON
from .schema_v1 import OPTIONS
metadata=MetaData()
exchanges=Table('control_node_exchanges',metadata,
    Column('id',BINARY(16),primary_key=True),
    Column('token_digest',BINARY(32),nullable=False,unique=True),
    *[Column(k,BINARY(16),nullable=False) for k in ('central_session_id','central_user_id','node_id','mapping_id','grant_id','legacy_user_id')],
    *[Column(k,BigInteger,nullable=False) for k in ('user_epoch','node_epoch','mapping_epoch','grant_epoch','config_revision','expires_at','federation_expires_at')],
    Column('public_key',BINARY(32),nullable=False),
    Column('key_fingerprint',BINARY(32),nullable=False),
    Column('machine_token_digest',BINARY(32),nullable=False),
    Column('request_id',BINARY(16)),
    Column('result',JSON),
    UniqueConstraint('node_id','request_id',name='uq_exchange_node_request'),**OPTIONS)
federations=Table('control_federation_sessions',metadata,
    Column('id',BINARY(16),primary_key=True),
    Column('exchange_id',BINARY(16),nullable=False,unique=True),
    Column('result',JSON,nullable=False),
    Column('expires_at',BigInteger,nullable=False),**OPTIONS)
