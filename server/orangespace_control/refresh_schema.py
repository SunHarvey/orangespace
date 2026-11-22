"""Rotating refresh credentials for renewable central sessions (control_0008)."""
from sqlalchemy import MetaData, Table, Column, BigInteger
from sqlalchemy.dialects.mysql import BINARY
from .schema_v1 import OPTIONS
metadata=MetaData()
refresh_tokens=Table('control_refresh_tokens',metadata,
    Column('id',BINARY(16),primary_key=True),
    Column('session_id',BINARY(16),nullable=False,index=True),
    Column('token_digest',BINARY(32),nullable=False,unique=True),
    # Hard end of the session; never extended by rotation.
    Column('deadline',BigInteger,nullable=False),
    Column('created_at',BigInteger,nullable=False),
    Column('expires_at',BigInteger,nullable=False),
    Column('used_at',BigInteger),
    Column('replaced_by',BINARY(16)),**OPTIONS)
