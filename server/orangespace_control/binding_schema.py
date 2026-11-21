"""Latest tunnel binding per node, central user and sandbox (control_0007)."""
from sqlalchemy import MetaData, Table, Column, BigInteger
from sqlalchemy.dialects.mysql import BINARY
from .schema_v1 import OPTIONS
metadata=MetaData()
bindings=Table('control_tunnel_bindings',metadata,
    Column('node_id',BINARY(16),primary_key=True),
    Column('central_user_id',BINARY(16),primary_key=True),
    Column('sandbox_id',BINARY(16),primary_key=True),
    Column('generation',BigInteger,nullable=False),
    Column('tunnel_id',BINARY(16),nullable=False),
    Column('federation_session_id',BINARY(16),nullable=False),
    Column('updated_at',BigInteger,nullable=False),**OPTIONS)
