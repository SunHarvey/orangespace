"""Enrollment v2 tables: deliberately independent of frozen v1 metadata."""
from sqlalchemy import MetaData, Table, Column, String, BigInteger, ForeignKey
from sqlalchemy.dialects.mysql import BINARY
from .schema_v1 import OPTIONS

metadata = MetaData()
enrollments = Table('control_enrollments', metadata,
    Column('id', BINARY(16), primary_key=True),
    Column('node_id', BINARY(16), nullable=False, unique=True),
    Column('alias', String(64), nullable=False, unique=True),
    Column('display_name', String(128), nullable=False),
    Column('api_origin', String(512), nullable=False),
    Column('tls_server_name', String(253), nullable=False),
    Column('fingerprint', BINARY(32), nullable=False),
    Column('token_digest', BINARY(32), nullable=False, unique=True),
    Column('expires_at', BigInteger, nullable=False), Column('consumed_at', BigInteger),
    Column('challenge_count', BigInteger, nullable=False), **OPTIONS)
challenges = Table('control_enrollment_challenges', metadata,
    Column('id', BINARY(16), primary_key=True),
    Column('enrollment_id', BINARY(16), ForeignKey(enrollments.c.id, ondelete='RESTRICT'), nullable=False),
    Column('public_key', BINARY(32), nullable=False), Column('nonce', String(43), nullable=False),
    Column('expires_at', BigInteger, nullable=False), Column('consumed_at', BigInteger), **OPTIONS)
