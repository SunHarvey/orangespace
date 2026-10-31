from contextlib import contextmanager
import time
from collections.abc import Iterator
from uuid import uuid4

from sqlalchemy import BigInteger, Boolean, ForeignKey, String
from orangespace_common.database import create_mysql_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    __abstract__ = True
    __table_args__ = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_bin"}


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, default=lambda: int(time.time()), nullable=False)


class AccessSession(Base):
    __tablename__ = "access_sessions"
    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class TunnelGrant(Base):
    __tablename__ = "tunnel_grants"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    epoch: Mapped[int] = mapped_column(BigInteger, default=1, nullable=False)


class TunnelGeneration(Base):
    __tablename__ = "tunnel_generations"
    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sandbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False)


class TunnelTombstone(Base):
    __tablename__ = "tunnel_tombstones"
    tunnel_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    session_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    sandbox_id: Mapped[str] = mapped_column(String(36), nullable=False)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False)


class Database:
    def __init__(self, url: str):
        self.engine = create_mysql_engine(url)
        self.factory = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self) -> None:
        from orangespace_common.node_migrations import verify_schema
        verify_schema(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.factory.begin() as session:
            yield session

    def close(self) -> None:
        self.engine.dispose()
