from contextlib import contextmanager, nullcontext
import threading
import time
from collections.abc import Iterator
from uuid import uuid4

from sqlalchemy import BigInteger, Boolean, ForeignKey, String
from .local_store import create_node_engine
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


MEMORY = "memory:"


class Database:
    """Node state store.

    ``MEMORY`` keeps sessions, federation bindings and tunnel bookkeeping in
    process memory only: nothing is installed or written to disk and a restart
    forgets everything (clients exchange again; the Centre remembers tunnel
    generations and IDs). Any other URL is the legacy migrated database.
    """
    def __init__(self, url: str):
        self.memory = url == MEMORY
        if self.memory:
            from sqlalchemy import create_engine
            from sqlalchemy.pool import StaticPool
            # One private connection, serialized by a process lock.
            self.engine = create_engine("sqlite://", poolclass=StaticPool,
                                        connect_args={"check_same_thread": False})
        else:
            self.engine = create_node_engine(url)
        self.lock = threading.RLock() if self.memory else None
        self.factory = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self) -> None:
        if self.memory:
            from .federation import metadata as federation_metadata
            Base.metadata.create_all(self.engine)
            federation_metadata.create_all(self.engine)
            return
        from orangespace_common.node_migrations import verify_schema
        verify_schema(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.lock if self.lock is not None else nullcontext():
            with self.factory.begin() as session:
                yield session

    def close(self) -> None:
        self.engine.dispose()
