"""Explicit Node-private SQLite storage; never a fallback for failed MySQL.

The containing directory is a separately provisioned private state directory,
not the personal-files area. Runtime opens existing files only. No SQL retries.
"""
import os
from pathlib import Path
import sqlite3
import stat

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

BUSY_TIMEOUT_MS = 1000


def local_path(url: str) -> Path:
    parsed = make_url(url)
    if (parsed.drivername != "sqlite" or parsed.host or parsed.username or parsed.password
            or parsed.port or parsed.query or "?" in url or "#" in url
            or not parsed.database or not parsed.database.startswith("/")):
        raise ValueError("explicit absolute Node SQLite file URL required")
    path = Path(parsed.database)
    if str(path) != parsed.database or any(part in (".", "..") for part in parsed.database.split("/")):
        raise ValueError("ordinary canonical Node state path required")
    for ancestor in [path.parent, *path.parent.parents]:
        info = ancestor.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise ValueError("Node state ancestors must be trusted ordinary directories")
    info = path.parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_mode & 0o700 != 0o700:
        raise ValueError("private owned writable Node state directory required")
    return path


def _verify_file(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or info.st_mode & 0o600 != 0o600):
        raise ValueError("private owned writable ordinary Node state file required")


def create_local_engine(url: str, *, provision: bool = False):
    path = local_path(url)
    if provision:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    _verify_file(path)

    def connect():
        local_path(url)
        _verify_file(path)
        # Internally generated URI guarantees mode=rw: sqlite may not recreate it.
        connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                     timeout=BUSY_TIMEOUT_MS / 1000, check_same_thread=False,
                                     isolation_level=None)
        try:
            cursor = connection.cursor()
            if provision:
                cursor.execute("PRAGMA journal_mode=WAL")
                if cursor.fetchone()[0] != "wal":
                    raise RuntimeError("Node WAL provisioning failed")
            cursor.execute("PRAGMA journal_mode")
            if cursor.fetchone()[0] != "wal":
                raise RuntimeError("Node store requires explicit migration to WAL")
            for name, value in (("foreign_keys", 1), ("busy_timeout", BUSY_TIMEOUT_MS),
                                ("synchronous", 2), ("read_uncommitted", 0)):
                cursor.execute(f"PRAGMA {name}={value}")
                cursor.execute(f"PRAGMA {name}")
                if cursor.fetchone()[0] != value:
                    raise RuntimeError("Node SQLite connection policy rejected")
            cursor.close()
            return connection
        except BaseException:
            connection.close()
            raise

    engine = create_engine("sqlite://", creator=connect, poolclass=NullPool, hide_parameters=True)

    @event.listens_for(engine, "begin")
    def begin(connection):
        # File writer lock precedes even the first SELECT, across engines/processes.
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def create_node_engine(url: str, *, provision: bool = False):
    if make_url(url).drivername.startswith("sqlite"):
        return create_local_engine(url, provision=provision)
    from orangespace_common.database import create_mysql_engine
    return create_mysql_engine(url)
