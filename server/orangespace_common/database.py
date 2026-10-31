"""Fail-closed MySQL 8.4 runtime policy shared by node and control plane."""
import json
import os
from pathlib import Path
import ssl
import stat

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url


COLLATION = "utf8mb4_0900_bin"


def load_database_url(path: str | Path) -> str:
    """Read a private regular JSON file without following the final symlink.

    Its parent directory must be administrator-managed. No URL is logged.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_uid not in (0, os.geteuid()):
                raise ValueError
            value = json.load(stream)
            if not isinstance(value, dict) or set(value) != {"database_url"} or not isinstance(value["database_url"], str):
                raise ValueError
            return value["database_url"]
    except (OSError, ValueError, TypeError):
        raise ValueError("database configuration must be a protected regular JSON file") from None


def create_mysql_engine(url: str) -> Engine:
    """Create the sole supported runtime engine; connection verifies server policy."""
    try:
        parsed = make_url(url)
    except Exception:
        raise ValueError("MySQL 8.4 URL required") from None
    if parsed.drivername != "mysql+pymysql" or not parsed.database:
        raise ValueError("MySQL 8.4 with PyMySQL is the only runtime database")
    query = dict(parsed.query)
    allowed = {"unix_socket", "ssl_ca", "ssl_cert", "ssl_key", "charset"}
    if set(query) - allowed or any(not isinstance(v, str) or not v for v in query.values()):
        raise ValueError("unsupported MySQL connection option")
    if query.get("charset", "utf8mb4") != "utf8mb4":
        raise ValueError("MySQL requires utf8mb4")
    socket = query.get("unix_socket")
    connect_args = {"connect_timeout": 10, "read_timeout": 30, "write_timeout": 30}
    if socket:
        if not os.path.isabs(socket) or parsed.host not in (None, "localhost") or set(query) & {"ssl_ca", "ssl_cert", "ssl_key"}:
            raise ValueError("MySQL requires a local absolute socket or verified TLS")
        connect_args["unix_socket"] = socket
    else:
        if not parsed.host or not query.get("ssl_ca"):
            raise ValueError("MySQL TCP requires verified TLS and an explicit CA")
        context = ssl.create_default_context(cafile=query["ssl_ca"])
        if "ssl_cert" in query:
            context.load_cert_chain(query["ssl_cert"], query.get("ssl_key"))
        elif "ssl_key" in query:
            raise ValueError("TLS key requires certificate")
        connect_args["ssl"] = context
    clean = parsed.set(query={"charset": "utf8mb4"})
    engine = create_engine(clean, connect_args=connect_args, isolation_level="READ COMMITTED", pool_pre_ping=True, hide_parameters=True)

    @event.listens_for(engine, "connect")
    def verify_server(connection, _record):
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT VERSION(), @@default_storage_engine")
            version, storage = cursor.fetchone()
            if not version.startswith("8.4.") or "mariadb" in version.lower() or storage.lower() != "innodb":
                raise RuntimeError("MySQL 8.4 / InnoDB required")
            cursor.execute("SET NAMES utf8mb4 COLLATE utf8mb4_0900_bin")
            cursor.execute("SELECT @@SESSION.sql_mode")
            modes = set(cursor.fetchone()[0].split(","))
            if not modes & {"STRICT_TRANS_TABLES", "STRICT_ALL_TABLES"}:
                raise RuntimeError("strict MySQL SQL mode required")
        finally:
            cursor.close()
    return engine
