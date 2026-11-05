"""Runtime policy tests do not require a database server."""
import importlib
import json

import pytest


@pytest.fixture
def engine_capture(monkeypatch):
    module = importlib.import_module("orangespace_common.database")
    captured = {}

    def create_engine(url, **kwargs):
        captured.update(url=url, **kwargs)
        return captured

    def listens_for(engine, name):
        assert engine is captured
        assert name == "connect"

        def register(callback):
            captured["verify_server"] = callback
            return callback

        return register

    monkeypatch.setattr(module, "create_engine", create_engine)
    monkeypatch.setattr(module.event, "listens_for", listens_for)
    return module, captured


def test_explicit_disabled_transport_strips_marker_and_disables_driver_tls(engine_capture, monkeypatch):
    module, captured = engine_capture

    def unexpected_tls_context(**kwargs):
        pytest.fail("explicit DISABLED must not construct a TLS context")

    monkeypatch.setattr(module.ssl, "create_default_context", unexpected_tls_context)
    engine = module.create_mysql_engine("mysql+pymysql://user:***@db.example/db?ssl_mode=DISABLED")
    assert engine is captured
    assert dict(captured["url"].query) == {"charset": "utf8mb4"}
    assert captured["connect_args"] == {
        "connect_timeout": 10, "read_timeout": 30, "write_timeout": 30,
        "ssl_disabled": True,
    }
    assert captured["isolation_level"] == "READ COMMITTED"
    assert captured["hide_parameters"] is True
    assert captured["pool_pre_ping"] is True


@pytest.mark.parametrize("option", [
    "unix_socket=/run/mysql/mysql.sock", "ssl_ca=/ca", "ssl_cert=/cert", "ssl_key=/key",
    "ssl_disabled=true", "charset=latin1", "unix_socket=", "ssl_ca=", "ssl_cert=", "ssl_key=",
])
def test_disabled_transport_rejects_incompatible_options(engine_capture, option):
    module, captured = engine_capture
    with pytest.raises(ValueError):
        module.create_mysql_engine("mysql+pymysql://user:***@localhost/db?ssl_mode=DISABLED&" + option)
    assert not captured


@pytest.mark.parametrize("mode", [
    "disabled", "Disabled", "REQUIRED", "VERIFY_IDENTITY", "", "DISABLED%20",
    "DISABLED&ssl_mode=DISABLED", "DISABLED&ssl_mode=REQUIRED",
])
def test_invalid_ssl_mode_is_rejected(engine_capture, mode):
    module, captured = engine_capture
    with pytest.raises(ValueError):
        module.create_mysql_engine("mysql+pymysql://user:***@db.example/db?ssl_mode=" + mode)
    assert not captured


@pytest.mark.parametrize("query", [
    "ssl_mode=DISABLED&ssl_mode=", "ssl_mode=&ssl_mode=DISABLED",
    "ssl_mode=DISABLED&ssl_mode", "ssl_mode=&ssl_ca=/trusted-ca",
    "ssl_mode&ssl_ca=/trusted-ca",
])
def test_blank_or_duplicate_mode_cannot_disappear_during_url_parsing(engine_capture, monkeypatch, query):
    module, captured = engine_capture
    monkeypatch.setattr(module.ssl, "create_default_context", lambda **kwargs: object())
    with pytest.raises(ValueError):
        module.create_mysql_engine("mysql+pymysql://user:***@db.example/db?" + query)
    assert not captured


def test_tcp_default_still_requires_verified_ca(engine_capture, monkeypatch):
    module, captured = engine_capture
    contexts = []
    context = object()

    def verified_context(*, cafile):
        contexts.append(cafile)
        return context

    monkeypatch.setattr(module.ssl, "create_default_context", verified_context)
    with pytest.raises(ValueError, match="explicit CA"):
        module.create_mysql_engine("mysql+pymysql://user:***@db.example/db")
    module.create_mysql_engine("mysql+pymysql://user:***@db.example/db?ssl_ca=/trusted-ca")
    assert contexts == ["/trusted-ca"]
    assert captured["connect_args"]["ssl"] is context
    assert "ssl_disabled" not in captured["connect_args"]
    assert dict(captured["url"].query) == {"charset": "utf8mb4"}


def _run_server_policy(captured, version, storage="InnoDB", modes="STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION"):
    class Cursor:
        def __init__(self):
            self.statements = []
            self.closed = False

        def execute(self, statement):
            self.statements.append(statement)

        def fetchone(self):
            if self.statements[-1] == "SELECT VERSION(), @@default_storage_engine":
                return version, storage
            return (modes,)

        def close(self):
            self.closed = True

    class Connection:
        def cursor(self):
            return cursor

    cursor = Cursor()
    try:
        captured["verify_server"](Connection(), None)
    finally:
        assert cursor.closed
    return cursor.statements


@pytest.mark.parametrize("version", [
    "8.0.36", "8.0.37", "8.0.99", "8.0.36-log", "8.0.36-rds.20260101",
    "8.4.0", "8.4.10", "8.4.0-commercial",
])
def test_server_policy_accepts_supported_versions(engine_capture, version):
    module, captured = engine_capture
    module.create_mysql_engine("mysql+pymysql://user:***@/db?unix_socket=/run/mysql/mysql.sock")
    statements = _run_server_policy(captured, version)
    assert statements == [
        "SELECT VERSION(), @@default_storage_engine",
        "SET NAMES utf8mb4 COLLATE utf8mb4_0900_bin", "SELECT @@SESSION.sql_mode",
    ]


@pytest.mark.parametrize("version", [
    "5.7.44", "8.0.0", "8.0.35", "8.1.0", "8.2.0", "8.3.0", "9.0.0",
    "8.4.", "8.4.bad", "8.4.0.1", "8.4.0-", "8.4.0\n", "8.4.0 garbage",
    "8.0.36garbage", "8.4.0-MariaDB", "8.0.36-mariadb", "10.11.0-MariaDB", "", None,
])
def test_server_policy_rejects_unsupported_or_malformed_versions(engine_capture, version):
    module, captured = engine_capture
    module.create_mysql_engine("mysql+pymysql://user:***@/db?unix_socket=/run/mysql/mysql.sock")
    with pytest.raises(RuntimeError, match="MySQL"):
        _run_server_policy(captured, version)


@pytest.mark.parametrize("version", ["8.0.36", "8.4.0"])
@pytest.mark.parametrize("storage,modes", [
    ("MyISAM", "STRICT_TRANS_TABLES"), ("InnoDB", "NO_ENGINE_SUBSTITUTION"), ("InnoDB", ""),
])
def test_server_policy_preserves_storage_and_strict_mode_guards(engine_capture, version, storage, modes):
    module, captured = engine_capture
    module.create_mysql_engine("mysql+pymysql://user:***@/db?unix_socket=/run/mysql/mysql.sock")
    with pytest.raises(RuntimeError):
        _run_server_policy(captured, version, storage, modes)


def test_runtime_rejects_legacy_urls_without_connecting():
    module = importlib.import_module("orangespace_common.database")
    for url in ("sqlite:///old.sqlite", "postgresql+psycopg://localhost/old", "mysql://localhost/db"):
        with pytest.raises(ValueError, match="MySQL"):
            module.create_mysql_engine(url)


def test_runtime_requires_socket_or_verified_tls():
    module = importlib.import_module("orangespace_common.database")
    for suffix in ("", "?ssl_disabled=true", "?ssl_ca=/ca&ssl_check_hostname=false"):
        with pytest.raises(ValueError):
            module.create_mysql_engine("mysql+pymysql://user:secret@localhost/db" + suffix)


def test_protected_database_config(tmp_path):
    module = importlib.import_module("orangespace_common.database")
    path = tmp_path / "database.json"
    path.write_text(json.dumps({"database_url": "mysql+pymysql://u:p@/db?unix_socket=/run/mysql/mysql.sock"}))
    path.chmod(0o600)
    assert module.load_database_url(path).startswith("mysql+pymysql:")
    path.chmod(0o644)
    with pytest.raises(ValueError, match="protected"):
        module.load_database_url(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="protected"):
        module.load_database_url(link)


def test_settings_refuses_secret_url_environment(monkeypatch):
    from orangespace_node.config import Settings
    monkeypatch.setenv("ORANGESPACE_DATABASE_URL", "sqlite:///secret")
    with pytest.raises(ValueError, match="environment"):
        Settings._database_url_from_file()
