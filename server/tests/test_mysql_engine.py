"""Runtime policy tests do not require a database server."""
import importlib
import json

import pytest


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
