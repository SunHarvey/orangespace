"""Control-plane protected configuration (no database substitute)."""
import importlib.util
import json
import os
import pytest


def test_protected_config_requires_explicit_secret_and_permissions(tmp_path):
    assert importlib.util.find_spec('orangespace_control.config') is not None
    from orangespace_control.config import load_config, ConfigError
    path = tmp_path / 'control.json'
    path.write_text(json.dumps({'database_url': 'mysql+pymysql://u:secret@localhost/control', 'session_ttl_seconds': 3600}))
    path.chmod(0o600)
    config = load_config(path)
    assert config.session_ttl_seconds == 3600
    assert 'secret' not in repr(config)
    path.chmod(0o644)
    with pytest.raises(ConfigError):
        load_config(path)
    path.chmod(0o600)
    path.write_text('{"database_url":"a","database_url":"b"}')
    with pytest.raises(ConfigError):
        load_config(path)
    path.write_text('{"database_url":"mysql+pymysql://u:p@localhost/control","admin_password":"bad"}')
    with pytest.raises(ConfigError):
        load_config(path)
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(ConfigError):
        load_config(link)
