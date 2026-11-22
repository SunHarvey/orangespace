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


def test_renewal_limits_have_defaults_and_bounds(tmp_path):
    from orangespace_control.config import load_config, ConfigError
    path = tmp_path / 'control.json'
    url = 'mysql+pymysql://u:secret@localhost/control'

    def load(**extra):
        path.write_text(json.dumps({'database_url': url, **extra}))
        path.chmod(0o600)
        return load_config(path)

    config = load()
    assert (config.refresh_ttl_seconds, config.session_max_seconds) == (1209600, 2592000)
    config = load(session_ttl_seconds=600, refresh_ttl_seconds=3600, session_max_seconds=86400)
    assert (config.session_ttl_seconds, config.refresh_ttl_seconds, config.session_max_seconds) == (600, 3600, 86400)
    for bad in [dict(session_ttl_seconds=3600, refresh_ttl_seconds=1800),
                dict(refresh_ttl_seconds=86400, session_max_seconds=3600),
                dict(session_max_seconds=31536001, refresh_ttl_seconds=3600),
                dict(refresh_ttl_seconds=True)]:
        with pytest.raises(ConfigError):
            load(**bad)
