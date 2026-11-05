"""Managed runtime policy on owned local SQLite; no external DB or credentials."""
import json
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from orangespace_node.runtime import load_profile, build_app
from orangespace_node.config import Settings
from orangespace_node.app import create_app
from test_node_local_store import local_url, provision

NODE = UUID('11111111-1111-4111-8111-111111111111')


def profile_file(tmp_path, **changes):
    value = dict(schema=1, nodeUUID=str(NODE), dataRoot=str(tmp_path / 'files'),
                 dbConfig=str(tmp_path / 'db.json'))
    value.update(changes)
    path = tmp_path / 'profile.json'
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize('url', ['mysql+pymysql://unused.invalid/never', 'sqlite:///:memory:'])
def test_managed_policy_rejects_nonlocal_database_before_engine(tmp_path, monkeypatch, url):
    import orangespace_node.app as module
    def forbidden(*args, **kwargs):
        pytest.fail('engine creation reached')
    monkeypatch.setattr(module, 'Database', forbidden)
    with pytest.raises(ValueError, match='SQLite'):
        create_app(Settings(node_id=NODE, data_root=tmp_path / 'files', database_url=url,
                            federation_config=tmp_path / 'fed.json', deployment_mode='managed-local'))


@pytest.mark.parametrize('mode', [True, 'unknown', 1])
def test_settings_policy_is_strict(tmp_path, mode):
    with pytest.raises(ValueError, match='deployment'):
        Settings(node_id=NODE, data_root=tmp_path, database_url='unused', deployment_mode=mode)


def test_missing_federation_is_startup_error(tmp_path):
    url = local_url(tmp_path)
    provision(url)
    with pytest.raises(ValueError, match='federation'):
        create_app(Settings(node_id=NODE, data_root=tmp_path / 'files', database_url=url,
                            deployment_mode='managed-local'))


def federation_file(tmp_path):
    # Synthetic protected machine config, not enrollment or live Centre authority.
    path = tmp_path / 'fed.json'
    path.write_text(json.dumps(dict(origin='https://centre.invalid', token='x' * 43,
        node_id=str(NODE), node_epoch=1, config_revision=1, node_api_origin='https://node.invalid')))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize('operation', ['login', 'identity'])
def test_profile_policy_reaches_live_app_and_never_password_falls_back(tmp_path, monkeypatch, operation):
    url = local_url(tmp_path)
    provision(url)
    dbconfig = tmp_path / 'db.json'
    dbconfig.write_text(json.dumps(dict(database_url=url)))
    dbconfig.chmod(0o600)
    fed = federation_file(tmp_path)
    profile = load_profile(profile_file(tmp_path, deploymentMode='managed-local', federationConfig=str(fed)))
    app = build_app(profile)
    with TestClient(app) as client:
        assert client.get('/healthz').status_code == 200
        assert app.state.federation is not None
        app.state.federation = None  # Explicit injected loss seam, not a live Centre.
        import orangespace_node.app as module
        def forbidden(*args, **kwargs):
            raise AssertionError('local authentication fallback reached')
        monkeypatch.setattr(module, 'login', forbidden)
        monkeypatch.setattr(module, 'authenticate', forbidden)
        if operation == 'login':
            assert client.post('/v1/auth/login', json=dict(username='owned', password='unused')).status_code == 403
        else:
            assert client.get('/v1/me', headers={'Authorization': 'Bearer unused'}).status_code == 503


@pytest.mark.parametrize('layout', ['same', 'state-in-files', 'files-in-state', 'personal-symlink', 'personal-ancestor-alias', 'dotdot-alias'])
def test_managed_state_and_personal_roots_are_disjoint(tmp_path, layout):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    personal = tmp_path / 'files'
    if layout == 'same':
        personal = state
    elif layout == 'state-in-files':
        personal = tmp_path
    elif layout == 'files-in-state':
        personal = state / 'files'
    elif layout == 'personal-symlink':
        personal.symlink_to(state, target_is_directory=True)
    elif layout == 'personal-ancestor-alias':
        alias = tmp_path / 'alias'
        alias.symlink_to(state, target_is_directory=True)
        personal = alias / 'files'
    else:
        personal = state / '..' / 'state' / 'files'
    url = 'sqlite:///' + str(state / 'node.db')
    provision(url)
    with pytest.raises(ValueError, match='separate'):
        create_app(Settings(node_id=NODE, data_root=personal, database_url=url,
            deployment_mode='managed-local', federation_config=federation_file(tmp_path)))


@pytest.mark.parametrize('kind', ['missing', 'symlink', 'hardlink', 'public', 'state-parent-symlink'])
def test_managed_requires_existing_ordinary_private_state(tmp_path, kind):
    from pathlib import Path
    import os
    url = local_url(tmp_path)
    provision(url)
    path = Path(url.removeprefix('sqlite:///'))
    if kind == 'missing':
        path.unlink()
    elif kind == 'symlink':
        target = path.with_name('target.db')
        path.rename(target)
        path.symlink_to(target)
    elif kind == 'hardlink':
        os.link(path, path.with_name('alias.db'))
    elif kind == 'public':
        path.chmod(0o644)
    else:
        alias = tmp_path / 'alias'
        alias.symlink_to(path.parent, target_is_directory=True)
        url = 'sqlite:///' + str(alias / 'node.db')
    with pytest.raises((ValueError, OSError)):
        create_app(Settings(node_id=NODE, data_root=tmp_path / 'files', database_url=url,
            deployment_mode='managed-local', federation_config=federation_file(tmp_path)))


def test_invalid_protected_federation_fails_before_database(tmp_path, monkeypatch):
    url = local_url(tmp_path)
    provision(url)
    fed = federation_file(tmp_path)
    fed.write_text('{}')
    import orangespace_node.app as module
    def forbidden(*args, **kwargs):
        raise AssertionError('database reached for invalid federation')
    monkeypatch.setattr(module, 'Database', forbidden)
    with pytest.raises(ValueError, match='federation'):
        create_app(Settings(node_id=NODE, data_root=tmp_path / 'files', database_url=url,
            deployment_mode='managed-local', federation_config=fed))


def test_managed_admin_cannot_silently_drop_policy(tmp_path, monkeypatch, capsys):
    from orangespace_node.runtime import main
    import orangespace_node.cli as cli
    def forbidden():
        raise AssertionError('legacy CLI reached with managed policy')
    monkeypatch.setattr(cli, 'main', forbidden)
    path = profile_file(tmp_path, deploymentMode='managed-local')
    with pytest.raises(SystemExit) as error:
        main(['--profile', str(path), 'admin', 'list-users'])
    assert error.value.code == 2
    assert 'managed-local admin' in capsys.readouterr().err


def test_absent_mode_preserves_legacy_http_authentication(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import orangespace_node.app as module
    url = local_url(tmp_path)
    provision(url)
    calls = []
    # Explicit injected authentication seam: HTTP policy compatibility, not password crypto.
    def local_login(database, username, password, ttl):
        calls.append('login')
        return ('owned-token', 123456)
    def local_authenticate(database, token):
        calls.append('identity')
        assert token == 'owned-token'
        return SimpleNamespace(user_id=str(NODE), username='owned', expires_at=123456)
    monkeypatch.setattr(module, 'login', local_login)
    monkeypatch.setattr(module, 'authenticate', local_authenticate)
    app = create_app(Settings(node_id=NODE, data_root=tmp_path / 'files', database_url=url))
    with TestClient(app) as client:
        assert client.post('/v1/auth/login', json=dict(username='owned', password='unused')).status_code == 200
        assert client.get('/v1/me', headers={'Authorization': 'Bearer owned-token'}).status_code == 200
    assert calls == ['login', 'identity']


def test_protected_profile_explicit_managed_mode_and_legacy_default(tmp_path):
    assert load_profile(profile_file(tmp_path)).deployment_mode is None
    assert load_profile(profile_file(tmp_path, deploymentMode='managed-local')).deployment_mode == 'managed-local'


@pytest.mark.parametrize('mode', ['legacy', '', True, 1, None, ['managed-local']])
def test_protected_profile_rejects_unknown_or_nonstrict_modes(tmp_path, mode):
    with pytest.raises(ValueError, match='protected node runtime profile'):
        load_profile(profile_file(tmp_path, deploymentMode=mode))
