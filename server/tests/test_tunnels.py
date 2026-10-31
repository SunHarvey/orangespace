import time
from uuid import uuid4

from sqlalchemy import update

from orangespace_node.auth import digest_token
from orangespace_node.database import AccessSession


def binding(**changes):
    return {"sandbox_id": str(uuid4()), "generation": 1, "tunnel_id": str(uuid4()), **changes}


def test_session_authority_and_no_implicit_tunnel_grant(client, tokens):
    auth = tokens["alice"]
    session = client.get("/v1/session", headers=auth)
    assert session.status_code == 200
    value = session.json()
    assert set(value) == {"user_id", "username", "node_id", "expires_at"}
    assert {k: value[k] for k in ("user_id", "username", "node_id")} == client.get("/v1/me", headers=auth).json()
    assert time.time() < value["expires_at"]
    assert client.get("/v1/session").status_code == 401
    assert client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding()).status_code == 403
    with client.app.state.database.session() as db:
        db.execute(update(AccessSession).where(AccessSession.token_digest == digest_token(auth["Authorization"].split()[1])).values(expires_at=int(time.time()) - 1))
    assert client.get("/v1/session", headers=auth).status_code == 401


def test_explicit_admin_grant_does_not_enable_unconfigured_runtime(client, tokens):
    from orangespace_node.auth import set_tunnel_grant
    from orangespace_node.database import TunnelGrant
    db = client.app.state.database
    user_id = client.get("/v1/me", headers=tokens["alice"]).json()["user_id"]
    set_tunnel_grant(db, "alice", True)
    with db.session() as session:
        assert session.get(TunnelGrant, user_id).enabled
    assert client.post("/v1/tunnels", headers={**tokens["alice"], "X-OrangeSpace-Lease-Schema": "2"}, json=binding()).status_code == 503
    assert client.post("/v1/tunnels", headers={**tokens["bruce"], "X-OrangeSpace-Lease-Schema": "2"}, json=binding()).status_code == 403
    set_tunnel_grant(db, "alice", False)
    assert client.post("/v1/tunnels", headers={**tokens["alice"], "X-OrangeSpace-Lease-Schema": "2"}, json=binding()).status_code == 403


def test_tunnel_json_rejects_ambiguous_duplicate_members(client, tokens):
    import json
    value = binding()
    raw = json.dumps(value)[:-1] + ', "generation": 2}'
    assert client.post("/v1/tunnels", headers={**tokens["alice"], "X-OrangeSpace-Lease-Schema": "2"}, content=raw).status_code == 422


def test_concurrent_admin_grant_epochs_never_lose_revocation(client):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from sqlalchemy import event, select
    from orangespace_node.auth import set_tunnel_grant
    from orangespace_node.database import TunnelGrant
    database = client.app.state.database
    set_tunnel_grant(database, "alice", True)
    barrier = threading.Barrier(4)
    def synchronize_reads(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().startswith("SELECT") and "FROM tunnel_grants" in statement:
            barrier.wait(timeout=3)
    event.listen(database.engine, "after_cursor_execute", synchronize_reads)
    try:
        with ThreadPoolExecutor(4) as pool:
            list(pool.map(lambda _: set_tunnel_grant(database, "alice", False), range(4)))
    finally:
        event.remove(database.engine, "after_cursor_execute", synchronize_reads)
    with database.session() as session:
        grant = session.scalar(select(TunnelGrant))
        assert grant.epoch == 5
        assert not grant.enabled


import pytest


@pytest.mark.parametrize("changes", [{"generation": True}, {"generation": 1.0}, {"generation": 0}, {"generation": 2**53}, {"sandbox_id": "00000000-0000-0000-0000-000000000000"}, {"sandbox_id": "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"}, {"tunnel_id": "wrong"}, {"user_id": "untrusted"}, {"node_id": "untrusted"}, {"executable": "/untrusted"}])
def test_binding_schema_is_exact_and_strict(client, tokens, changes):
    response = client.post("/v1/tunnels", headers={**tokens["alice"], "X-OrangeSpace-Lease-Schema": "2"}, json=binding(**changes))
    assert response.status_code == 422
    assert "untrusted" not in response.text


def test_admin_cli_is_only_tunnel_grant_interface(client, config, mysql_config_path, monkeypatch, capsys):
    import sys
    from sqlalchemy import select
    from orangespace_node.cli import main
    from orangespace_node.database import TunnelGrant
    monkeypatch.setenv("ORANGESPACE_NODE_ID", str(config.node_id))
    monkeypatch.delenv("ORANGESPACE_DATABASE_URL", raising=False)
    monkeypatch.setenv("ORANGESPACE_DATABASE_CONFIG", str(mysql_config_path))
    monkeypatch.setenv("ORANGESPACE_DATA_ROOT", str(config.data_root))
    for operation, enabled in (("enable-tunnel", True), ("disable-tunnel", False)):
        monkeypatch.setattr(sys, "argv", ["orangespace-node", operation, "alice"])
        main()
        with client.app.state.database.session() as session:
            assert session.scalar(select(TunnelGrant)).enabled == enabled
    assert client.post("/v1/tunnel-grants", json={"username": "alice", "enabled": True}).status_code == 404
    assert capsys.readouterr().out.count("Tunnel grant updated.") == 2
