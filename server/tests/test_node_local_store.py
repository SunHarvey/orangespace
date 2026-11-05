"""Owned local files only: no network database fixtures."""
import os
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import inspect, text

from orangespace_node.database import Database
from orangespace_common.node_migrations import upgrade


def local_url(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return "sqlite:///" + str(state / "node.db")


def provision(url):
    from orangespace_node.local_store import create_local_engine
    engine = create_local_engine(url, provision=True)
    try:
        upgrade(engine)
    finally:
        engine.dispose()


def test_explicit_migration_and_runtime_pragmas(tmp_path):
    url = local_url(tmp_path)
    path = Path(url.removeprefix("sqlite:///"))
    path.touch(mode=0o600)
    db = Database(url)
    with pytest.raises(RuntimeError, match="migration"):
        db.initialize()
    db.close()
    provision(url)
    db = Database(url)
    db.initialize()
    with db.engine.connect() as connection:
        assert set(inspect(connection).get_table_names()) == {
            "alembic_version", "users", "access_sessions", "tunnel_grants",
            "tunnel_generations", "tunnel_tombstones", "federation_bindings"}
        for pragma, expected in [("journal_mode", "wal"), ("foreign_keys", 1),
                                 ("synchronous", 2), ("busy_timeout", 1000)]:
            assert connection.scalar(text("PRAGMA " + pragma)) == expected
        fk = inspect(connection).get_foreign_keys("federation_bindings")
        assert fk[0]["referred_table"] == "access_sessions"
        assert fk[0]["options"]["ondelete"] == "RESTRICT"
    assert path.stat().st_mode & 0o777 == 0o600
    db.close()


def test_schema_verification_checks_real_tables_and_constraints(tmp_path):
    url = local_url(tmp_path)
    provision(url)
    db = Database(url)
    with db.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE federation_bindings")
    with pytest.raises(RuntimeError, match="schema"):
        db.initialize()
    db.close()


def test_explicit_migration_command_provisions_owned_file(tmp_path):
    import json
    import subprocess
    import sys
    url = local_url(tmp_path)
    config = tmp_path / "local.json"
    config.write_text(json.dumps({"database_url": url}))
    config.chmod(0o600)
    result = subprocess.run([sys.executable, "-m", "orangespace_common.node_migrations",
                             "upgrade", "--database-config", str(config)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    db = Database(url)
    db.initialize()
    db.close()


USER = "11111111-1111-4111-8111-111111111111"
SANDBOX = "22222222-2222-4222-8222-222222222222"


def seed(url):
    import time
    from orangespace_node.database import User, AccessSession, TunnelGrant, TunnelGeneration
    db = Database(url)
    with db.session() as session:
        session.add(User(id=USER, username="owned", password_hash="not-a-password"))
        session.flush()
        session.add(AccessSession(token_digest="d" * 64, user_id=USER,
                                  expires_at=int(time.time()) + 600))
        session.add(TunnelGrant(user_id=USER, enabled=True, epoch=7))
        session.add(TunnelGeneration(user_id=USER, sandbox_id=SANDBOX, generation=1))
    db.close()


def reserve_in_production(url, generation, tunnel_id, ready=None, start=None, result=None):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from orangespace_node.tunnels import TunnelManager, TunnelBody
    db = Database(url)
    manager = TunnelManager(db, SimpleNamespace(node_id=USER, tunnel_config=None))
    manager.config = SimpleNamespace(max_leases=4, port_start=12000, port_end=12004,
                                    lease_seconds=30, endpoint_ip="127.0.0.1",
                                    tls_server_name="owned.invalid", probe_port=12010)
    attempted = []
    def fail_after_committed_reservation(reply):
        # Separate engine sees the pair before any helper side effect.
        observer = Database(url)
        from orangespace_node.database import TunnelGeneration, TunnelTombstone
        with observer.session() as session:
            assert session.get(TunnelGeneration, (USER, SANDBOX)).generation == generation
            assert session.get(TunnelTombstone, tunnel_id).generation == generation
        observer.close()
        attempted.append(tunnel_id)
        raise RuntimeError("owned injected helper failure")
    manager._start = fail_after_committed_reservation
    if ready is not None:
        ready.put("ready")
        assert start.wait(5)
    try:
        manager.create(SimpleNamespace(user_id=USER, token_digest="d" * 64,
                                       expires_at=2**40),
                       TunnelBody(sandbox_id=SANDBOX, generation=generation, tunnel_id=tunnel_id))
    except HTTPException as error:
        value = (error.status_code, attempted)
    finally:
        manager.close()
        db.close()
    if result is not None:
        result.put(value)
    return value


@pytest.mark.parametrize("existing", [True, False])
def test_production_reservation_independent_processes_restart_and_burned_helper_failure(tmp_path, existing):
    import multiprocessing
    from uuid import uuid4
    from orangespace_node.database import TunnelGeneration, TunnelTombstone
    url = local_url(tmp_path)
    provision(url)
    seed(url)
    if not existing:
        db = Database(url)
        with db.session() as session:
            session.execute(text("DELETE FROM tunnel_generations WHERE user_id=:u"), {"u": USER})
        db.close()
    ctx = multiprocessing.get_context("fork")
    ready, result, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    ids = [str(uuid4()), str(uuid4())]
    processes = [ctx.Process(target=reserve_in_production,
                            args=(url, 2, tid, ready, start, result)) for tid in ids]
    try:
        for process in processes:
            process.start()
        assert [ready.get(timeout=5) for _ in processes] == ["ready", "ready"]
        start.set()
        answers = [result.get(timeout=5) for _ in processes]
        assert sorted(code for code, _ in answers) == [409, 503]
        assert sum(len(attempts) for _, attempts in answers) == 1
        for process in processes:
            process.join(5)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.kill()
                process.join(2)
    db = Database(url)
    db.initialize()
    with db.session() as session:
        assert session.get(TunnelGeneration, (USER, SANDBOX)).generation == 2
        tombstones = session.query(TunnelTombstone).all()
        assert len(tombstones) == 1
        used = tombstones[0].tunnel_id
    db.close()
    assert reserve_in_production(url, 2, str(uuid4())) == (409, [])
    assert reserve_in_production(url, 1, str(uuid4())) == (409, [])
    assert reserve_in_production(url, 3, used) == (409, [])
    assert reserve_in_production(url, 3, str(uuid4()))[0] == 503


def test_rollback_generation_and_tombstone_pair(tmp_path):
    from orangespace_node.database import TunnelGeneration, TunnelTombstone
    url = local_url(tmp_path)
    provision(url)
    seed(url)
    db = Database(url)
    with pytest.raises(RuntimeError, match="rollback"):
        with db.session() as session:
            session.get(TunnelGeneration, (USER, SANDBOX)).generation = 2
            session.flush()
            session.add(TunnelTombstone(tunnel_id="rollback", user_id=USER,
                        session_digest="d" * 64, sandbox_id=SANDBOX, generation=2))
            session.flush()
            raise RuntimeError("rollback")
    db.close()
    db = Database(url)
    with db.session() as session:
        assert session.get(TunnelGeneration, (USER, SANDBOX)).generation == 1
        assert session.get(TunnelTombstone, "rollback") is None
    db.close()


@pytest.mark.parametrize("kind", ["missing", "unmigrated", "corrupt", "readonly", "hardlink", "symlink"])
def test_invalid_state_never_recreated_or_reset(tmp_path, kind):
    url = local_url(tmp_path)
    path = Path(url.removeprefix("sqlite:///"))
    if kind == "unmigrated":
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.close()
        path.chmod(0o600)
    elif kind == "corrupt":
        path.write_bytes(b"owned corrupt state" * 100)
        path.chmod(0o600)
    elif kind in ("readonly", "hardlink", "symlink"):
        provision(url)
        if kind == "readonly":
            path.chmod(0o400)
        else:
            alias = path.with_name("alias.db")
            if kind == "hardlink":
                os.link(path, alias)
            else:
                path.rename(alias)
                path.symlink_to(alias)
    before = path.read_bytes() if path.exists() else None
    with pytest.raises(Exception):
        db = Database(url)
        try:
            db.initialize()
        finally:
            db.close()
    assert (path.read_bytes() if path.exists() else None) == before


def test_federation_restrict_fk_is_enforced_and_retained(tmp_path):
    from sqlalchemy.exc import IntegrityError
    url = local_url(tmp_path)
    provision(url)
    seed(url)
    db = Database(url)
    with db.session() as session:
        session.execute(text("INSERT INTO federation_bindings VALUES (:e, :t, :c, :f)"),
                        {"e": "exchange", "t": "d" * 64, "c": "c" * 64, "f": "{}"})
        session.execute(text("UPDATE access_sessions SET revoked_at=123"))
    db.close()
    db = Database(url)
    for statement in ("DELETE FROM access_sessions", "DELETE FROM users"):
        with pytest.raises(IntegrityError):
            with db.session() as session:
                session.execute(text(statement))
    with db.session() as session:
        assert session.scalar(text("SELECT revoked_at FROM access_sessions")) == 123
        assert session.scalar(text("SELECT epoch FROM tunnel_grants")) == 7
        assert session.scalar(text("SELECT cleanup_digest FROM federation_bindings")) == "c" * 64
    db.close()


def test_all_sessions_lock_before_first_select_with_bounded_busy(tmp_path):
    import threading
    import time
    from sqlalchemy.exc import OperationalError
    url = local_url(tmp_path)
    provision(url)
    first, second = Database(url), Database(url)
    results = []
    def competing_select():
        before = time.monotonic()
        try:
            with second.session() as session:
                session.execute(text("SELECT 1"))
                results.append("unexpected read")
        except OperationalError:
            results.append(time.monotonic() - before)
    with first.session() as session:
        session.execute(text("SELECT 1"))
        thread = threading.Thread(target=competing_select)
        thread.start()
        thread.join(3)
        assert not thread.is_alive()
        assert len(results) == 1 and isinstance(results[0], float)
        assert 0.8 <= results[0] < 2.5
    first.close()
    second.close()


@pytest.mark.parametrize("url", ["sqlite://", "sqlite:///:memory:", "sqlite:///relative.db",
                                  "sqlite:////tmp/state.db?mode=memory", "sqlite:///file:alias"])
def test_nonordinary_urls_are_rejected(url):
    with pytest.raises((ValueError, OSError)):
        Database(url)


def test_schema_verification_rejects_missing_replay_primary_key(tmp_path):
    url = local_url(tmp_path)
    provision(url)
    db = Database(url)
    with db.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE tunnel_generations")
        connection.exec_driver_sql("CREATE TABLE tunnel_generations (user_id VARCHAR(36) NOT NULL, sandbox_id VARCHAR(36) NOT NULL, generation BIGINT NOT NULL)")
    with pytest.raises(RuntimeError, match="schema"):
        db.initialize()
    db.close()


def test_untrusted_writable_ancestor_rejected(tmp_path):
    outer = tmp_path / "untrusted"
    outer.mkdir(mode=0o777)
    outer.chmod(0o777)
    state = outer / "state"
    state.mkdir(mode=0o700)
    path = state / "node.db"
    path.touch(mode=0o600)
    with pytest.raises(ValueError):
        Database("sqlite:///" + str(path))


def test_replay_history_cannot_have_cascading_user_fk(tmp_path):
    url = local_url(tmp_path)
    provision(url)
    db = Database(url)
    with db.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE tunnel_generations")
        connection.exec_driver_sql("CREATE TABLE tunnel_generations (user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE, sandbox_id VARCHAR(36) NOT NULL, generation BIGINT NOT NULL, PRIMARY KEY(user_id, sandbox_id))")
    with pytest.raises(RuntimeError, match="schema"):
        db.initialize()
    db.close()
