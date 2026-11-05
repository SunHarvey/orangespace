"""Independent-process HTTP/ASGI portals; injected auth/helper, NOT transport evidence."""
import multiprocessing
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from orangespace_node.app import create_app, identity
from orangespace_node.config import Settings
from orangespace_node.database import Database, TunnelGeneration, TunnelTombstone
from test_node_local_store import local_url, provision, seed, USER, SANDBOX


def http_reservation(url, personal, tunnel_id, ready, start, answers):
    # Each process owns an app, database engine, manager AND TestClient portal.
    app = create_app(Settings(node_id=UUID(USER), data_root=personal, database_url=url))
    app.dependency_overrides[identity] = lambda: SimpleNamespace(
        user_id=USER, token_digest='d' * 64, expires_at=2**40)
    attempted = []
    with TestClient(app) as client:
        manager = app.state.tunnels  # Production TunnelManager.create, no replacement.
        manager.config = SimpleNamespace(max_leases=4, port_start=12000, port_end=12004,
            lease_seconds=30, endpoint_ip='127.0.0.1', tls_server_name='owned.invalid', probe_port=12010)
        def injected_helper_failure(reply):
            # No executable/network helper. Failure follows durable reservation.
            attempted.append(tunnel_id)
            raise RuntimeError('injected helper failure, not real transport')
        manager._start = injected_helper_failure
        ready.put('ready')
        assert start.wait(5)
        reply = client.post('/v1/tunnels', headers={'X-OrangeSpace-Lease-Schema': '2'},
                            json=dict(sandbox_id=SANDBOX, generation=2, tunnel_id=tunnel_id))
        answers.put((reply.status_code, attempted))


@pytest.mark.parametrize('existing', [True, False])
def test_http_same_generation_has_one_reservation_one_conflict(tmp_path, existing):
    from sqlalchemy import text
    url = local_url(tmp_path)
    provision(url)
    seed(url)
    if not existing:
        db = Database(url)
        with db.session() as session:
            session.execute(text('DELETE FROM tunnel_generations'))
        db.close()
    context = multiprocessing.get_context('spawn')
    ready, answers, start = context.Queue(), context.Queue(), context.Event()
    processes = [context.Process(target=http_reservation,
        args=(url, tmp_path / ('files-' + str(i)), str(uuid4()), ready, start, answers))
        for i in range(2)]
    try:
        for process in processes:
            process.start()
        assert [ready.get(timeout=8) for _ in processes] == ['ready', 'ready']
        start.set()
        results = [answers.get(timeout=8) for _ in processes]
        assert sorted(status for status, _ in results) == [409, 503]
        assert sum(len(attempts) for _, attempts in results) == 1
        for process in processes:
            process.join(5)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.kill()
                process.join(2)
    db = Database(url)
    try:
        with db.session() as session:
            assert session.get(TunnelGeneration, (USER, SANDBOX)).generation == 2
            rows = session.query(TunnelTombstone).all()
            assert len(rows) == 1
            assert rows[0].tunnel_id == next(attempts[0] for _, attempts in results if attempts)
    finally:
        db.close()
