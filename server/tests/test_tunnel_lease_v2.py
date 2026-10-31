"""Lease-v2 deterministic clock seams; these are not native acceptance."""
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from orangespace_node.database import TunnelGeneration, TunnelTombstone
from test_tunnels import binding


@pytest.mark.parametrize("route", ["/v1/tunnels", "/v1/tunnels/" + "11111111-1111-1111-1111-111111111111/renew"])
@pytest.mark.parametrize("version", [None, "1", "3", "02", "2 ", "2, 2", ""])
def test_schema_rejection_precedes_manager_mutation(client, tokens, monkeypatch, route, version):
    manager = client.app.state.tunnels
    called = []
    monkeypatch.setattr(manager, "create", lambda *a: called.append("create"))
    monkeypatch.setattr(manager, "renew", lambda *a: called.append("renew"))
    headers = dict(tokens["alice"])
    if version is not None:
        headers["X-OrangeSpace-Lease-Schema"] = version
    response = client.post(route, headers=headers, json=binding() if route == "/v1/tunnels" else {})
    assert response.status_code == 426
    assert not called and not manager.children and not manager.leases
    with manager.db.session() as db:
        assert db.scalar(select(TunnelGeneration)) is None
        assert db.scalar(select(TunnelTombstone)) is None


def test_duplicate_schema_header_is_not_exact(client, tokens):
    headers = list(tokens["alice"].items()) + [("X-OrangeSpace-Lease-Schema", "2")] * 2
    assert client.post("/v1/tunnels", headers=headers, json=binding()).status_code == 426


@pytest.fixture
def clock_manager(client, tokens, monkeypatch):
    from orangespace_node import tunnels
    from orangespace_node.auth import authenticate, set_tunnel_grant
    manager = client.app.state.tunnels
    set_tunnel_grant(manager.db, "alice", True)
    current = authenticate(manager.db, tokens["alice"]["Authorization"].split()[1])
    clock = SimpleNamespace(wall=1000.25, mono=100.0, cost=0.125, session=2000)
    monkeypatch.setattr(tunnels, "time", SimpleNamespace(time=lambda: clock.wall, monotonic=lambda: clock.mono))
    monkeypatch.setattr(manager, "config", SimpleNamespace(max_leases=4, port_start=12000, port_end=12003,
        lease_seconds=30, endpoint_ip="127.0.0.1", tls_server_name="node.test", probe_port=8081))
    monkeypatch.setattr(manager, "_authority", lambda *a: (clock.session, 1))
    processes = []
    def start(reply):
        process = SimpleNamespace(pid=len(processes) + 1, tunnel_id=reply["tunnel_id"], stopped=False)
        process.poll = lambda: 0 if process.stopped else None
        processes.append(process)
        manager.children[process.pid] = process
        clock.wall += clock.cost
        clock.mono += clock.cost
        return process
    def stop(process):
        process.stopped = True
        manager.children.pop(process.pid)
    monkeypatch.setattr(manager, "_start", start)
    monkeypatch.setattr(manager, "_stop", stop)
    try:
        yield manager, current, clock, processes
    finally:
        manager.close()


def test_create_v2_budget_is_after_startup_and_wall_quantization(clock_manager):
    from orangespace_node.tunnels import TunnelBody
    manager, current, clock, processes = clock_manager
    reply = manager.create(current, TunnelBody(**binding()))
    assert len(reply) == 17
    assert reply["lease_schema"] == 2 and type(reply["lease_schema"]) is int
    assert type(reply["remaining_ttl_ms"]) is int
    assert reply["remaining_ttl_ms"] == 29625
    assert reply["expires_at"] == 1030
    assert not processes[0].stopped


def test_renew_v2_budget_is_fresh_and_not_cached_create_ttl(clock_manager):
    from orangespace_node.tunnels import TunnelBody
    manager, current, clock, _processes = clock_manager
    created = manager.create(current, TunnelBody(**binding()))
    clock.wall += 0.25
    clock.mono += 0.25
    renewed = manager.renew(current, created["tunnel_id"])
    assert set(renewed) == {"tunnel_id", "node_id", "expires_at", "lease_schema", "remaining_ttl_ms"}
    assert renewed["lease_schema"] == 2 and type(renewed["remaining_ttl_ms"]) is int
    assert renewed["remaining_ttl_ms"] == 29375
    assert created["remaining_ttl_ms"] == 29625


@pytest.mark.parametrize("operation", ["create", "renew"])
def test_submillisecond_exhaustion_revokes_exact_owned_child(clock_manager, monkeypatch, operation):
    from fastapi import HTTPException
    from orangespace_node.tunnels import TunnelBody
    manager, current, clock, processes = clock_manager
    request = binding()
    if operation == "create":
        clock.cost = 29.7495
        invoke = lambda: manager.create(current, TunnelBody(**request))
    else:
        manager.create(current, TunnelBody(**request))
        original = manager._remaining_ttl_ms
        def late_budget(*args):
            clock.wall += 29.6245
            clock.mono += 29.6245
            return original(*args)
        monkeypatch.setattr(manager, "_remaining_ttl_ms", late_budget)
        invoke = lambda: manager.renew(current, request["tunnel_id"])
    with pytest.raises(HTTPException) as error:
        invoke()
    assert error.value.status_code == 410
    assert request["tunnel_id"] not in manager.leases
    assert not manager.children and processes[0].stopped


def test_renew_cannot_reanchor_after_old_deadline_during_validation(clock_manager, monkeypatch):
    from fastapi import HTTPException
    from orangespace_node.tunnels import TunnelBody
    manager, current, clock, processes = clock_manager
    created = manager.create(current, TunnelBody(**binding()))
    original = manager._valid
    def delayed_valid(lease):
        expiry = original(lease)
        clock.mono = lease.deadline
        return expiry
    monkeypatch.setattr(manager, "_valid", delayed_valid)
    with pytest.raises(HTTPException) as error:
        manager.renew(current, created["tunnel_id"])
    assert error.value.status_code == 410
    assert not manager.leases and not manager.children and processes[0].stopped


@pytest.mark.parametrize("skew,expected", [(-0.5, 29625), (0.5, 29125)])
def test_subsecond_wall_skew_cannot_extend_monotonic_budget(clock_manager, monkeypatch, skew, expected):
    from orangespace_node.tunnels import TunnelBody
    manager, current, clock, _processes = clock_manager
    original = manager._start
    def shifted_start(reply):
        process = original(reply)
        clock.wall += skew
        return process
    monkeypatch.setattr(manager, "_start", shifted_start)
    reply = manager.create(current, TunnelBody(**binding()))
    assert reply["remaining_ttl_ms"] == expected
    assert reply["expires_at"] == 1030


@pytest.mark.parametrize("operation", ["create", "renew"])
def test_short_session_caps_authenticated_budget(clock_manager, operation):
    from orangespace_node.tunnels import TunnelBody
    manager, current, clock, _processes = clock_manager
    clock.session = 1002
    created = manager.create(current, TunnelBody(**binding()))
    result = created if operation == "create" else manager.renew(current, created["tunnel_id"])
    assert result["expires_at"] == clock.session
    assert result["remaining_ttl_ms"] == 1625


@pytest.mark.parametrize("budget,expected", [(0.0, None), (-1.0, None), (0.0005, None), (0.125, 125), (30.0, 30000), (31.0, 30000)])
@pytest.mark.parametrize("bound", ["mono", "wall", "session"])
def test_budget_floor_and_all_authority_bounds(clock_manager, budget, expected, bound):
    from fastapi import HTTPException
    manager, _current, clock, _processes = clock_manager
    clock.wall = clock.mono = 0.0
    bounds = {"mono": 60.0, "wall": 60.0, "session": 60.0, bound: budget}
    if expected is None:
        with pytest.raises(HTTPException) as error:
            manager._remaining_ttl_ms(bounds["mono"], bounds["wall"], bounds["session"])
        assert error.value.status_code == 410
    else:
        assert manager._remaining_ttl_ms(bounds["mono"], bounds["wall"], bounds["session"]) == expected


def test_budget_never_rounds_submillisecond_float_up(clock_manager):
    import math
    from fastapi import HTTPException
    manager, _current, clock, _processes = clock_manager
    clock.wall = clock.mono = 0.0
    with pytest.raises(HTTPException):
        manager._remaining_ttl_ms(math.nextafter(0.001, 0.0), 60, 60)
    assert manager._remaining_ttl_ms(0.001, 60, 60) == 1


@pytest.mark.parametrize("route", ["/v1/tunnels", "/v1/tunnels/11111111-1111-1111-1111-111111111111/renew"])
def test_schema_two_does_not_mask_missing_authentication(client, route):
    assert client.post(route, headers={"X-OrangeSpace-Lease-Schema": "2"}, json={}).status_code == 401
