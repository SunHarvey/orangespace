"""Real local sing-box children; budget delays/faults are injected Python seams."""
from types import SimpleNamespace
import os
import signal
import subprocess
import time

import pytest
from fastapi import HTTPException

from orangespace_node import tunnels
from orangespace_node.auth import authenticate
from orangespace_node.tunnels import TunnelBody
from test_tunnels import binding
from test_tunnel_runtime import runtime_client, new_lease


def test_v2_real_child_startup_cost_reduces_returned_budget(runtime_client, monkeypatch):
    client, auth, _path, _cert = runtime_client
    manager = client.app.state.tunnels
    original = manager._start
    def delayed_start(reply):
        process = original(reply)
        time.sleep(0.05)
        return process
    monkeypatch.setattr(manager, "_start", delayed_start)
    value = new_lease(client, auth)
    assert len(value) == 17 and value["lease_schema"] == 2
    assert type(value["remaining_ttl_ms"]) is int and 1 <= value["remaining_ttl_ms"] < 29950
    assert manager.config.lease_seconds == 30
    process = manager.leases[value["tunnel_id"]].process
    assert process.poll() is None and process.pidfd is not None
    assert client.delete(f'/v1/tunnels/{value["tunnel_id"]}', headers=auth).status_code == 204
    assert process.poll() is not None and process.pidfd is None


@pytest.mark.parametrize("operation", ["create", "renew"])
@pytest.mark.parametrize("fault", [None, "signal", "wait"])
def test_v2_exhaustion_keeps_exact_real_child_cleanup_ownership(runtime_client, monkeypatch, operation, fault):
    client, auth, _path, _cert = runtime_client
    manager = client.app.state.tunnels
    current = authenticate(manager.db, auth["Authorization"].split()[1])
    healthy = new_lease(client, auth)
    healthy_process = manager.leases[healthy["tunnel_id"]].process
    request = binding()
    target = None
    if operation == "renew":
        value = new_lease(client, auth, **request)
        target = manager.leases[value["tunnel_id"]].process
    original_start = manager._start
    original_budget = manager._remaining_ttl_ms
    original_signal = signal.pidfd_send_signal
    blocked = True
    observed = []
    def fail_cleanup():
        observed.append(request["tunnel_id"] not in manager.leases)
        if fault == "signal":
            raise OSError("injected owned pidfd failure")
        raise subprocess.TimeoutExpired("owned fixture child", 2)
    def instrument(process):
        original_wait = process.wait
        def wait(*args, **kwargs):
            if blocked and fault == "wait":
                fail_cleanup()
            return original_wait(*args, **kwargs)
        patches.setattr(process, "wait", wait)
    def start(reply):
        nonlocal target
        target = original_start(reply)
        instrument(target)
        return target
    def send_signal(fd, sig, *args, **kwargs):
        if target is not None and fd == target.pidfd and blocked and fault == "signal":
            fail_cleanup()
        return original_signal(fd, sig, *args, **kwargs)
    def exhausted_budget(deadline, expires_at, session_expiry):
        # This case exercises cleanup of a child that actually started. The
        # independent pre-spawn admission check must retain its real budget.
        if operation == "create" and target is None:
            return original_budget(deadline, expires_at, session_expiry)
        # Only the budget computation sees elapsed time. Real OS clocks and
        # other live leases remain untouched, including during cleanup.
        with monkeypatch.context() as clock_patch:
            clock_patch.setattr(tunnels, "time", SimpleNamespace(
                time=time.time, monotonic=lambda: deadline))
            return original_budget(deadline, expires_at, session_expiry)
    try:
        with monkeypatch.context() as patches, manager.lock:
            if target is not None:
                instrument(target)
            patches.setattr(manager, "_start", start)
            patches.setattr(manager, "_remaining_ttl_ms", exhausted_budget)
            patches.setattr(signal, "pidfd_send_signal", send_signal)
            with pytest.raises(HTTPException) as error:
                if operation == "create":
                    manager.create(current, TunnelBody(**request))
                else:
                    manager.renew(current, request["tunnel_id"])
            assert error.value.status_code == (503 if fault else 410)
            assert target is not None and request["tunnel_id"] not in manager.leases
            assert healthy_process.poll() is None
            if fault:
                assert observed and all(observed) and manager.failed
                assert manager.children.get(target.pid) is target and target.pidfd is not None
                os.fstat(target.pidfd)
                blocked = False
                manager._reap()
            assert target.poll() is not None and target.pidfd is None
            assert target.pid not in manager.children
        assert manager.renew(current, healthy["tunnel_id"])["lease_schema"] == 2
        assert healthy_process.poll() is None
    finally:
        blocked = False
        with manager.lock:
            manager._reap()
