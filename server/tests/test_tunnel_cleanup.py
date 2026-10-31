"""Injected cleanup faults around owned, real Linux sing-box children.

These are controlled Python fault injections, not observed kernel failures.
"""
import os
import signal
import subprocess
import threading
import time

import pytest
from fastapi import HTTPException

from orangespace_node.auth import authenticate, set_tunnel_grant
from orangespace_node.database import TunnelGeneration, TunnelTombstone
from orangespace_node.tunnels import TunnelBody
from test_tunnels import binding
from test_tunnel_runtime import runtime_client, new_lease, wait_removed


@pytest.mark.parametrize("path", ["delete", "supersede", "startup", "postspawn"])
@pytest.mark.parametrize("fault", ["signal", "wait"])
def test_sync_cleanup_revokes_before_fault_and_retries(runtime_client, monkeypatch, path, fault):
    client, auth, _config_path, _cert = runtime_client
    manager = client.app.state.tunnels
    current = authenticate(manager.db, auth["Authorization"].split()[1])
    healthy = new_lease(client, auth)
    old = new_lease(client, auth) if path in ("delete", "supersede") else None
    request = binding(**({"sandbox_id": old["sandbox_id"], "generation": 2} if path == "supersede" else {}))
    target = manager.leases[old["tunnel_id"]].process if old else None
    healthy_process = manager.leases[healthy["tunnel_id"]].process
    original_signal = signal.pidfd_send_signal
    calls, invalidated = [], []
    blocked = True

    def fail_owned():
        calls.append(True)
        invalidated.append(old is None or old["tunnel_id"] not in manager.leases)
        if fault == "signal":
            raise OSError("injected owned pidfd signal failure")
        raise subprocess.TimeoutExpired("owned trusted runtime", 2)

    def send_signal(fd, sig, *args, **kwargs):
        if target is not None and fd == target.pidfd and blocked and fault == "signal":
            fail_owned()
        return original_signal(fd, sig, *args, **kwargs)

    def instrument(process):
        original_wait = process.wait
        def wait(*args, **kwargs):
            if blocked and fault == "wait":
                fail_owned()
            return original_wait(*args, **kwargs)
        patches.setattr(process, "wait", wait)

    try:
        with monkeypatch.context() as patches:
            patches.setattr(signal, "pidfd_send_signal", send_signal)
            with manager.lock:
                if target is not None:
                    instrument(target)
                elif path == "startup":
                    def startup_failure(process, port):
                        nonlocal target
                        target = process
                        instrument(process)
                        raise RuntimeError("injected readiness failure")
                    patches.setattr(manager, "_listener", startup_failure)
                else:
                    original_start = manager._start
                    original_authority = manager._authority
                    def postspawn_failure(reply):
                        nonlocal target
                        target = original_start(reply)
                        instrument(target)
                        def changed_epoch(*args):
                            patches.setattr(manager, "_authority", original_authority)
                            expiry, epoch = original_authority(*args)
                            return expiry, epoch + 1
                        patches.setattr(manager, "_authority", changed_epoch)
                        return target
                    patches.setattr(manager, "_start", postspawn_failure)
                error = None
                try:
                    if path == "delete":
                        manager.delete(current, old["tunnel_id"])
                    else:
                        manager.create(current, TunnelBody(**request))
                except Exception as caught:
                    error = caught
                assert calls and all(invalidated), "authorization must be removed before signaling/waiting"
                assert isinstance(error, HTTPException), "cleanup faults must return a generic HTTP error"
                assert error.status_code == 503
                assert manager.failed, "synchronous cleanup must latch allocation failure"
                assert target is not None and manager.children.get(target.pid) is target
                pinned = target.pidfd
                assert pinned is not None
                os.fstat(pinned)
                for _ in range(3):
                    manager._reap()
                assert len(calls) >= 4, "pending cleanup must be retried despite otherwise-valid authority"
                assert target.pidfd == pinned and manager.children.get(target.pid) is target
                os.fstat(pinned)
                if fault == "signal":
                    assert target.poll() is None
                cleanup_id = old["tunnel_id"] if old else request["tunnel_id"]
                with pytest.raises(HTTPException) as incomplete_delete:
                    manager.delete(current, cleanup_id)
                assert incomplete_delete.value.status_code == 503, "pending deletion must not claim cleanup success"
                if old:
                    with pytest.raises(HTTPException) as inactive:
                        manager.renew(current, old["tunnel_id"])
                    assert inactive.value.status_code in (404, 410)
                    with pytest.raises(HTTPException) as hidden:
                        manager.probe(old["tunnel_id"], old["probe_request"])
                    assert hidden.value.status_code == 404
                assert healthy_process.poll() is None
                assert manager.renew(current, healthy["tunnel_id"])["tunnel_id"] == healthy["tunnel_id"]
                assert manager.probe(healthy["tunnel_id"], healthy["probe_request"])["proof"] == healthy["probe_response"]
                if path != "delete":
                    with manager.db.session() as session:
                        assert session.get(TunnelTombstone, request["tunnel_id"]) is not None
                        assert session.get(TunnelGeneration, (current.user_id, request["sandbox_id"])).generation == request["generation"]
                with pytest.raises(HTTPException) as disabled:
                    manager.create(current, TunnelBody(**binding()))
                assert disabled.value.status_code == 503
                blocked = False
            wait_removed(manager, cleanup_id, target)
            with manager.lock:
                assert manager.thread.is_alive()
                assert target.poll() is not None and target.pidfd is None
                assert manager.children.get(target.pid) is not target
            assert client.delete(f'/v1/tunnels/{cleanup_id}', headers=auth).status_code == 204
            assert manager.failed
            assert client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding()).status_code == 503
            if old:
                cleanup_entered, cleanup_release = threading.Event(), threading.Event()
                healthy_wait = healthy_process.wait
                def paused_healthy_wait(*args, **kwargs):
                    result = healthy_wait(*args, **kwargs)
                    cleanup_entered.set()
                    assert cleanup_release.wait(5), "grant cleanup barrier was not released"
                    return result
                try:
                    with manager.lock:
                        patches.setattr(healthy_process, "wait", paused_healthy_wait)
                        set_tunnel_grant(manager.db, "alice", False)
                        set_tunnel_grant(manager.db, "alice", True)
                    assert cleanup_entered.wait(3)
                    # The reaper owns the lock while releasing B's real child.
                    # Busy is not authorization: require exactly 429 here, then
                    # strict inactive semantics only after ownership quiesces.
                    status = client.post(f'/v1/tunnels/{old["tunnel_id"]}/renew', headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}).status_code
                    assert status == 429, f"busy renew status={status}"
                    status = client.post(f'/v1/tunnels/{old["tunnel_id"]}/probe', headers={"X-OrangeSpace-Probe": old["probe_request"]}).status_code
                    assert status == 429, f"busy probe status={status}"
                finally:
                    cleanup_release.set()
                # Grant toggling intentionally invalidates even healthy B.
                wait_removed(manager, healthy["tunnel_id"], healthy_process)
                with manager.lock:
                    assert not manager.leases and not manager.children
                    assert healthy_process.poll() is not None and healthy_process.pidfd is None
                    assert manager.failed and manager.thread.is_alive()
                status = client.post(f'/v1/tunnels/{old["tunnel_id"]}/renew', headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}).status_code
                assert status in (404, 410), f"settled renew status={status}"
                status = client.post(f'/v1/tunnels/{old["tunnel_id"]}/probe', headers={"X-OrangeSpace-Probe": old["probe_request"]}).status_code
                assert status == 404, f"settled probe status={status}"
    finally:
        # Remove every injected fault before guaranteed fixture-owned cleanup,
        # including when an assertion fails during the RED run.
        blocked = False
        manager.close()


@pytest.mark.parametrize("reason", ["generation", "grant-toggle"])
def test_validity_requires_current_durable_generation_and_grant_epoch(runtime_client, reason):
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    manager = client.app.state.tunnels
    current = authenticate(manager.db, auth["Authorization"].split()[1])
    with manager.lock:
        if reason == "generation":
            # Model the durable reservation having committed before synchronous
            # teardown: old generation must no longer authorize renewal/proof.
            with manager.db.session() as session:
                session.get(TunnelGeneration, (current.user_id, value["sandbox_id"])).generation += 1
        else:
            set_tunnel_grant(manager.db, "alice", False)
            set_tunnel_grant(manager.db, "alice", True)
        with pytest.raises(HTTPException) as inactive:
            manager._valid(manager.leases[value["tunnel_id"]])
        assert inactive.value.status_code == 410
        with pytest.raises(HTTPException) as hidden:
            manager.probe(value["tunnel_id"], value["probe_request"])
        assert hidden.value.status_code == 404
        with pytest.raises(HTTPException):
            manager.renew(current, value["tunnel_id"])


@pytest.mark.parametrize("action", ["logout", "close"])
@pytest.mark.parametrize("fault", ["signal", "wait"])
def test_multi_cleanup_invalidates_all_and_keeps_reaper_on_failure(runtime_client, monkeypatch, action, fault):
    client, auth, _path, _cert = runtime_client
    manager = client.app.state.tunnels
    current = authenticate(manager.db, auth["Authorization"].split()[1])
    values = [new_lease(client, auth), new_lease(client, auth)]
    target, other = [manager.leases[v["tunnel_id"]].process for v in values]
    original_signal, original_wait = signal.pidfd_send_signal, target.wait
    before_kill = []
    owner_thread = threading.get_ident()
    blocked = True

    def fail_owned():
        # Logout revokes DB authority before acquiring the manager lock. The
        # watcher may therefore already be cleaning individual revoked leases;
        # assert whole-selection removal at the synchronous caller's attempts.
        if threading.get_ident() == owner_thread:
            before_kill.append(all(v["tunnel_id"] not in manager.leases for v in values))
        if fault == "signal":
            raise OSError("injected owned pidfd signal failure")
        raise subprocess.TimeoutExpired("owned trusted runtime", 2)

    def send_signal(fd, sig, *args, **kwargs):
        if fd == target.pidfd and blocked and fault == "signal":
            fail_owned()
        return original_signal(fd, sig, *args, **kwargs)

    def wait(*args, **kwargs):
        if blocked and fault == "wait":
            fail_owned()
        return original_wait(*args, **kwargs)

    try:
        with monkeypatch.context() as patches:
            patches.setattr(signal, "pidfd_send_signal", send_signal)
            patches.setattr(target, "wait", wait)
            with pytest.raises(HTTPException) as incomplete:
                if action == "logout":
                    manager.logout(current)
                else:
                    manager.close()
            assert incomplete.value.status_code == 503
            assert before_kill and all(before_kill), "all selected leases must be invalid before any kill attempt"
            assert manager.failed and manager.thread.is_alive() and not manager.stopping.is_set()
            assert other.poll() is not None, "one failed cleanup must not prevent the other selected cleanup"
            assert target.pid in manager.children and target.pidfd is not None
            os.fstat(target.pidfd)
            blocked = False
            deadline = time.monotonic() + 4
            while target.pid in manager.children and time.monotonic() < deadline:
                time.sleep(0.02)
            assert not manager.children and not manager.leases
            assert manager.thread.is_alive() and manager.failed
            if action == "logout":
                assert authenticate(manager.db, auth["Authorization"].split()[1]) is None
    finally:
        blocked = False
        manager.close()


@pytest.mark.parametrize("fault", ["signal", "wait"])
def test_logout_retries_already_pending_session_child(runtime_client, monkeypatch, fault):
    client, auth, _path, _cert = runtime_client
    manager = client.app.state.tunnels
    current = authenticate(manager.db, auth["Authorization"].split()[1])
    value = new_lease(client, auth)
    target = manager.leases[value["tunnel_id"]].process
    original_signal = signal.pidfd_send_signal
    blocked = True

    def send_signal(fd, sig, *args, **kwargs):
        if blocked and fault == "signal" and fd == target.pidfd:
            raise OSError("injected owned pidfd signal failure")
        return original_signal(fd, sig, *args, **kwargs)

    original_wait = target.wait
    def wait(*args, **kwargs):
        if blocked and fault == "wait":
            raise subprocess.TimeoutExpired("owned trusted runtime", 2)
        return original_wait(*args, **kwargs)

    try:
        with monkeypatch.context() as patches:
            patches.setattr(signal, "pidfd_send_signal", send_signal)
            patches.setattr(target, "wait", wait)
            with manager.lock:
                with pytest.raises(HTTPException):
                    manager.delete(current, value["tunnel_id"])
                assert value["tunnel_id"] not in manager.leases
                assert manager.children.get(target.pid) is target
                with pytest.raises(HTTPException) as incomplete:
                    manager.logout(current)
                assert incomplete.value.status_code == 503
                assert authenticate(manager.db, auth["Authorization"].split()[1]) is None
    finally:
        blocked = False
        manager.close()
