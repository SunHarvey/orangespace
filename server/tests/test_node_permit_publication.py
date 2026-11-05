"""Real MySQL manager, deterministic lock contention; MODEL children, not Go/native."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi import HTTPException
from test_tunnel_lease_v2 import clock_manager
from test_tunnels import binding
from orangespace_node.tunnels import TunnelBody


@pytest.mark.parametrize('cleanup_fault', [None, 'signal', 'wait'])
@pytest.mark.parametrize('renew', [False, True])
@pytest.mark.parametrize('newer', [False, True])
def test_busy_final_publication_exact_owner(clock_manager, monkeypatch, renew, newer, cleanup_fault):
    manager, current, clock, processes = clock_manager
    clock.cost = 0
    deadline = clock.mono + 20
    original_start = manager._start
    monkeypatch.setattr(manager, '_start', lambda reply, deadline=None: original_start(reply))
    a = TunnelBody(**binding())
    reply = manager.create(current, a, deadline)
    if renew:
        reply = manager.renew(current, a.tunnel_id, deadline)
    child = processes[0]
    exact_pidfd = None
    fault_enabled = [True]
    if cleanup_fault and not newer:
        # MODEL signal/wait faults, not real kernel failures or real child PIDs.
        import os
        import subprocess
        from orangespace_node import tunnels
        child.pidfd = os.open('/dev/null', os.O_RDONLY)
        exact_pidfd = child.pidfd
        def model_signal(fd, sig):
            assert fd == exact_pidfd
            if fault_enabled[0] and cleanup_fault == 'signal':
                raise OSError('model signal fault')
            child.stopped = True
        def model_wait(timeout):
            if fault_enabled[0] and cleanup_fault == 'wait':
                raise subprocess.TimeoutExpired('model child', timeout)
            assert child.stopped
            return 0
        child.wait = model_wait
        original_stop = manager._stop
        def stop(process):
            if process is child:
                return type(manager)._stop(manager, process)
            return original_stop(process)
        monkeypatch.setattr(tunnels.signal, 'pidfd_send_signal', model_signal)
        monkeypatch.setattr(manager, '_stop', stop)
    old_deadline = manager.leases[a.tunnel_id].deadline
    old_expiry = manager.leases[a.tunnel_id].reply['expires_at']
    if newer:
        # Frozen clock deliberately gives identical numeric metadata.
        _, snapshot = manager.renewal_snapshot(current, a.tunnel_id)
        manager.renew(current, a.tunnel_id, deadline)
        assert manager.leases[a.tunnel_id].deadline == old_deadline
        assert manager.leases[a.tunnel_id].reply['expires_at'] == old_expiry
        with pytest.raises(HTTPException) as stale:
            manager.renew(current, a.tunnel_id, deadline, snapshot)
        assert stale.value.status_code == 409
        with pytest.raises(HTTPException) as stale:
            manager.permit_reply(current, reply, deadline)
        assert stale.value.status_code == 409
        assert not processes[0].stopped
    entered, release, busy = Event(), Event(), Event()
    real_lock = manager.lock
    class ObservedLock:
        def acquire(self, *args, **kwargs):
            acquired = real_lock.acquire(*args, **kwargs)
            if not acquired:
                busy.set()
            return acquired
        def release(self):
            real_lock.release()
        def __enter__(self):
            real_lock.acquire()
            return self
        def __exit__(self, *args):
            real_lock.release()
    monkeypatch.setattr(manager, 'lock', ObservedLock())
    b = TunnelBody(**binding())
    def slow_start(reply, deadline=None):
        entered.set()
        assert release.wait(3)
        return original_start(reply)
    monkeypatch.setattr(manager, '_start', slow_start)
    with ThreadPoolExecutor(2) as pool:
        second = pool.submit(manager.create, current, b, deadline)
        assert entered.wait(3)
        final = pool.submit(manager.permit_reply, current, reply, deadline)
        try:
            assert busy.wait(3), 'real operation acquire did not time out'
        finally:
            release.set()
        second.result(3)
        with pytest.raises(HTTPException) as caught:
            final.result(3)
        if cleanup_fault and not newer:
            assert a.tunnel_id not in manager.leases
            assert manager.children[child.pid] is child
            assert child.pidfd == exact_pidfd and manager.failed
            assert b.tunnel_id in manager.leases and not processes[1].stopped
            fault_enabled[0] = False
            with manager.lock:
                manager._reap()
            assert child.pid not in manager.children and child.pidfd is None
            assert child.stopped and manager.failed
            assert b.tunnel_id in manager.leases and not processes[1].stopped
        assert caught.value.status_code == 429
        assert caught.value.detail == 'tunnel service busy'
    assert b.tunnel_id in manager.leases
    assert not processes[1].stopped and processes[1].pid in manager.children
    if newer:
        assert a.tunnel_id in manager.leases
        assert not processes[0].stopped and processes[0].pid in manager.children
    else:
        assert a.tunnel_id not in manager.leases
        assert processes[0].stopped and processes[0].pid not in manager.children
