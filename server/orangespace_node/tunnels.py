"""Single-owner, memory-only lease credentials and dedicated Linux TUIC children.

The administrator must run exactly one worker inside a systemd KillMode=control-group
unit: process-local cleanup cannot survive SIGKILL of the API itself.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
from fractions import Fraction
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import secrets
import selectors
import signal
import stat
import subprocess
import threading
import time
from uuid import UUID, uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import IntegrityError

from .database import AccessSession, TunnelGrant, TunnelGeneration, TunnelTombstone, User


def canonical_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
        if str(parsed) == value and parsed.int:
            return value
    except (ValueError, TypeError, AttributeError):
        pass
    raise ValueError("invalid UUID")


class TunnelBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    sandbox_id: str
    generation: int = Field(ge=1, le=2**53 - 1)
    tunnel_id: str

    @field_validator("sandbox_id", "tunnel_id")
    @classmethod
    def valid_uuid(cls, value):
        return canonical_uuid(value)


class EmptyBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def protected_open(value: str | Path, limit: int = 65536) -> int:
    """Root-controlled, no symlinks, no group/other writes, bounded regular file.

    Use directory descriptors for every component: no validation/reopen race.
    Root is the trusted administrator; API users never select these paths.
    """
    path = Path(value)
    if not path.is_absolute() or any(p in (".", "..") for p in path.parts):
        raise ValueError("unprotected runtime file")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for i, part in enumerate(path.parts[1:]):
            last = i == len(path.parts) - 2
            nxt = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (0 if last else os.O_DIRECTORY), dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("unprotected runtime file")
            if last and (not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_nlink != 1):
                raise ValueError("invalid runtime file")
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    executable: str
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    certificate: str
    private_key: str
    endpoint_ip: str
    listen_ip: str
    tls_server_name: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    port_start: int = Field(ge=1024, le=65535)
    port_end: int = Field(ge=1024, le=65535)
    max_leases: int = Field(ge=1, le=128)
    lease_seconds: int = Field(ge=1, le=30)
    startup_timeout: float = Field(ge=0.1, le=5)
    probe_port: int = Field(ge=1, le=65535)
    dns_port: int = Field(ge=1, le=65535)
    lock_file: str

    @field_validator("endpoint_ip", "listen_ip")
    @classmethod
    def literal_ip(cls, value):
        ipaddress.ip_address(value)
        return value


class SecretText(str):
    """Explicit serialization is allowed; incidental repr/debug output is not."""
    def __repr__(self):
        return "<redacted>"


class RuntimeProcess(subprocess.Popen):
    pidfd: int | None = None
    tunnel_id: str | None = None


@dataclass(repr=False)
class Lease:
    user_id: str
    session_digest: str
    grant_epoch: int
    deadline: float
    reply: dict = field(repr=False)
    process: RuntimeProcess = field(repr=False)
    authority: object = field(default_factory=object, repr=False)


class PermitReply(dict):
    """Internal handoff; ownership is never a public HTTP field."""
    def __init__(self, reply, lease):
        super().__init__(reply)
        self.owner = (lease, lease.authority)


class TunnelManager:
    def __init__(self, database, settings):
        self.db, self.node_id = database, str(settings.node_id)
        self.config = None
        self.failed = False
        self.executable_fd = self.lock_fd = None
        self.leases: dict[str, Lease] = {}
        self.children: dict[int, RuntimeProcess] = {}
        self.lock = threading.RLock()
        self.stopping = threading.Event()
        self.thread = None
        try:
            if settings.tunnel_config is not None:
                if resource.getrlimit(resource.RLIMIT_CORE)[0] != 0:
                    raise ValueError("API core dumps must be disabled")
                fd = protected_open(settings.tunnel_config)
                try:
                    self.config = RuntimeConfig.model_validate_json(os.read(fd, 65537))
                finally:
                    os.close(fd)
                c = self.config
                if not 0 <= c.port_end - c.port_start < 256 or c.max_leases > c.port_end - c.port_start + 1:
                    raise ValueError("invalid runtime allocation bounds")
                self.executable_fd = protected_open(c.executable, 100 * 1024 * 1024)
                with os.fdopen(os.dup(self.executable_fd), "rb") as binary:
                    if hashlib.file_digest(binary, "sha256").hexdigest() != c.executable_sha256:
                        raise ValueError("runtime hash mismatch")
                for path in (c.certificate, c.private_key):
                    fd = protected_open(path)
                    try:
                        if path == c.private_key and os.fstat(fd).st_mode & 0o007:
                            raise ValueError("TLS key must not be public")
                    finally:
                        os.close(fd)
                self.lock_fd = protected_open(c.lock_file)
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.thread = threading.Thread(target=self._watch, daemon=True, name="tunnel-reaper")
                self.thread.start()
        except Exception:
            self.close()
            raise ValueError("invalid protected tunnel configuration") from None

    @contextmanager
    def operation(self):
        if not self.lock.acquire(timeout=0.1):
            raise HTTPException(429, "tunnel service busy")
        try:
            yield
        finally:
            self.lock.release()

    def _authority(self, user_id, digest):
        with self.db.session() as session:
            access = session.get(AccessSession, digest)
            user = session.get(User, user_id)
            grant = session.get(TunnelGrant, user_id)
            if not access or access.user_id != user_id or access.revoked_at is not None or access.expires_at <= time.time() or not user or not user.enabled:
                raise HTTPException(401, "authentication required")
            if not grant or not grant.enabled:
                raise HTTPException(403, "tunnel grant required")
            return access.expires_at, grant.epoch

    def _listener(self, process, port):
        """Check this exact child's socket inode, not another process's port."""
        try:
            sockets = {os.readlink(p) for p in Path(f"/proc/{process.pid}/fd").iterdir()}
            for table in ("udp", "udp6"):
                for row in Path(f"/proc/{process.pid}/net/{table}").read_text().splitlines()[1:]:
                    fields = row.split()
                    if int(fields[1].split(":")[1], 16) == port and f"socket:[{fields[9]}]" in sockets:
                        return True
        except (OSError, ValueError, IndexError):
            pass
        return False

    def _start(self, reply, authority_deadline=None):
        c = self.config
        assert c is not None and self.executable_fd is not None
        document = {"log": {"disabled": True}, "inbounds": [{"type": "tuic", "listen": c.listen_ip,
            "listen_port": reply["endpoint_port"], "users": [{"uuid": reply["tuic_uuid"], "password": reply["tuic_password"]}],
            "zero_rtt_handshake": False, "tls": {"enabled": True, "certificate_path": c.certificate, "key_path": c.private_key}}],
            "dns": {"servers": [{"type": "udp", "tag": "node-resolver", "server": "127.0.0.1", "server_port": c.dns_port}], "final": "node-resolver"},
            "outbounds": [{"type": "direct", "tag": "node-egress"}],
            "route": {"rules": [
                {"ip_cidr": ["127.0.0.1/32"], "port": c.probe_port, "network": "tcp", "action": "route", "outbound": "node-egress"},
                {"port": 53, "action": "hijack-dns"},
                {"action": "resolve"},
                {"ip_is_private": True, "action": "reject"},
                {"ip_cidr": ["0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4", "::/128", "ff00::/8"], "action": "reject"}],
                "default_domain_resolver": "node-resolver", "final": "node-egress"}}
        if authority_deadline is not None and time.monotonic() >= authority_deadline:
            raise HTTPException(410, "tunnel inactive")
        process = RuntimeProcess([f"/proc/self/fd/{self.executable_fd}", "run", "-c", "stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={}, close_fds=True, pass_fds=(self.executable_fd,), start_new_session=True, cwd="/")
        assert process.stdin is not None
        self.children[process.pid] = process
        process.tunnel_id = reply["tunnel_id"]
        process.pidfd = None
        try:
            # Pin before any poll/reap and before sending the first secret byte.
            process.pidfd = os.pidfd_open(process.pid)
            resource.prlimit(process.pid, resource.RLIMIT_CORE, (0, 0))
            payload = memoryview(json.dumps(document).encode())
            os.set_blocking(process.stdin.fileno(), False)
            deadline = time.monotonic() + c.startup_timeout
            if authority_deadline is not None:
                deadline = min(deadline, authority_deadline)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin, selectors.EVENT_WRITE)
                while payload:
                    if time.monotonic() >= deadline or process.poll() is not None:
                        raise RuntimeError("runtime startup failed")
                    if selector.select(max(0, deadline - time.monotonic())):
                        payload = payload[os.write(process.stdin.fileno(), payload):]
            process.stdin.close()
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                if self._listener(process, reply["endpoint_port"]):
                    return process
                time.sleep(0.01)
            raise RuntimeError("runtime startup failed")
        except BaseException:
            process.stdin.close()
            self._stop(process)
            raise

    def _stop(self, process):
        # The pinned trusted foreground sing-box does not spawn child programs.
        # Signal a stable kernel handle, never a reused PID/process-group number.
        try:
            if process.pidfd is not None:
                try:
                    signal.pidfd_send_signal(process.pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                # pidfd acquisition failed before any credential was delivered.
                process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            # Every caller, including synchronous startup/delete/supersede,
            # must preserve exact ownership and permanently stop allocations.
            self.failed = True
            raise HTTPException(503, "tunnel cleanup incomplete") from None
        if process.pidfd is not None:
            os.close(process.pidfd)
            process.pidfd = None
        self.children.pop(process.pid, None)

    def _remaining_ttl_ms(self, deadline, expires_at, session_expiry):
        # Subtract exact represented clock values before flooring: float
        # multiplication can otherwise round a sub-millisecond budget up.
        wall = Fraction(time.time())
        mono = Fraction(time.monotonic())
        remaining = min(Fraction(deadline) - mono, Fraction(expires_at) - wall,
                        Fraction(session_expiry) - wall, Fraction(30))
        milliseconds = remaining * 1000
        ttl = milliseconds.numerator // milliseconds.denominator
        if ttl <= 0:
            raise HTTPException(410, "tunnel inactive")
        return ttl

    def create(self, current, body, permit_deadline=None):
        with self.operation():
            expiry, epoch = self._authority(current.user_id, current.token_digest)
            if permit_deadline is not None:
                self._remaining_ttl_ms(permit_deadline, expiry, current.expires_at)
            if self.config is None or self.stopping.is_set() or self.failed:
                raise HTTPException(503, "tunnel runtime disabled")
            self._reap()
            if self.failed:
                raise HTTPException(503, "tunnel cleanup incomplete")
            c = self.config
            if len(self.children) >= c.max_leases:
                raise HTTPException(429, "tunnel capacity exhausted")
            try:
                with self.db.session() as session:
                    if session.get(TunnelTombstone, body.tunnel_id):
                        raise HTTPException(409, "stale tunnel binding")
                    key = (current.user_id, body.sandbox_id)
                    generation = session.get(TunnelGeneration, key)
                    if generation and body.generation <= generation.generation:
                        raise HTTPException(409, "stale tunnel binding")
                    if generation:
                        generation.generation = body.generation
                    else:
                        session.add(TunnelGeneration(user_id=current.user_id, sandbox_id=body.sandbox_id, generation=body.generation))
                    session.add(TunnelTombstone(tunnel_id=body.tunnel_id, user_id=current.user_id,
                        session_digest=current.token_digest, sandbox_id=body.sandbox_id, generation=body.generation))
            except IntegrityError:
                raise HTTPException(409, "stale tunnel binding") from None
            # Superseding generation invalidates the old listener before starting.
            for key, lease in list(self.leases.items()):
                if lease.user_id == current.user_id and lease.reply["sandbox_id"] == body.sandbox_id:
                    self._remove(key)
            used = {lease.reply["endpoint_port"] for lease in self.leases.values()}
            port = next((p for p in range(c.port_start, c.port_end + 1) if p not in used), None)
            if port is None:
                raise HTTPException(429, "tunnel capacity exhausted")
            reply = {**body.model_dump(), "user_id": current.user_id, "node_id": self.node_id,
                "expires_at": min(expiry, int(time.time()) + c.lease_seconds), "endpoint_ip": c.endpoint_ip,
                "endpoint_port": port, "tls_server_name": c.tls_server_name, "tuic_uuid": str(uuid4()),
                "tuic_password": secrets.token_urlsafe(32), "probe_host": "127.0.0.1", "probe_port": c.probe_port,
                "probe_request": secrets.token_urlsafe(32), "probe_response": secrets.token_urlsafe(32)}
            for key in ("tuic_uuid", "tuic_password", "probe_request", "probe_response"):
                reply[key] = SecretText(reply[key])
            deadline = time.monotonic() + max(0, min(c.lease_seconds, reply["expires_at"] - time.time()))
            if permit_deadline is not None:
                deadline = min(deadline, permit_deadline)
            process = None
            try:
                self._remaining_ttl_ms(deadline, reply["expires_at"], expiry)
                process = self._start(reply) if permit_deadline is None else self._start(reply, deadline)
                actual_expiry, actual_epoch = self._authority(current.user_id, current.token_digest)
                if epoch != actual_epoch or reply["expires_at"] <= time.time() or time.monotonic() >= deadline:
                    raise HTTPException(409, "tunnel authorization changed")
                reply["expires_at"] = min(reply["expires_at"], actual_expiry)
                reply["lease_schema"] = 2
                reply["remaining_ttl_ms"] = self._remaining_ttl_ms(deadline, reply["expires_at"], actual_expiry)
                lease = Lease(current.user_id, current.token_digest, epoch, deadline, reply, process)
                result = PermitReply(reply, lease) if permit_deadline is not None else dict(reply)
                self.leases[body.tunnel_id] = lease
                return result
            except BaseException as error:
                if process:
                    self._stop(process)
                if isinstance(error, HTTPException):
                    raise
                if isinstance(error, Exception):
                    raise HTTPException(503, "tunnel runtime failed") from None
                raise

    def _valid(self, lease):
        expiry, epoch = self._authority(lease.user_id, lease.session_digest)
        with self.db.session() as session:
            generation = session.get(TunnelGeneration, (lease.user_id, lease.reply["sandbox_id"]))
            if not generation or generation.generation != lease.reply["generation"]:
                raise HTTPException(410, "tunnel inactive")
        if lease.reply["expires_at"] <= time.time() or time.monotonic() >= lease.deadline or epoch != lease.grant_epoch or lease.process.poll() is not None:
            raise HTTPException(410, "tunnel inactive")
        return expiry

    def _remove(self, tunnel_id):
        self._remove_many([tunnel_id])

    def _remove_many(self, tunnel_ids, pending=()):
        # Revoke the whole selection before any fallible cleanup. children
        # retains each exact process/pidfd, independently of active authority.
        processes = [self.leases.pop(key).process for key in tunnel_ids]
        processes.extend(pending)
        error = None
        for process in processes:
            try:
                self._stop(process)
            except HTTPException as caught:
                error = caught
        if error is not None:
            raise error

    def logout(self, current):
        from .auth import revoke
        # Revoke authority before waiting for startup: a child already being
        # configured must fail its post-spawn check, never publish a late grant.
        revoke(self.db, current.token_digest)
        with self.lock:
            # The reaper may have revoked a lease while logout waited for the
            # lock. Its still-owned child remains part of this session's cleanup.
            active = {lease.process.pid for lease in self.leases.values()}
            pending = []
            with self.db.session() as session:
                for pid, process in self.children.items():
                    if pid not in active:
                        tombstone = session.get(TunnelTombstone, process.tunnel_id)
                        if tombstone and tombstone.session_digest == current.token_digest:
                            pending.append(process)
            self._remove_many([tunnel_id for tunnel_id, lease in self.leases.items()
                if lease.session_digest == current.token_digest], pending)

    def renewal_snapshot(self, current, tunnel_id):
        with self.operation():
            lease = self.leases.get(tunnel_id)
            if not lease or lease.user_id != current.user_id or lease.session_digest != current.token_digest:
                raise HTTPException(404, "tunnel not found")
            self._valid(lease)
            body = TunnelBody(tunnel_id=tunnel_id, sandbox_id=lease.reply["sandbox_id"], generation=lease.reply["generation"])
            return body, (lease, lease.deadline, lease.reply["expires_at"], lease.grant_epoch, lease.authority)

    def permit_reply(self, current, reply, deadline):
        """Final publication fence; never re-anchor the consumed permit."""
        owner = getattr(reply, 'owner', None)
        try:
            with self.operation():
                lease = self.leases.get(reply['tunnel_id'])
                if not lease or not owner or lease is not owner[0] or lease.authority is not owner[1] or lease.user_id != current.user_id or lease.session_digest != current.token_digest or lease.deadline > deadline or lease.reply['expires_at'] != reply['expires_at']:
                    raise HTTPException(409, 'tunnel authority changed')
                expiry = self._valid(lease)
                reply['remaining_ttl_ms'] = self._remaining_ttl_ms(min(deadline, lease.deadline), lease.reply['expires_at'], expiry)
                return dict(reply)
        except BaseException:
            # Admission can fail before entering operation(). Cleanup waits for
            # the existing mutation owner, then compares exact authority, not
            # tuple/deadline equality. A later renewal must remain untouched.
            with self.lock:
                lease = self.leases.get(reply['tunnel_id'])
                if lease and owner and lease is owner[0] and lease.authority is owner[1]:
                    try:
                        self._remove(reply['tunnel_id'])
                    except HTTPException:
                        # _stop latched failure and retained exact retry ownership;
                        # cleanup must not replace the publication error.
                        pass
            raise

    def renew(self, current, tunnel_id, permit_deadline=None, snapshot=None):
        with self.operation():
            lease = self.leases.get(tunnel_id)
            if not lease or lease.user_id != current.user_id or lease.session_digest != current.token_digest:
                raise HTTPException(404, "tunnel not found")
            if snapshot is not None and (lease is not snapshot[0] or (lease.deadline, lease.reply["expires_at"], lease.grant_epoch) != snapshot[1:4] or lease.authority is not snapshot[4]):
                raise HTTPException(409, "tunnel authority changed")
            if permit_deadline is not None:
                self._remaining_ttl_ms(permit_deadline, current.expires_at, current.expires_at)
            try:
                expiry = self._valid(lease)
            except HTTPException:
                self._remove(tunnel_id)
                raise HTTPException(410, "tunnel inactive") from None
            assert self.config is not None
            new_expiry = min(expiry, int(time.time()) + self.config.lease_seconds)
            new_deadline = time.monotonic() + max(0, min(self.config.lease_seconds, new_expiry - time.time()))
            if permit_deadline is not None:
                new_deadline = min(new_deadline, permit_deadline)
            try:
                ttl = self._remaining_ttl_ms(new_deadline, new_expiry, expiry)
                if time.monotonic() >= lease.deadline or time.time() >= lease.reply["expires_at"]:
                    raise HTTPException(410, "tunnel inactive")
            except HTTPException:
                self._remove(tunnel_id)
                raise
            authority = object()
            reply = {"tunnel_id": tunnel_id, "expires_at": new_expiry, "node_id": self.node_id,
                     "lease_schema": 2, "remaining_ttl_ms": ttl}
            # Allocate the provisional return before changing live authority.
            if permit_deadline is not None:
                result = PermitReply(reply, lease)
                result.owner = (lease, authority)
            else:
                result = reply
            lease.reply["expires_at"] = new_expiry
            lease.deadline = new_deadline
            lease.authority = authority
            return result

    def delete(self, current, tunnel_id):
        with self.operation():
            with self.db.session() as session:
                tombstone = session.get(TunnelTombstone, tunnel_id)
                if not tombstone or tombstone.user_id != current.user_id or tombstone.session_digest != current.token_digest:
                    raise HTTPException(404, "tunnel not found")
            if tunnel_id in self.leases:
                self._remove(tunnel_id)
            else:
                # Authorization may already be gone while exact child cleanup
                # is pending. An idempotent DELETE must not falsely report it
                # reaped; retry only the owned process for this tombstone.
                for process in list(self.children.values()):
                    if process.tunnel_id == tunnel_id:
                        self._stop(process)

    def probe(self, tunnel_id, secret):
        with self.operation():
            lease = self.leases.get(tunnel_id)
            if not lease or not isinstance(secret, str) or not secret.isascii() or len(secret) != 43 or not secrets.compare_digest(secret, lease.reply["probe_request"]):
                raise HTTPException(404, "tunnel not found")
            try:
                self._valid(lease)
            except HTTPException:
                self._remove(tunnel_id)
                raise HTTPException(404, "tunnel not found") from None
            return {"tunnel_id": tunnel_id, "proof": lease.reply["probe_response"]}

    def _reap(self):
        for tunnel_id, lease in list(self.leases.items()):
            try:
                self._valid(lease)
            except Exception:
                try:
                    self._remove(tunnel_id)
                except HTTPException:
                    # _stop latched failure and retained ownership for retry.
                    pass
        active = {lease.process.pid for lease in self.leases.values()}
        for pid, process in list(self.children.items()):
            if pid not in active:
                try:
                    self._stop(process)
                except HTTPException:
                    pass

    def _watch(self):
        while not self.stopping.wait(0.2):
            with self.lock:
                self._reap()

    def close(self):
        with self.lock:
            self.leases.clear()
            error = None
            for process in list(self.children.values()):
                try:
                    self._stop(process)
                except HTTPException as caught:
                    error = caught
            if error is not None:
                # Keep the watcher and protected owner descriptors alive until
                # every uncertain child has actually been killed and reaped.
                raise error
            self.stopping.set()
            for fd in (self.lock_fd, self.executable_fd):
                if fd is not None:
                    os.close(fd)
            self.lock_fd = self.executable_fd = None
        if self.thread:
            self.thread.join()
