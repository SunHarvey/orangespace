"""Single-worker foreground Linux node, selected by a protected JSON path."""
import argparse
from contextlib import asynccontextmanager
from dataclasses import dataclass
import sys
import json
import os
import stat
from pathlib import Path
from uuid import UUID
import ipaddress


@dataclass(frozen=True, repr=False)
class RuntimeProfile:
    node_id: UUID
    data_root: Path
    database_config: Path
    tunnel_config: Path | None
    federation_config: Path | None
    host: str = "127.0.0.1"
    port: int = 19091
    tls_host: str | None = None
    tls_port: int | None = None
    tls_certificate: Path | None = None
    tls_private_key: Path | None = None
    deployment_mode: str | None = None


def load_profile(path: str | Path) -> RuntimeProfile:
    def members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        if not Path(path).is_absolute():
            raise ValueError
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_uid not in (0, os.geteuid()) or info.st_nlink != 1):
                raise ValueError
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=members)
        required = {"schema", "nodeUUID", "dataRoot", "dbConfig"}
        allowed = required | {"tunnelConfig", "federationConfig", "listenHost", "listenPort",
                              "tlsListenHost", "tlsListenPort", "tlsCertificate", "tlsPrivateKey", "deploymentMode"}
        if not isinstance(value, dict) or not required <= set(value) <= allowed:
            raise ValueError
        if type(value["schema"]) is not int or value["schema"] != 1:
            raise ValueError
        if "deploymentMode" in value and (type(value["deploymentMode"]) is not str or value["deploymentMode"] != "managed-local"):
            raise ValueError
        for key in ("dataRoot", "dbConfig", "tunnelConfig", "federationConfig"):
            item = value.get(key)
            if item is None and key in ("tunnelConfig", "federationConfig"):
                continue
            if not isinstance(item, str) or not Path(item).is_absolute() or "\x00" in item:
                raise ValueError
        port = value.get("listenPort", 19091)
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError
        if value.get("listenHost", "127.0.0.1") != "127.0.0.1":
            raise ValueError
        tls_host = tls_port = tls_certificate = tls_private_key = None
        if any(key in value for key in ("tlsListenHost", "tlsListenPort", "tlsCertificate", "tlsPrivateKey")):
            tls_port = value.get("tlsListenPort")
            tls_host = value.get("tlsListenHost", "127.0.0.1")
            if type(tls_port) is not int or not 1024 <= tls_port <= 65535 or tls_port == port:
                raise ValueError
            if type(tls_host) is not str:
                raise ValueError
            address = ipaddress.ip_address(tls_host)
            if not (address.is_loopback or address.is_private) or address.is_unspecified or address.is_multicast or address.is_link_local:
                raise ValueError
            for key in ("tlsCertificate", "tlsPrivateKey"):
                if type(value.get(key)) is not str or not Path(value[key]).is_absolute() or "\x00" in value[key]:
                    raise ValueError
            tls_certificate, tls_private_key = Path(value["tlsCertificate"]), Path(value["tlsPrivateKey"])
        node_id = UUID(value["nodeUUID"])
        if str(node_id) != value["nodeUUID"] or node_id.int == 0:
            raise ValueError
        return RuntimeProfile(
            node_id=node_id, data_root=Path(value["dataRoot"]),
            database_config=Path(value["dbConfig"]),
            tunnel_config=Path(value["tunnelConfig"]) if value.get("tunnelConfig") else None,
            federation_config=Path(value["federationConfig"]) if value.get("federationConfig") else None,
            port=port, deployment_mode=value.get("deploymentMode"),
            tls_host=tls_host, tls_port=tls_port,
            tls_certificate=tls_certificate, tls_private_key=tls_private_key,
        )
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        raise ValueError("invalid protected node runtime profile") from None


def build_app(profile: RuntimeProfile):
    from orangespace_common.database import load_database_url
    from .app import create_app
    from .config import Settings

    settings = Settings(
        node_id=profile.node_id, data_root=profile.data_root,
        database_url=load_database_url(profile.database_config),
        tunnel_config=profile.tunnel_config, federation_config=profile.federation_config,
        deployment_mode=profile.deployment_mode,
    )
    app = create_app(settings)
    original = app.router.lifespan_context

    @asynccontextmanager
    async def private_lifespan(application):
        try:
            async with original(application):
                # The TUIC HTTP probe reaches this SAME app/manager/lifespan.
                tunnel = application.state.tunnels.config
                if tunnel is not None and tunnel.probe_port != profile.port:
                    raise ValueError("probe port mismatch")
                yield
        except Exception:
            # Uvicorn formats lifespan tracebacks. Never expose DB/config errors.
            raise RuntimeError("node runtime failed (startup/shutdown)") from None

    app.router.lifespan_context = private_lifespan
    return app


async def serve_dual(profile: RuntimeProfile):
    """One Node lifespan/manager, loopback probe and verified-TLS API listeners."""
    import asyncio
    from contextlib import contextmanager
    import signal
    import uvicorn
    from typing import Any

    if profile.tls_port is None or profile.tls_host is None or profile.tls_certificate is None or profile.tls_private_key is None:
        raise ValueError("TLS listener profile required")

    class Server(uvicorn.Server):
        @contextmanager
        def capture_signals(self):
            # The owning runtime handles signals for BOTH listeners together.
            yield

    app = build_app(profile)
    common: dict[str, Any] = dict(lifespan="off", access_log=False, proxy_headers=False,
                  server_header=False, timeout_graceful_shutdown=30)
    servers = [Server(uvicorn.Config(app, host=profile.host, port=profile.port, **common)),
               Server(uvicorn.Config(app, host=profile.tls_host, port=profile.tls_port,
                                     ssl_certfile=str(profile.tls_certificate),
                                     ssl_keyfile=str(profile.tls_private_key), **common))]
    loop = asyncio.get_running_loop()
    stopped = False
    tasks = []

    def stop():
        nonlocal stopped
        stopped = True
        for server in servers:
            server.should_exit = True

    async def run(server):
        try:
            await server.serve()
        except SystemExit:
            # Uvicorn uses sys.exit on bind failure; do not strand the other task.
            raise RuntimeError("node listener startup failed") from None

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)
    try:
        async with app.router.lifespan_context(app):
            if stopped:
                return
            listeners_completed_normally = False
            try:
                tasks = [asyncio.create_task(run(server)) for server in servers]
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                if not stopped:
                    raise RuntimeError("node listener exited unexpectedly")
                listeners_completed_normally = True
            finally:
                stop()
                if tasks:
                    done, pending = await asyncio.wait(tasks, timeout=35)
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    if pending and listeners_completed_normally:
                        raise RuntimeError("node listener shutdown incomplete")
                    if listeners_completed_normally and any(
                        task.cancelled() or task.exception() is not None for task in done
                    ):
                        raise RuntimeError("node listener shutdown failed") from None
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Linux node foreground runtime; credentials stay in protected files")
    parser.add_argument("--profile", required=True, help="absolute protected JSON profile path")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    admin = commands.add_parser("admin", help="existing node CLI using profile-selected paths")
    admin.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if "ORANGESPACE_DATABASE_URL" in os.environ:
            raise ValueError("credential environment is forbidden")
        profile = load_profile(args.profile)
        if args.command == "admin":
            if profile.deployment_mode == "managed-local":
                parser.error("managed-local admin is unsupported by the legacy Node CLI; use explicit migration tooling")
            from .cli import main as node_cli

            keys = ("ORANGESPACE_NODE_ID", "ORANGESPACE_DATA_ROOT", "ORANGESPACE_DATABASE_CONFIG",
                    "ORANGESPACE_TUNNEL_CONFIG", "ORANGESPACE_FEDERATION_CONFIG")
            previous = {key: os.environ.get(key) for key in keys}
            old_argv = sys.argv
            try:
                values = (str(profile.node_id), str(profile.data_root), str(profile.database_config),
                          str(profile.tunnel_config) if profile.tunnel_config else None,
                          str(profile.federation_config) if profile.federation_config else None)
                for key, value in zip(keys, values):
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
                sys.argv = ["orangespace-node", *args.arguments]
                node_cli()
            finally:
                sys.argv = old_argv
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
        else:
            import uvicorn
            if profile.tls_port is not None:
                import asyncio
                asyncio.run(serve_dual(profile))
            else:
                uvicorn.run(build_app(profile), host=profile.host, port=profile.port,
                            workers=1, access_log=False, proxy_headers=False,
                            server_header=False, timeout_graceful_shutdown=30)
    except Exception:
        print("node runtime failed; check protected profile, database migration, and filesystem permissions", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
