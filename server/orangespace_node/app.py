from contextlib import asynccontextmanager
import json
import re
import time
from typing import Annotated
from urllib.parse import quote

import anyio
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from . import __version__
from .auth import Identity, LoginLimiter, authenticate, login
from .config import Settings
from .database import Database
from .tunnels import EmptyBody, TunnelBody, TunnelManager, canonical_uuid
from .storage import FileReader, PersonalStorage, StorageError


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class DirectoryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=4096)


class DownloadResponse(StreamingResponse):
    """Own the descriptor even if sending headers fails before iteration starts."""
    def __init__(self, reader: FileReader, *args, **kwargs):
        self.reader = reader
        super().__init__(*args, **kwargs)

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                await run_in_threadpool(self.reader.close)


def unique_json(body):
    def members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=members)


async def small_json(request: Request, schema):
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 16 * 1024:
            raise HTTPException(413, "request body too large")
        body.extend(chunk)
    try:
        return schema.model_validate(unique_json(body))
    except (ValueError, ValidationError):
        # Do not echo invalid input: login bodies contain passwords.
        raise HTTPException(422, "invalid JSON request") from None


def identity(request: Request) -> Identity:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    fed = request.app.state.federation
    if fed is not None:
        # Authorization is bound to the server-matched endpoint, never the URL
        # (which includes deployment mount prefixes). Unknown routes fail closed.
        route = request.scope.get('route')
        endpoint = getattr(route, 'endpoint', None)
        policy = request.app.state.federation_policies.get((endpoint, request.method))
        if policy is None:
            raise HTTPException(403, 'federated authorization policy unavailable')
        if policy == 'lease-permit':
            request.state.permit_budget = request.scope['orangespace.operation_deadline']
            return fed.authenticate(token if scheme.lower() == 'bearer' else '', 'tunnel')
        scope = None if policy == 'identity' else policy
        return fed.authenticate(token if scheme.lower() == 'bearer' else '', scope)
    current = authenticate(request.app.state.database, token) if scheme.lower() == "bearer" else None
    if current is None:
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
    return current


def byte_range(value: str | None, size: int) -> tuple[int, int, int]:
    if value is None:
        return 0, size, 200
    match = re.fullmatch(r"bytes=([0-9]*)-([0-9]*)", value) if len(value) <= 128 else None
    if not match or not any(match.groups()) or size == 0:
        raise HTTPException(416, "invalid byte range", headers={"Content-Range": f"bytes */{size}"})
    left, right = match.groups()
    if not left:
        count = int(right)
        if count == 0:
            raise HTTPException(416, "invalid byte range", headers={"Content-Range": f"bytes */{size}"})
        start, end = max(size - count, 0), size - 1
    else:
        start, end = int(left), min(int(right), size - 1) if right else size - 1
    if start >= size or end < start:
        raise HTTPException(416, "invalid byte range", headers={"Content-Range": f"bytes */{size}"})
    return start, end - start + 1, 206


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.from_env()
    from .federation import Federation, ExchangeBody, load_config
    federation_config = load_config(config.federation_config, config.node_id) if config.federation_config is not None else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database = Database(config.database_url)
        storage = None
        tunnels = None
        try:
            # CLI init-db is recommended for deployment; this is idempotent for
            # the initial schema and convenient for local development.
            await run_in_threadpool(database.initialize)
            storage = await run_in_threadpool(PersonalStorage, config.data_root)
            tunnels = await run_in_threadpool(TunnelManager, database, config)
            app.state.tunnels = tunnels
            app.state.database = database
            app.state.federation = Federation(federation_config, database) if federation_config is not None else None
            app.state.storage = storage
            app.state.login_limiter = LoginLimiter(config.login_attempts, config.login_window_seconds)
            app.state.password_limiter = anyio.CapacityLimiter(4)
            app.state.upload_limiter = anyio.CapacityLimiter(8)
            yield
        finally:
            if tunnels:
                await run_in_threadpool(tunnels.close)
            if storage:
                storage.close()
            database.close()

    app = FastAPI(title="橙域 OrangeSpace Node", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def response_headers(request: Request, call_next):
        request.scope['orangespace.operation_deadline'] = time.monotonic() + 30
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-OrangeSpace-Node"] = str(config.node_id)
        return response

    @app.exception_handler(StorageError)
    async def storage_error(_request: Request, error: StorageError):
        return JSONResponse({"detail": error.detail}, status_code=error.status)

    @app.get("/healthz")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post('/federation/v1/sessions/exchange')
    async def exchange(request: Request):
        if app.state.federation is None:
            raise HTTPException(404, 'federation unavailable')
        body = await small_json(request, ExchangeBody)
        return await run_in_threadpool(app.state.federation.exchange, body)

    @app.post('/federation/v1/sessions/exchange-cleanup')
    async def exchange_cleanup(request: Request):
        if app.state.federation is None:
            raise HTTPException(404, 'federation unavailable')
        body = await small_json(request, ExchangeBody)
        return await run_in_threadpool(app.state.federation.cleanup, body)

    @app.post("/v1/auth/login")
    async def sign_in(request: Request):
        if app.state.federation is not None:
            raise HTTPException(403, 'local password login disabled')
        body = await small_json(request, LoginBody)
        peer = request.client.host if request.client else "unknown"
        limiter = app.state.login_limiter
        if not limiter.consume("peer:" + peer) or not limiter.consume("account:" + body.username.strip().lower()):
            raise HTTPException(429, "too many login attempts", headers={"Retry-After": str(config.login_window_seconds)})
        password_limiter = app.state.password_limiter
        try:
            password_limiter.acquire_nowait()
        except anyio.WouldBlock:
            raise HTTPException(429, "login service busy", headers={"Retry-After": "5"}) from None
        try:
            result = await run_in_threadpool(login, app.state.database, body.username, body.password, config.token_lifetime_seconds)
        finally:
            password_limiter.release()
        if result is None:
            raise HTTPException(401, "invalid username or password")
        token, expires = result
        return {"access_token": token, "token_type": "bearer", "expires_at": expires, "node_id": str(config.node_id)}

    @app.post("/v1/auth/logout", status_code=204)
    def sign_out(current: Annotated[Identity, Depends(identity)]):
        app.state.tunnels.logout(current)
        return Response(status_code=204)

    @app.get("/v1/session")
    def session_info(current: Annotated[Identity, Depends(identity)]):
        return {"user_id": current.user_id, "username": current.username, "node_id": str(config.node_id),
                "expires_at": current.expires_at}

    @app.post("/v1/tunnels")
    async def create_tunnel(request: Request, current: Annotated[Identity, Depends(identity)]):
        require_lease_schema(request)
        body = await small_json(request, TunnelBody)
        if app.state.federation is not None:
            deadline = await run_in_threadpool(app.state.federation.permit, current, body, 'create', request.state.permit_budget)
            reply = await run_in_threadpool(app.state.tunnels.create, current, body, deadline)
            return await run_in_threadpool(app.state.tunnels.permit_reply, current, reply, deadline)
        return await run_in_threadpool(app.state.tunnels.create, current, body)

    def require_lease_schema(request):
        if request.headers.getlist("x-orangespace-lease-schema") != ["2"]:
            raise HTTPException(426, "lease schema 2 required")

    def tunnel_identifier(value):
        try:
            return canonical_uuid(value)
        except ValueError:
            raise HTTPException(422, "invalid tunnel ID") from None

    @app.post("/v1/tunnels/{tunnel_id}/renew")
    async def renew_tunnel(tunnel_id: str, request: Request, current: Annotated[Identity, Depends(identity)]):
        require_lease_schema(request)
        # Bounded empty-body parser: absent bytes or exactly an empty JSON object.
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 16 * 1024:
                raise HTTPException(413, "request body too large")
            body.extend(chunk)
        if body:
            try:
                EmptyBody.model_validate(unique_json(body))
            except (ValueError, ValidationError):
                raise HTTPException(422, "invalid JSON request") from None
        tid = tunnel_identifier(tunnel_id)
        if app.state.federation is not None:
            binding, snapshot = await run_in_threadpool(app.state.tunnels.renewal_snapshot, current, tid)
            deadline = await run_in_threadpool(app.state.federation.permit, current, binding, 'renew', request.state.permit_budget)
            reply = await run_in_threadpool(app.state.tunnels.renew, current, tid, deadline, snapshot)
            return await run_in_threadpool(app.state.tunnels.permit_reply, current, reply, deadline)
        return await run_in_threadpool(app.state.tunnels.renew, current, tid)

    @app.delete("/v1/tunnels/{tunnel_id}", status_code=204)
    def delete_tunnel(tunnel_id: str, current: Annotated[Identity, Depends(identity)]):
        app.state.tunnels.delete(current, tunnel_identifier(tunnel_id))
        return Response(status_code=204)

    @app.post("/v1/tunnels/{tunnel_id}/probe")
    def tunnel_probe(tunnel_id: str, request: Request):
        runtime = app.state.tunnels.config
        local = tuple(request.scope.get("server") or ())
        proxy_headers = any(name == "forwarded" or name == "x-real-ip" or name.startswith("x-forwarded-") for name in request.headers)
        if runtime is None or not request.client or request.client.host != "127.0.0.1" or local != ("127.0.0.1", runtime.probe_port) or proxy_headers:
            raise HTTPException(404, "tunnel not found")
        if request.headers.get("authorization"):
            raise HTTPException(400, "probe uses separate authorization")
        return app.state.tunnels.probe(tunnel_identifier(tunnel_id), request.headers.get("x-orangespace-probe"))

    @app.get("/v1/me")
    def me(current: Annotated[Identity, Depends(identity)]):
        return {"user_id": current.user_id, "username": current.username, "node_id": str(config.node_id)}

    @app.get("/v1/files")
    def list_files(current: Annotated[Identity, Depends(identity)], path: str = Query(default="", max_length=4096)):
        return {"node_id": str(config.node_id), "path": path, "entries": app.state.storage.list(current.user_id, path)}

    @app.post("/v1/directories", status_code=201)
    async def create_directory(request: Request, current: Annotated[Identity, Depends(identity)]):
        body = await small_json(request, DirectoryBody)
        result = await run_in_threadpool(app.state.storage.mkdir, current.user_id, body.path)
        return {"node_id": str(config.node_id), "path": body.path, **result}

    @app.put("/v1/files/{path:path}", status_code=201)
    async def upload_file(request: Request, path: str, current: Annotated[Identity, Depends(identity)], overwrite: bool = False):
        length = request.headers.get("content-length")
        if length is not None:
            if not length.isascii() or not length.isdecimal() or len(length) > 20:
                raise HTTPException(400, "invalid content length")
            if int(length) > config.max_upload_bytes:
                raise HTTPException(413, "file exceeds node upload limit")
        limiter = app.state.upload_limiter
        try:
            limiter.acquire_nowait()
        except anyio.WouldBlock:
            raise HTTPException(429, "too many active uploads", headers={"Retry-After": "5"}) from None
        upload = None
        try:
            upload = await run_in_threadpool(app.state.storage.begin_upload, current.user_id, path, config.max_upload_bytes, overwrite)
            async for chunk in request.stream():
                await run_in_threadpool(upload.write, chunk)
            if length is not None and upload.size != int(length):
                raise HTTPException(400, "incomplete request body")
            result = await run_in_threadpool(upload.commit)
            return {"node_id": str(config.node_id), "path": path, **result}
        finally:
            with anyio.CancelScope(shield=True):
                if upload:
                    await run_in_threadpool(upload.close)
                limiter.release()

    @app.get("/v1/files/{path:path}")
    async def download_file(request: Request, path: str, current: Annotated[Identity, Depends(identity)]):
        reader = await run_in_threadpool(app.state.storage.read, current.user_id, path)
        try:
            start, count, status = byte_range(request.headers.get("range"), reader.info.st_size)
            if start:
                import os
                await run_in_threadpool(os.lseek, reader.fd, start, os.SEEK_SET)
        except BaseException:
            reader.close()
            raise

        async def chunks():
            remaining = count
            try:
                while remaining:
                    data = await run_in_threadpool(reader.read, min(remaining, 256 * 1024))
                    if not data:
                        break
                    remaining -= len(data)
                    yield data
            finally:
                with anyio.CancelScope(shield=True):
                    await run_in_threadpool(reader.close)

        headers = {"Content-Length": str(count), "Accept-Ranges": "bytes",
                   "Content-Disposition": "attachment; filename*=UTF-8''" + quote(path.rsplit("/", 1)[-1], safe="")}
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{start + count - 1}/{reader.info.st_size}"
        return DownloadResponse(reader, chunks(), status_code=status, media_type="application/octet-stream", headers=headers,
                                background=BackgroundTask(reader.close))

    @app.delete("/v1/files/{path:path}", status_code=204)
    def delete_file(path: str, current: Annotated[Identity, Depends(identity)]):
        app.state.storage.delete(current.user_id, path)
        return Response(status_code=204)

    app.state.federation_policies = {
        (sign_out, 'POST'): 'identity',
        (session_info, 'GET'): 'identity',
        (me, 'GET'): 'identity',
        (create_tunnel, 'POST'): 'lease-permit',
        (renew_tunnel, 'POST'): 'lease-permit',
        (delete_tunnel, 'DELETE'): 'identity',
        (list_files, 'GET'): 'files.read',
        (download_file, 'GET'): 'files.read',
        (create_directory, 'POST'): 'files.write',
        (upload_file, 'PUT'): 'files.write',
        (delete_file, 'DELETE'): 'files.write',
    }
    return app
