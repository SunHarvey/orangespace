"""Same-origin console files: explicit SPA routes and public build assets only."""
from pathlib import Path
import re
from fastapi import HTTPException
from starlette.responses import FileResponse

SPA_PATHS = ('/', '/login', '/nodes', '/users', '/enrollments', '/grants',
             '/sessions', '/sandboxes', '/leases', '/audit-events')
ASSET = re.compile(r'[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8,}\.(?:js|css|png|svg|ico|woff2?)')


def install_console(app, dist=None):
    @app.get('/healthz')
    async def healthz():
        # Process readiness after create_app's migration check, not DB liveness.
        return {'status': 'ok'}

    if dist is None:
        return
    root = Path(dist).resolve(strict=True)
    index = root / 'index.html'
    if not root.is_dir() or not index.is_file() or index.is_symlink():
        raise ValueError('console build missing')

    async def console_index():
        return FileResponse(index, headers={'Cache-Control': 'no-store'})

    for path in SPA_PATHS:
        app.add_api_route(path, console_index, methods=['GET'], include_in_schema=False)

    @app.get('/assets/{name}')
    async def asset(name: str):
        candidate = root / 'assets' / name
        if (not ASSET.fullmatch(name) or (root / 'assets').is_symlink()
                or candidate.is_symlink() or not candidate.is_file()
                or not candidate.resolve().is_relative_to(root)):
            raise HTTPException(404)
        return FileResponse(candidate, headers={'Cache-Control': 'no-store'})
