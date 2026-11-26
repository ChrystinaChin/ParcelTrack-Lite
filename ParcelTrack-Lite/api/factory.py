"""Create internal-only FastAPI service. PHP is the public web entrypoint."""
import hmac
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from api.core import ROOT, initialize, load_environment
from api.modules import m1_auth, m2_parcels, m3_delivery


def create_app(settings: dict | None = None) -> FastAPI:
    load_environment()
    settings = settings or {}
    key = settings.get('INTERNAL_KEY', os.environ.get('PARCELTRACK_INTERNAL_KEY', ''))
    if len(key) < 32:
        raise RuntimeError('Set PARCELTRACK_INTERNAL_KEY (at least 32 characters) in .env')
    database = str(settings.get('DATABASE', os.environ.get('PARCELTRACK_DB_PATH',
                                 str(ROOT / 'instance' / 'parceltrack.sqlite3'))))
    uploads = str(settings.get('UPLOAD_DIR', os.environ.get('PARCELTRACK_UPLOAD_DIR',
                                str(ROOT / 'instance' / 'uploads'))))
    upload_path = Path(uploads).resolve()
    if upload_path.is_relative_to((ROOT / 'php' / 'public').resolve()):
        raise RuntimeError('Proof uploads MUST be stored outside the PHP web root')
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        initialize(database)
        Path(uploads).mkdir(parents=True,exist_ok=True,mode=0o700)
        yield
    app = FastAPI(title='ParcelTrack Internal API',docs_url=None,redoc_url=None,
                  openapi_url=None,lifespan=lifespan)
    app.state.internal_key = key
    app.state.db_path = database
    app.state.upload_dir = uploads
    app.state.test_mode = bool(settings.get('TESTING', False))

    @app.middleware('http')
    async def internal_only(request: Request, call_next):
        client = request.client.host if request.client else ''
        if not app.state.test_mode and client not in ('127.0.0.1', '::1'):
            return JSONResponse({'detail':'Forbidden.'},status_code=403)
        supplied = request.headers.get('X-Internal-Key', '')
        if not hmac.compare_digest(supplied, app.state.internal_key):
            return JSONResponse({'detail':'Forbidden.'},status_code=403)
        if request.headers.get('Content-Length', '').isdigit() and int(request.headers['Content-Length']) > 4 * 1024 * 1024:
            return JSONResponse({'detail':'Request too large.'},status_code=413)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({'detail':'Invalid request input.'},status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        logging.exception('Database failure')
        return JSONResponse({'detail':'Service temporarily unavailable.'},status_code=503)

    @app.exception_handler(Exception)
    async def uncaught_error(request, exc):
        logging.exception('Unexpected failure')
        return JSONResponse({'detail':'An unexpected error occurred.'},status_code=500)

    app.include_router(m1_auth.router)
    app.include_router(m2_parcels.router)
    app.include_router(m3_delivery.router)
    return app
