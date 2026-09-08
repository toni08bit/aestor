from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile, WebSocket, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth import (
    assert_login_allowed,
    clear_login_failures,
    create_session_token,
    password_matches,
    record_login_failure,
    require_api_bearer,
    require_web_session,
    verify_session_token,
)
from app.config import Settings, get_settings
from app.models import CompletedIdInfo, JobCreate, JobInfo, LoginRequest, StatusResponse
from app.services.download_manager import DownloadManager
from app.services.encryption import Encryptor
from app.services.live import LiveHub
from app.services.ntfy import NtfyNotifier
from app.services.store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("aestor")

STATIC_DIR = Path(__file__).resolve().parent / "static"

_PUBLIC_API_PATHS = {
    "/api/auth/login",
}


class AppState:
    settings: Settings
    store: Store
    manager: DownloadManager
    ntfy: NtfyNotifier
    live: LiveHub


state = AppState()


def build_live_snapshot() -> dict[str, Any]:
    settings = state.settings
    store = state.store
    active = sum(
        1
        for j in store.jobs.values()
        if j.status.value in {"queued", "downloading", "paused", "encrypting"}
    )
    status = StatusResponse(
        dev_mode=settings.dev_mode,
        active_jobs=active,
        completed_files=store.completed_count(),
        ntfy_enabled=state.ntfy.enabled,
    )
    return {
        "type": "snapshot",
        "status": status.model_dump(mode="json"),
        "jobs": [j.model_dump(mode="json") for j in store.list_jobs()],
        "files": store.list_file_ids(),
    }


class ApiAuthGate(BaseHTTPMiddleware):
    """Defense-in-depth: every /api path requires the right credential.

    - /api/v1/*  → bearer token only
    - other /api → web session cookie (except login)
    - /docs etc. → always 404
    WebSocket auth is handled in the /api/ws endpoint (cookies).
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        settings = get_settings()

        if path in {"/docs", "/redoc", "/openapi.json"} or path.startswith("/docs/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)

        if not path.startswith("/api/"):
            return await call_next(request)

        if path == "/api/ws":
            return await call_next(request)

        if path in _PUBLIC_API_PATHS or path == "/api/auth/logout":
            return await call_next(request)

        from app.auth import token_matches

        if path.startswith("/api/v1/"):
            auth = request.headers.get("authorization") or ""
            ok = False
            if auth.lower().startswith("bearer "):
                ok = token_matches(auth[7:].strip(), settings.api_bearer_token)
            if not ok:
                return JSONResponse(
                    {"detail": "Bearer token required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return await call_next(request)

        cookie = request.cookies.get(settings.session_cookie_name)
        if not cookie or not verify_session_token(cookie, settings):
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.download_dir.mkdir(parents=True, exist_ok=True)
    settings.completed_dir.mkdir(parents=True, exist_ok=True)

    encryptor = Encryptor(settings.encryption_public_key_path)
    store = Store(settings.completed_dir, encryptor)
    ntfy = NtfyNotifier(settings)
    live = LiveHub()
    manager = DownloadManager(settings, store, encryptor, ntfy)

    state.settings = settings
    state.store = store
    state.manager = manager
    state.ntfy = ntfy
    state.live = live

    await manager.start()
    await live.start(build_live_snapshot, interval=settings.live_push_interval)
    log.info(
        "aestor started (dev_mode=%s ntfy=%s live=%.2fs)",
        settings.dev_mode,
        ntfy.enabled,
        settings.live_push_interval,
    )
    try:
        yield
    finally:
        await live.stop()
        await manager.stop()
        log.info("aestor stopped")


app = FastAPI(
    title="aestor",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(ApiAuthGate)


def get_manager() -> DownloadManager:
    return state.manager


def get_store() -> Store:
    return state.store


def get_ntfy() -> NtfyNotifier:
    return state.ntfy


# --- Auth ---


@app.post("/api/auth/login")
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
):
    assert_login_allowed(request)
    if not password_matches(body.password, settings):
        record_login_failure(request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    clear_login_failures(request)
    token = create_session_token(settings)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        samesite="lax",
        secure=not settings.dev_mode,
        max_age=settings.session_max_age,
        path="/",
    )
    return {"ok": True}


@app.post("/api/auth/logout")
async def logout(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
):
    response.delete_cookie(settings.session_cookie_name, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(_: Annotated[None, Depends(require_web_session)]):
    return {"ok": True}


@app.websocket("/api/ws")
async def live_ws(websocket: WebSocket):
    settings = get_settings()
    token = websocket.cookies.get(settings.session_cookie_name)
    if not token or not verify_session_token(token, settings):
        await websocket.close(code=4401)
        return
    await state.live.connect(websocket)
    await state.live.listen(websocket)


# --- Status / jobs (web session) ---


@app.get("/api/status", response_model=StatusResponse)
async def status_endpoint(
    _: Annotated[None, Depends(require_web_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[Store, Depends(get_store)],
):
    active = sum(
        1
        for j in store.jobs.values()
        if j.status.value in {"queued", "downloading", "paused", "encrypting"}
    )
    return StatusResponse(
        dev_mode=settings.dev_mode,
        active_jobs=active,
        completed_files=store.completed_count(),
        ntfy_enabled=state.ntfy.enabled,
    )


@app.get("/api/jobs", response_model=list[JobInfo])
async def list_jobs(
    _: Annotated[None, Depends(require_web_session)],
    store: Annotated[Store, Depends(get_store)],
):
    return store.list_jobs()


@app.post("/api/jobs", response_model=JobInfo, status_code=status.HTTP_201_CREATED)
async def create_job(
    body: JobCreate,
    _: Annotated[None, Depends(require_web_session)],
    manager: Annotated[DownloadManager, Depends(get_manager)],
):
    try:
        job = manager.add_url(body.url, body.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    state.live.mark_dirty()
    return job.to_info()


@app.post("/api/jobs/torrent", response_model=JobInfo, status_code=status.HTTP_201_CREATED)
async def upload_torrent(
    _: Annotated[None, Depends(require_web_session)],
    manager: Annotated[DownloadManager, Depends(get_manager)],
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
):
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty torrent file")
    filename = name or file.filename or "upload.torrent"
    try:
        job = manager.add_torrent_bytes(data, filename)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid torrent: {exc}") from exc
    state.live.mark_dirty()
    return job.to_info()


@app.delete("/api/jobs/{job_id}")
async def cancel_job(
    job_id: str,
    _: Annotated[None, Depends(require_web_session)],
    manager: Annotated[DownloadManager, Depends(get_manager)],
):
    ok = await manager.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Job not found or not cancellable")
    state.live.mark_dirty()
    return {"ok": True}


@app.post("/api/jobs/{job_id}/pause")
async def pause_job(
    job_id: str,
    _: Annotated[None, Depends(require_web_session)],
    manager: Annotated[DownloadManager, Depends(get_manager)],
):
    ok = await manager.pause(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Job not found or not pausable")
    state.live.mark_dirty()
    return {"ok": True}


@app.post("/api/jobs/{job_id}/resume")
async def resume_job(
    job_id: str,
    _: Annotated[None, Depends(require_web_session)],
    manager: Annotated[DownloadManager, Depends(get_manager)],
):
    ok = await manager.resume(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Job not found or not resumable")
    state.live.mark_dirty()
    return {"ok": True}


@app.get("/api/files", response_model=list[CompletedIdInfo])
async def list_completed_web(
    _: Annotated[None, Depends(require_web_session)],
    store: Annotated[Store, Depends(get_store)],
):
    return store.list_file_ids()


@app.post("/api/ntfy/test")
async def ntfy_test(
    _: Annotated[None, Depends(require_web_session)],
    ntfy: Annotated[NtfyNotifier, Depends(get_ntfy)],
):
    if not ntfy.enabled:
        raise HTTPException(status_code=400, detail="ntfy is not configured")
    await ntfy.send(
        event="test",
        title="aestor · test",
        message="ntfy is working.",
        tags="bell,white_check_mark",
        priority=3,
        force=True,
    )
    return {"ok": True}


# --- Outer bearer API: encrypted manifest + pull/delete by uuid ---


@app.get("/api/v1/list", response_class=PlainTextResponse)
async def api_list_manifest(
    _: Annotated[None, Depends(require_api_bearer)],
    store: Annotated[Store, Depends(get_store)],
):
    """Serve the encrypted-lines manifest. Client decrypts each line locally."""
    if not store.manifest_path.is_file():
        return PlainTextResponse("")
    return PlainTextResponse(
        store.manifest_path.read_text(encoding="utf-8"),
        media_type="text/plain; charset=utf-8",
    )


@app.get("/api/v1/files/{file_id}")
async def api_download_file(
    file_id: str,
    _: Annotated[None, Depends(require_api_bearer)],
    store: Annotated[Store, Depends(get_store)],
):
    """Pull the encrypted blob stored under this uuid (filename is the uuid)."""
    path = store.blob_path(file_id)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=file_id,
    )


@app.delete("/api/v1/files/{file_id}")
async def api_delete_file(
    file_id: str,
    _: Annotated[None, Depends(require_api_bearer)],
    store: Annotated[Store, Depends(get_store)],
):
    """Unrecoverably delete the encrypted blob and drop its manifest line."""
    if not store.delete_completed(file_id):
        raise HTTPException(status_code=404, detail="File not found")
    state.live.mark_dirty()
    return {"ok": True}


# Static UI last so API routes win
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
