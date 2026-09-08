"""Download orchestration: libtorrent + HTTP, encrypt-on-complete."""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlparse

import httpx

from app.config import Settings
from app.models import JobKind, JobStatus, PeerInfo, new_id, utcnow
from app.services.encryption import Encryptor
from app.services.geoip import country_code_for_ip
from app.services.ntfy import NtfyNotifier
from app.services.store import JobRecord, Store

log = logging.getLogger(__name__)

try:
    import libtorrent as lt
except ImportError:  # pragma: no cover
    lt = None  # type: ignore


def _guess_name_from_url(url: str) -> str:
    path = unquote(urlparse(url).path)
    name = Path(path).name
    return name or "download"


def _is_magnet(url: str) -> bool:
    return url.strip().lower().startswith("magnet:")


def _is_http(url: str) -> bool:
    return url.strip().lower().startswith(("http://", "https://"))


def _remove_torrent(session, handle, delete_files: bool = False) -> None:
    # libtorrent 2.x python bindings: remove option 1 = delete_files
    session.remove_torrent(handle, 1 if delete_files else 0)


def _state_name(status) -> str:
    state = getattr(status, "state", None)
    if state is None:
        return "unknown"
    # Prefer enum name when available
    name = getattr(state, "name", None)
    if isinstance(name, str):
        return name
    mapping = {
        0: "queued_for_checking",
        1: "checking_files",
        2: "downloading_metadata",
        3: "downloading",
        4: "finished",
        5: "seeding",
        6: "allocating",
        7: "checking_resume_data",
    }
    try:
        return mapping.get(int(state), str(state))
    except Exception:
        return str(state)


def _peer_endpoint(peer) -> tuple[str, int]:
    ip = getattr(peer, "ip", None)
    if isinstance(ip, tuple) and len(ip) >= 2:
        return str(ip[0]), int(ip[1])
    if isinstance(ip, str):
        return ip, 0
    return str(ip or "?"), 0


def _collect_peers(handle) -> list[PeerInfo]:
    peers: list[PeerInfo] = []
    try:
        raw = handle.get_peer_info()
    except Exception:
        return peers
    for peer in raw:
        host, port = _peer_endpoint(peer)
        encrypted = bool(getattr(peer, "rc4_encrypted", False) or getattr(peer, "plaintext_encrypted", False))
        conn = "bt"
        if getattr(peer, "web_seed", False) or getattr(peer, "http_seed", False):
            conn = "web"
        elif getattr(peer, "utp_socket", False):
            conn = "utp"
        peers.append(
            PeerInfo(
                ip=host,
                port=port,
                client=str(getattr(peer, "client", "") or ""),
                down_speed=float(getattr(peer, "down_speed", 0) or 0),
                up_speed=float(getattr(peer, "up_speed", 0) or 0),
                progress=float(getattr(peer, "progress", 0) or 0),
                seed=bool(getattr(peer, "seed", False)),
                encrypted=encrypted,
                connection=conn,
                country=country_code_for_ip(host),
            )
        )
    peers.sort(key=lambda p: (p.ip, p.port))
    return peers[:64]


def _eta_seconds(total: Optional[int], done: int, rate: float) -> Optional[float]:
    if not total or total <= 0 or rate <= 0:
        return None
    remaining = total - done
    if remaining <= 0:
        return 0.0
    return remaining / rate


class _UserPaused(Exception):
    """Internal signal to break an HTTP stream when the user pauses."""


class DownloadManager:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        encryptor: Encryptor,
        ntfy: Optional[NtfyNotifier] = None,
    ) -> None:
        if lt is None:
            raise RuntimeError("libtorrent is not installed")
        self.settings = settings
        self.store = store
        self.encryptor = encryptor
        self.ntfy = ntfy or NtfyNotifier(settings)

        self._session = None
        self._handles: dict[str, object] = {}
        self._http_tasks: dict[str, asyncio.Task] = {}
        self._poll_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    def _notify(self, coro) -> None:
        asyncio.create_task(coro)

    def _fail_job(self, job: JobRecord, error: str) -> None:
        job.status = JobStatus.FAILED
        job.error = error
        job.touch()
        self._notify(self.ntfy.failed(name=job.name, error=error))

    async def start(self) -> None:
        # Debian's libtorrent 2.0 bindings take a settings dict (no settings_pack class).
        settings = {
            "enable_dht": True,
            "enable_lsd": True,
            "enable_upnp": True,
            "enable_natpmp": True,
            "out_enc_policy": 1,  # pe_enabled
            "in_enc_policy": 1,
            "anonymous_mode": True,
            # Prefer zero ratio — we pause/remove as soon as the download finishes.
            "share_ratio_limit": 0,
            "seed_time_ratio_limit": 0,
            "seed_time_limit": 0,
        }
        self._session = lt.session(settings)
        for factory_name in (
            "create_ut_metadata_plugin",
            "create_ut_pex_plugin",
            "create_smart_ban_plugin",
        ):
            factory = getattr(lt, factory_name, None)
            if factory:
                try:
                    self._session.add_extension(factory)
                except Exception:
                    pass

        self.settings.download_dir.mkdir(parents=True, exist_ok=True)
        self.settings.completed_dir.mkdir(parents=True, exist_ok=True)

        self._poll_task = asyncio.create_task(self._poll_loop(), name="torrent-poll")

    async def stop(self) -> None:
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        for task in list(self._http_tasks.values()):
            task.cancel()
        if self._session:
            for handle in list(self._handles.values()):
                try:
                    _remove_torrent(self._session, handle, delete_files=False)
                except Exception:
                    pass
            self._session = None

    def _ensure_can_start(self) -> None:
        if self._session is None:
            raise RuntimeError("session not started")

    def add_url(self, url: str, name: Optional[str] = None) -> JobRecord:
        url = url.strip()
        if _is_magnet(url):
            return self._add_magnet(url, name)
        if _is_http(url):
            lower = url.lower().split("?", 1)[0]
            if lower.endswith(".torrent"):
                return self._add_remote_torrent(url, name)
            return self._add_http(url, name)
        raise ValueError("URL must be a magnet: link or http(s) URL")

    def add_torrent_bytes(self, data: bytes, filename: str = "upload.torrent") -> JobRecord:
        self._ensure_can_start()

        job = JobRecord(kind=JobKind.TORRENT, name=filename, source=filename)
        work = self.settings.download_dir / job.id
        work.mkdir(parents=True, exist_ok=True)
        torrent_path = work / "source.torrent"
        torrent_path.write_bytes(data)
        job.torrent_path = torrent_path
        job.work_dir = work
        self.store.add_job(job)

        info = lt.torrent_info(str(torrent_path))
        job.name = info.name() or filename
        atp = lt.add_torrent_params()
        atp.ti = info
        atp.save_path = str(work)
        handle = self._session.add_torrent(atp)
        handle.resume()
        job.status = JobStatus.DOWNLOADING
        self._handles[job.id] = handle
        job.touch()
        return job

    def _add_magnet(self, magnet: str, name: Optional[str]) -> JobRecord:
        self._ensure_can_start()

        display = name or "magnet"
        try:
            params = lt.parse_magnet_uri(magnet)
            parsed_name = getattr(params, "name", None) or ""
            if parsed_name:
                display = name or parsed_name
        except Exception:
            params = lt.add_torrent_params()
            params.url = magnet

        job = JobRecord(kind=JobKind.MAGNET, name=display, source=magnet)
        work = self.settings.download_dir / job.id
        work.mkdir(parents=True, exist_ok=True)
        job.work_dir = work
        self.store.add_job(job)

        params.save_path = str(work)
        handle = self._session.add_torrent(params)
        handle.resume()
        job.status = JobStatus.DOWNLOADING
        self._handles[job.id] = handle
        job.touch()
        return job

    def _add_remote_torrent(self, url: str, name: Optional[str]) -> JobRecord:
        self._ensure_can_start()

        job = JobRecord(
            kind=JobKind.TORRENT,
            name=name or _guess_name_from_url(url),
            source=url,
        )
        work = self.settings.download_dir / job.id
        work.mkdir(parents=True, exist_ok=True)
        job.work_dir = work
        self.store.add_job(job)
        job.status = JobStatus.DOWNLOADING
        job.touch()
        self._http_tasks[job.id] = asyncio.create_task(
            self._fetch_torrent_then_add(job, url),
            name=f"torrent-fetch-{job.id}",
        )
        return job

    def _add_http(self, url: str, name: Optional[str]) -> JobRecord:
        self._ensure_can_start()

        job = JobRecord(
            kind=JobKind.HTTP,
            name=name or _guess_name_from_url(url),
            source=url,
        )
        work = self.settings.download_dir / job.id
        work.mkdir(parents=True, exist_ok=True)
        job.work_dir = work
        self.store.add_job(job)
        job.status = JobStatus.DOWNLOADING
        job.touch()
        self._http_tasks[job.id] = asyncio.create_task(
            self._http_download(job, url),
            name=f"http-{job.id}",
        )
        return job

    async def _fetch_torrent_then_add(self, job: JobRecord, url: str) -> None:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.content

            if self._session is None:
                raise RuntimeError("session gone")

            assert job.work_dir is not None
            torrent_path = job.work_dir / "source.torrent"
            torrent_path.write_bytes(data)
            job.torrent_path = torrent_path

            info = lt.torrent_info(str(torrent_path))
            job.name = info.name() or job.name
            atp = lt.add_torrent_params()
            atp.ti = info
            atp.save_path = str(job.work_dir)
            handle = self._session.add_torrent(atp)
            handle.resume()
            job.status = JobStatus.DOWNLOADING
            self._handles[job.id] = handle
            job.touch()
        except asyncio.CancelledError:
            job.status = JobStatus.CANCELLED
            job.touch()
            raise
        except Exception as exc:
            log.exception("torrent fetch failed for %s", job.id)
            self._fail_job(job, str(exc))
        finally:
            self._http_tasks.pop(job.id, None)

    async def _http_download(self, job: JobRecord, url: str) -> None:
        assert job.work_dir is not None
        dest = job.work_dir / job.name
        try:
            while True:
                if job.user_paused:
                    job.status = JobStatus.PAUSED
                    job.download_rate = 0.0
                    job.touch()
                    await asyncio.sleep(0.5)
                    continue

                job.status = JobStatus.DOWNLOADING
                job.error = None
                job.touch()

                try:
                    async with httpx.AsyncClient(follow_redirects=True, timeout=None) as client:
                        async with client.stream("GET", url) as resp:
                            resp.raise_for_status()
                            total = resp.headers.get("content-length")
                            job.total_bytes = int(total) if total else None
                            cd = resp.headers.get("content-disposition")
                            if cd and "filename=" in cd:
                                part = cd.split("filename=")[-1].strip().strip("\"'")
                                if part:
                                    job.name = Path(part).name
                                    dest = job.work_dir / job.name

                            downloaded = 0
                            last_t = time.monotonic()
                            last_bytes = 0
                            with dest.open("wb") as out:
                                async for chunk in resp.aiter_bytes(1024 * 256):
                                    if job.user_paused:
                                        raise _UserPaused()
                                    out.write(chunk)
                                    downloaded += len(chunk)
                                    job.downloaded_bytes = downloaded
                                    if job.total_bytes:
                                        job.progress = min(1.0, downloaded / job.total_bytes)
                                    now = time.monotonic()
                                    dt = now - last_t
                                    if dt >= 0.5:
                                        job.download_rate = (downloaded - last_bytes) / dt
                                        job.payload_download_rate = job.download_rate
                                        job.push_speed(job.download_rate, 0.0)
                                        job.eta_seconds = _eta_seconds(
                                            job.total_bytes, downloaded, job.download_rate
                                        )
                                        last_t = now
                                        last_bytes = downloaded
                                    job.state = "http"
                                    job.touch()

                    await self._finalize_path(job, dest)
                    return
                except _UserPaused:
                    job.status = JobStatus.PAUSED
                    job.download_rate = 0.0
                    job.touch()
                    if dest.exists():
                        dest.unlink()
                    job.downloaded_bytes = 0
                    job.progress = 0.0
                    while job.user_paused and job.status != JobStatus.CANCELLED:
                        await asyncio.sleep(0.5)
                    continue
        except asyncio.CancelledError:
            job.status = JobStatus.CANCELLED
            job.touch()
            raise
        except Exception as exc:
            log.exception("HTTP download failed for %s", job.id)
            self._fail_job(job, str(exc))
        finally:
            self._http_tasks.pop(job.id, None)

    async def _poll_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except Exception:
                log.exception("poll error")
            await asyncio.sleep(self.settings.torrent_poll_interval)

    async def _poll_once(self) -> None:
        if self._session is None:
            return

        finished: list[str] = []
        for job_id, handle in list(self._handles.items()):
            job = self.store.get_job(job_id)
            if not job or job.status in {
                JobStatus.COMPLETED,
                JobStatus.FAILED,
                JobStatus.CANCELLED,
                JobStatus.ENCRYPTING,
            }:
                continue
            try:
                status = handle.status()
            except Exception as exc:
                self._fail_job(job, str(exc))
                continue

            job.progress = float(status.progress)
            job.download_rate = float(status.download_rate)
            job.upload_rate = float(status.upload_rate)
            job.payload_download_rate = float(
                getattr(status, "download_payload_rate", status.download_rate) or 0
            )
            job.payload_upload_rate = float(
                getattr(status, "upload_payload_rate", status.upload_rate) or 0
            )
            job.total_bytes = int(status.total_wanted)
            job.downloaded_bytes = int(status.total_wanted_done)
            job.uploaded_bytes = int(getattr(status, "total_upload", 0) or 0)
            job.state = _state_name(status)
            job.num_peers = int(getattr(status, "num_peers", 0) or 0)
            job.num_seeds = int(getattr(status, "num_seeds", 0) or 0)
            job.list_peers = int(getattr(status, "list_peers", 0) or 0)
            job.list_seeds = int(getattr(status, "list_seeds", 0) or 0)

            # libtorrent's status.num_pieces is "pieces we have", NOT the total.
            have_pieces = int(getattr(status, "num_pieces", 0) or 0)
            total_pieces = 0
            pieces = getattr(status, "pieces", None)
            if pieces is not None:
                try:
                    total_pieces = len(pieces)
                    have_pieces = sum(1 for p in pieces if p)
                except Exception:
                    pass
            if total_pieces <= 0:
                try:
                    ti = handle.torrent_file()
                    if ti is not None:
                        total_pieces = int(ti.num_pieces())
                except Exception:
                    pass
            job.pieces_done = have_pieces
            job.num_pieces = total_pieces

            job.distributed_copies = float(getattr(status, "distributed_copies", 0) or 0)
            tracker = getattr(status, "current_tracker", None) or ""
            job.current_tracker = tracker or None
            job.has_metadata = bool(getattr(status, "has_metadata", False))
            job.save_path = str(getattr(status, "save_path", "") or "") or None
            try:
                duration = getattr(status, "active_duration", None)
                if duration is not None:
                    job.active_duration_seconds = float(duration.total_seconds())
            except Exception:
                pass
            try:
                ih = handle.info_hash()
                job.info_hash = str(ih)
            except Exception:
                try:
                    job.info_hash = str(handle.info_hashes().get_best())
                except Exception:
                    pass
            if getattr(status, "name", None):
                job.name = status.name

            job.eta_seconds = _eta_seconds(
                job.total_bytes, job.downloaded_bytes, job.download_rate
            )
            job.push_speed(job.download_rate, job.upload_rate)
            job.peers = _collect_peers(handle)

            if job.user_paused:
                job.status = JobStatus.PAUSED
                job.download_rate = 0.0
                job.upload_rate = 0.0
            else:
                job.status = JobStatus.DOWNLOADING

            done = False
            if job.status == JobStatus.DOWNLOADING:
                done = bool(getattr(status, "is_finished", False)) or bool(
                    getattr(status, "is_seeding", False)
                )
                if not done and status.progress >= 0.9999 and status.total_wanted > 0:
                    done = status.total_wanted_done >= status.total_wanted
            if done:
                finished.append(job_id)
            job.touch()

        for job_id in finished:
            await self._complete_torrent(job_id)

    async def _complete_torrent(self, job_id: str) -> None:
        async with self._lock:
            job = self.store.get_job(job_id)
            handle = self._handles.get(job_id)
            if not job or not handle:
                return
            if job.status in {JobStatus.ENCRYPTING, JobStatus.COMPLETED}:
                return

            job.status = JobStatus.ENCRYPTING
            job.progress = 0.0
            job.download_rate = 0.0
            job.upload_rate = 0.0
            job.touch()

            try:
                handle.pause()
                try:
                    handle.unset_flags(lt.torrent_flags.auto_managed)
                except Exception:
                    pass

                assert job.work_dir is not None
                status = handle.status()
                content_name = getattr(status, "name", None) or job.name
                content_path = job.work_dir / content_name
                if not content_path.exists():
                    candidates = [
                        p for p in job.work_dir.iterdir() if p.name != "source.torrent"
                    ]
                    if len(candidates) == 1:
                        content_path = candidates[0]
                    else:
                        content_path = job.work_dir

                bundle = content_path
                if content_path.is_dir():
                    zip_path = job.work_dir / f"{Path(content_name).name}.zip"
                    await asyncio.to_thread(self._zip_dir, content_path, zip_path)
                    bundle = zip_path
                    job.name = zip_path.name

                await self._finalize_path(job, bundle)

                try:
                    _remove_torrent(self._session, handle, delete_files=False)
                except Exception:
                    pass
                self._handles.pop(job_id, None)
            except Exception as exc:
                log.exception("finalize torrent failed")
                self._fail_job(job, str(exc))

    @staticmethod
    def _zip_dir(src: Path, dest: Path) -> None:
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if src.is_file():
                zf.write(src, arcname=src.name)
                return
            for path in src.rglob("*"):
                if path.is_file():
                    zf.write(path, arcname=str(path.relative_to(src)))

    async def _finalize_path(self, job: JobRecord, path: Path) -> None:
        job.status = JobStatus.ENCRYPTING
        job.progress = 0.0
        job.download_rate = 0.0
        job.upload_rate = 0.0
        file_id = new_id()
        original_name = path.name if path.is_file() else job.name
        size_bytes = path.stat().st_size if path.is_file() else 0
        if path.is_file():
            job.total_bytes = size_bytes
            job.downloaded_bytes = 0
        job.touch()

        def on_progress(done: int, total: int) -> None:
            job.downloaded_bytes = done
            if total > 0:
                job.total_bytes = total
                job.progress = min(1.0, done / total)
            else:
                job.progress = 1.0
            job.touch()

        await asyncio.to_thread(
            lambda: self.store.append_completed(
                file_id=file_id,
                original_name=original_name,
                source_path=path,
                on_progress=on_progress,
            )
        )

        wall = max(0.0, (utcnow() - job.created_at).total_seconds())
        await asyncio.to_thread(self.store.write_duration, file_id, wall)

        job.completed_file_id = file_id
        job.status = JobStatus.COMPLETED
        job.progress = 1.0
        # Drop plaintext name from job view after encryption
        job.name = file_id
        job.touch()

        self._notify(
            self.ntfy.completed(name=original_name, file_id=file_id, size_bytes=size_bytes)
        )

        if job.work_dir and job.work_dir.exists():
            shutil.rmtree(job.work_dir, ignore_errors=True)

    async def pause(self, job_id: str) -> bool:
        job = self.store.get_job(job_id)
        if not job:
            return False
        if job.status not in {
            JobStatus.QUEUED,
            JobStatus.DOWNLOADING,
        }:
            return False

        job.user_paused = True
        job.status = JobStatus.PAUSED
        job.download_rate = 0.0
        job.upload_rate = 0.0
        job.touch()

        handle = self._handles.get(job_id)
        if handle is not None:
            try:
                handle.pause()
            except Exception:
                pass
        return True

    async def resume(self, job_id: str) -> bool:
        job = self.store.get_job(job_id)
        if not job:
            return False
        if not job.user_paused and job.status != JobStatus.PAUSED:
            return False

        job.user_paused = False
        handle = self._handles.get(job_id)
        if handle is not None:
            try:
                handle.resume()
            except Exception:
                pass
        job.status = JobStatus.DOWNLOADING
        job.touch()
        return True

    async def cancel(self, job_id: str) -> bool:
        """Cancel an active job: wipe partial data and remove it from the list."""
        job = self.store.get_job(job_id)
        if not job:
            return False
        if job.status in {JobStatus.COMPLETED, JobStatus.ENCRYPTING}:
            return False

        handle = self._handles.pop(job_id, None)
        if handle and self._session:
            try:
                _remove_torrent(self._session, handle, delete_files=True)
            except Exception:
                pass

        task = self._http_tasks.pop(job_id, None)
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        if job.work_dir and job.work_dir.exists():
            shutil.rmtree(job.work_dir, ignore_errors=True)

        # If it somehow already produced a completed blob, wipe that too.
        if job.completed_file_id:
            self.store.delete_completed(job.completed_file_id)

        self.store.remove_job(job_id)
        return True
