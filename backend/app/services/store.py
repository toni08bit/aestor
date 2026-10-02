"""Job registry + encrypted outer-API manifest (uuid → encrypted name lines)."""

from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Optional

from app.models import (
    JobInfo,
    JobKind,
    JobStatus,
    PeerInfo,
    SpeedSample,
    new_id,
    utcnow,
)
from app.services.encryption import Encryptor, ProgressCb

log = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.db"
JOB_STATE_NAME = "job.json"
SPEED_HISTORY_MAX = 90  # ~3 minutes at 2s poll, more at 1s
META_SUFFIX = ".json"

# Statuses that should survive process/container restarts.
_PERSISTABLE = {
    JobStatus.QUEUED,
    JobStatus.DOWNLOADING,
    JobStatus.PAUSED,
    JobStatus.ENCRYPTING,
    JobStatus.FAILED,
}


class JobRecord:
    def __init__(
        self,
        *,
        kind: JobKind,
        name: str,
        source: str,
        torrent_path: Optional[Path] = None,
        job_id: Optional[str] = None,
    ) -> None:
        now = utcnow()
        self.id = job_id or new_id()
        self.kind = kind
        self.name = name
        self.source = source
        self.torrent_path = torrent_path
        self.status = JobStatus.QUEUED
        self.progress = 0.0
        self.download_rate = 0.0
        self.upload_rate = 0.0
        self.total_bytes: Optional[int] = None
        self.downloaded_bytes = 0
        self.uploaded_bytes = 0
        self.error: Optional[str] = None
        self.created_at = now
        self.updated_at = now
        self.completed_file_id: Optional[str] = None
        self.work_dir: Optional[Path] = None
        self.handle_key: Optional[str] = None
        self.user_paused = False
        self._dirty = False

        self.state: Optional[str] = None
        self.eta_seconds: Optional[float] = None
        self.num_peers = 0
        self.num_seeds = 0
        self.list_peers = 0
        self.list_seeds = 0
        self.num_pieces = 0
        self.pieces_done = 0
        self.distributed_copies = 0.0
        self.current_tracker: Optional[str] = None
        self.has_metadata = False
        self.save_path: Optional[str] = None
        self.info_hash: Optional[str] = None
        self.active_duration_seconds = 0.0
        self.payload_download_rate = 0.0
        self.payload_upload_rate = 0.0
        self.peers: list[PeerInfo] = []
        self.speed_history: Deque[SpeedSample] = deque(maxlen=SPEED_HISTORY_MAX)

    def touch(self) -> None:
        self.updated_at = utcnow()
        self._dirty = True

    def push_speed(self, down: float, up: float = 0.0) -> None:
        self.speed_history.append(SpeedSample(t=time.time(), down=down, up=up))

    def to_persist_dict(self) -> dict[str, Any]:
        torrent_rel: Optional[str] = None
        if self.torrent_path is not None:
            try:
                if self.work_dir and self.torrent_path.is_relative_to(self.work_dir):
                    torrent_rel = str(self.torrent_path.relative_to(self.work_dir))
                else:
                    torrent_rel = self.torrent_path.name
            except (ValueError, AttributeError):
                torrent_rel = self.torrent_path.name
        return {
            "id": self.id,
            "kind": self.kind.value,
            "name": self.name,
            "source": self.source,
            "status": self.status.value,
            "progress": self.progress,
            "total_bytes": self.total_bytes,
            "downloaded_bytes": self.downloaded_bytes,
            "uploaded_bytes": self.uploaded_bytes,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "user_paused": self.user_paused,
            "state": self.state,
            "info_hash": self.info_hash,
            "torrent_path": torrent_rel,
            "active_duration_seconds": self.active_duration_seconds,
        }

    @classmethod
    def from_persist_dict(cls, data: dict[str, Any], work_dir: Path) -> "JobRecord":
        job = cls(
            kind=JobKind(data["kind"]),
            name=str(data.get("name") or "download"),
            source=str(data.get("source") or ""),
            job_id=str(data["id"]),
        )
        job.work_dir = work_dir
        job.status = JobStatus(data.get("status") or JobStatus.QUEUED.value)
        job.progress = float(data.get("progress") or 0.0)
        total = data.get("total_bytes")
        job.total_bytes = int(total) if total is not None else None
        job.downloaded_bytes = int(data.get("downloaded_bytes") or 0)
        job.uploaded_bytes = int(data.get("uploaded_bytes") or 0)
        job.error = data.get("error")
        job.user_paused = bool(data.get("user_paused") or False)
        job.state = data.get("state")
        job.info_hash = data.get("info_hash")
        job.active_duration_seconds = float(data.get("active_duration_seconds") or 0.0)
        created = data.get("created_at")
        updated = data.get("updated_at")
        if created:
            job.created_at = datetime.fromisoformat(created)
        if updated:
            job.updated_at = datetime.fromisoformat(updated)
        rel = data.get("torrent_path")
        if rel:
            path = work_dir / rel
            job.torrent_path = path if path.is_file() else None
        elif (work_dir / "source.torrent").is_file():
            job.torrent_path = work_dir / "source.torrent"
        job._dirty = False
        return job

    def to_info(self) -> JobInfo:
        preview = self.source
        if len(preview) > 160:
            preview = preview[:157] + "..."
        return JobInfo(
            id=self.id,
            kind=self.kind,
            status=self.status,
            name=self.name,
            progress=self.progress,
            download_rate=self.download_rate,
            upload_rate=self.upload_rate,
            total_bytes=self.total_bytes,
            downloaded_bytes=self.downloaded_bytes,
            uploaded_bytes=self.uploaded_bytes,
            error=self.error,
            created_at=self.created_at,
            updated_at=self.updated_at,
            completed_file_id=self.completed_file_id,
            state=self.state,
            eta_seconds=self.eta_seconds,
            num_peers=self.num_peers,
            num_seeds=self.num_seeds,
            list_peers=self.list_peers,
            list_seeds=self.list_seeds,
            num_pieces=self.num_pieces,
            pieces_done=self.pieces_done,
            distributed_copies=self.distributed_copies,
            current_tracker=self.current_tracker,
            has_metadata=self.has_metadata,
            save_path=self.save_path,
            info_hash=self.info_hash,
            active_duration_seconds=self.active_duration_seconds,
            payload_download_rate=self.payload_download_rate,
            payload_upload_rate=self.payload_upload_rate,
            peers=list(self.peers),
            speed_history=list(self.speed_history),
            source_preview=preview,
        )


def secure_delete(path: Path) -> None:
    """Overwrite then unlink so the blob is unrecoverable from the filesystem."""
    if not path.is_file():
        return
    size = path.stat().st_size
    try:
        with path.open("r+b", buffering=0) as fh:
            remaining = size
            while remaining > 0:
                chunk = min(remaining, 1024 * 1024)
                fh.write(os.urandom(chunk))
                remaining -= chunk
            fh.flush()
            os.fsync(fh.fileno())
            fh.seek(0)
            remaining = size
            zero = b"\x00" * (1024 * 1024)
            while remaining > 0:
                chunk = min(remaining, len(zero))
                fh.write(zero[:chunk])
                remaining -= chunk
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        log.exception("secure overwrite failed for %s", path)
    path.unlink(missing_ok=True)


class Store:
    """In-memory jobs + on-disk encrypted manifest / UUID-named blobs.

    Active/failed jobs are also snapshotted under ``download_dir/<id>/job.json``
    so the queue can resume after a container restart.
    """

    def __init__(
        self,
        completed_dir: Path,
        encryptor: Encryptor,
        download_dir: Optional[Path] = None,
    ) -> None:
        self.jobs: dict[str, JobRecord] = {}
        self.completed_dir = completed_dir
        self.download_dir = download_dir
        self.encryptor = encryptor
        self.manifest_path = completed_dir / MANIFEST_NAME
        self.completed_dir.mkdir(parents=True, exist_ok=True)
        if self.download_dir is not None:
            self.download_dir.mkdir(parents=True, exist_ok=True)
        if not self.manifest_path.exists():
            self.manifest_path.write_text("", encoding="utf-8")

    def add_job(self, job: JobRecord, *, persist: bool = True) -> JobRecord:
        self.jobs[job.id] = job
        if persist:
            self.persist_job(job)
        return job

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        return self.jobs.get(job_id)

    def remove_job(self, job_id: str) -> Optional[JobRecord]:
        job = self.jobs.pop(job_id, None)
        if job is not None:
            self.drop_persisted_job(job)
        return job

    def list_jobs(self) -> list[JobInfo]:
        return sorted(
            (j.to_info() for j in self.jobs.values()),
            key=lambda x: x.created_at,
            reverse=True,
        )

    def persist_job(self, job: JobRecord) -> None:
        """Write job snapshot next to its work dir (no-op if not persistable)."""
        if job.status not in _PERSISTABLE:
            self.drop_persisted_job(job)
            return
        if job.work_dir is None:
            return
        try:
            job.work_dir.mkdir(parents=True, exist_ok=True)
            path = job.work_dir / JOB_STATE_NAME
            tmp = job.work_dir / f".{JOB_STATE_NAME}.tmp"
            payload = json.dumps(job.to_persist_dict(), ensure_ascii=False, indent=2)
            tmp.write_text(payload + "\n", encoding="utf-8")
            tmp.replace(path)
            job._dirty = False
        except OSError:
            log.exception("failed to persist job %s", job.id)

    def drop_persisted_job(self, job: JobRecord) -> None:
        if job.work_dir is None:
            return
        path = job.work_dir / JOB_STATE_NAME
        try:
            path.unlink(missing_ok=True)
        except OSError:
            log.exception("failed to drop persisted job %s", job.id)

    def flush_dirty_jobs(self) -> None:
        for job in self.jobs.values():
            if job._dirty and job.status in _PERSISTABLE:
                self.persist_job(job)

    def load_persisted_jobs(self) -> list[JobRecord]:
        if self.download_dir is None or not self.download_dir.is_dir():
            return []
        loaded: list[JobRecord] = []
        for path in sorted(self.download_dir.iterdir()):
            if not path.is_dir():
                continue
            state_path = path / JOB_STATE_NAME
            if not state_path.is_file():
                continue
            try:
                data = json.loads(state_path.read_text(encoding="utf-8"))
                job = JobRecord.from_persist_dict(data, path)
                if job.status not in _PERSISTABLE:
                    continue
                loaded.append(job)
            except Exception:
                log.exception("failed to load persisted job from %s", state_path)
        return loaded

    def blob_path(self, file_id: str) -> Path:
        return self.completed_dir / file_id

    def meta_path(self, file_id: str) -> Path:
        return self.completed_dir / f"{file_id}{META_SUFFIX}"

    def has_file(self, file_id: str) -> bool:
        return self.blob_path(file_id).is_file()

    def list_file_ids(self) -> list[dict]:
        """Web-safe listing: uuid + size + duration (no plaintext names)."""
        rows: list[dict] = []
        for path in sorted(self.completed_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file() or path.name == MANIFEST_NAME:
                continue
            if path.suffix in {META_SUFFIX, ".tmp"}:
                continue
            if path.name.endswith(".db.tmp") or path.name == "pair.json":
                continue
            row: dict = {"id": path.name, "encrypted_size_bytes": path.stat().st_size}
            duration = self._read_duration(path.name)
            if duration is not None:
                row["duration_seconds"] = duration
            rows.append(row)
        return rows

    def _read_duration(self, file_id: str) -> Optional[float]:
        meta = self.meta_path(file_id)
        if not meta.is_file():
            return None
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            value = data.get("duration_seconds")
            if value is None:
                return None
            return float(value)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def completed_count(self) -> int:
        return len(self.list_file_ids())

    def append_completed(
        self,
        *,
        file_id: str,
        original_name: str,
        source_path: Path,
        on_progress: Optional[ProgressCb] = None,
    ) -> Path:
        """Encrypt blob as {uuid}, append encrypted manifest line. Returns blob path."""
        dest = self.blob_path(file_id)
        tmp = Path(f"{dest}.tmp")
        try:
            self.encryptor.encrypt_file(source_path, tmp, on_progress=on_progress)
            tmp.replace(dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

        b64 = self.encryptor.encrypt_manifest_payload(
            {
                "id": file_id,
                "name": original_name,
            }
        )
        line = f"{file_id}\t{b64}\n"
        with self.manifest_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        return dest

    def write_duration(self, file_id: str, duration_seconds: float) -> None:
        meta = self.meta_path(file_id)
        meta.write_text(
            json.dumps({"duration_seconds": float(duration_seconds)}, separators=(",", ":")),
            encoding="utf-8",
        )

    def delete_completed(self, file_id: str) -> bool:
        """Unrecoverably delete blob + drop its manifest line."""
        path = self.blob_path(file_id)
        meta = self.meta_path(file_id)
        existed = path.is_file() or meta.is_file() or self._manifest_has(file_id)
        if not existed:
            return False

        secure_delete(path)
        meta.unlink(missing_ok=True)
        self._rewrite_manifest_without(file_id)
        return True

    def _manifest_has(self, file_id: str) -> bool:
        if not self.manifest_path.is_file():
            return False
        prefix = f"{file_id}\t"
        with self.manifest_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(prefix):
                    return True
        return False

    def _rewrite_manifest_without(self, file_id: str) -> None:
        if not self.manifest_path.is_file():
            return
        prefix = f"{file_id}\t"
        tmp = self.manifest_path.with_suffix(".db.tmp")
        with self.manifest_path.open("r", encoding="utf-8") as src, tmp.open(
            "w", encoding="utf-8"
        ) as dst:
            for line in src:
                if line.startswith(prefix):
                    continue
                dst.write(line)
            dst.flush()
            os.fsync(dst.fileno())
        tmp.replace(self.manifest_path)
