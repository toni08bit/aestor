"""Job registry + encrypted outer-API manifest (uuid → encrypted name lines)."""

from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Deque, Optional

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
SPEED_HISTORY_MAX = 90  # ~3 minutes at 2s poll, more at 1s
META_SUFFIX = ".json"


class JobRecord:
    def __init__(
        self,
        *,
        kind: JobKind,
        name: str,
        source: str,
        torrent_path: Optional[Path] = None,
    ) -> None:
        now = utcnow()
        self.id = new_id()
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

    def push_speed(self, down: float, up: float = 0.0) -> None:
        self.speed_history.append(SpeedSample(t=time.time(), down=down, up=up))

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
    """In-memory jobs + on-disk encrypted manifest / UUID-named blobs."""

    def __init__(self, completed_dir: Path, encryptor: Encryptor) -> None:
        self.jobs: dict[str, JobRecord] = {}
        self.completed_dir = completed_dir
        self.encryptor = encryptor
        self.manifest_path = completed_dir / MANIFEST_NAME
        self.completed_dir.mkdir(parents=True, exist_ok=True)
        if not self.manifest_path.exists():
            self.manifest_path.write_text("", encoding="utf-8")

    def add_job(self, job: JobRecord) -> JobRecord:
        self.jobs[job.id] = job
        return job

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        return self.jobs.get(job_id)

    def remove_job(self, job_id: str) -> Optional[JobRecord]:
        return self.jobs.pop(job_id, None)

    def list_jobs(self) -> list[JobInfo]:
        return sorted(
            (j.to_info() for j in self.jobs.values()),
            key=lambda x: x.created_at,
            reverse=True,
        )

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
        self.encryptor.encrypt_file(source_path, dest, on_progress=on_progress)

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
