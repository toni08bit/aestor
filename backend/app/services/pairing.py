"""Exclusive pull-client pairing and status for the web UI."""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.models import PullClientInfo, PullPhase, utcnow

log = logging.getLogger(__name__)

# Consider the pull client offline if no heartbeat within this window.
ONLINE_TTL_SECONDS = 45.0


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class PairingConflict(Exception):
    """Raised when another client is already paired and override was not set."""

    def __init__(self, current: PullClientInfo) -> None:
        self.current = current
        super().__init__(
            f"already paired to {current.client_id}"
            + (f" ({current.hostname})" if current.hostname else "")
        )


class PairingService:
    """Single-slot pairing: one pull client owns list/download/delete."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {}
        self._dirty_disk = False
        self._last_persist = 0.0
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            self._data = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._data = raw if isinstance(raw, dict) else {}
        except Exception:
            log.exception("failed to load pairing state from %s", self.path)
            self._data = {}

    def _save(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_persist) < 2.0:
            self._dirty_disk = True
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, default=str) + "\n", encoding="utf-8")
        tmp.replace(self.path)
        self._last_persist = now
        self._dirty_disk = False

    def _is_online(self, last_seen: Optional[datetime]) -> bool:
        if last_seen is None:
            return False
        age = (utcnow() - last_seen).total_seconds()
        return age <= ONLINE_TTL_SECONDS

    def to_info(self) -> PullClientInfo:
        with self._lock:
            if not self._data.get("client_id"):
                return PullClientInfo(paired=False)
            last_seen = _parse_dt(self._data.get("last_seen"))
            phase_raw = self._data.get("phase") or PullPhase.IDLE.value
            try:
                phase = PullPhase(phase_raw)
            except ValueError:
                phase = PullPhase.IDLE
            return PullClientInfo(
                paired=True,
                client_id=str(self._data.get("client_id")),
                hostname=self._data.get("hostname") or None,
                paired_at=_parse_dt(self._data.get("paired_at")),
                last_seen=last_seen,
                online=self._is_online(last_seen),
                phase=phase,
                file_id=self._data.get("file_id") or None,
                bytes_done=self._data.get("bytes_done"),
                bytes_total=self._data.get("bytes_total"),
                progress=self._data.get("progress"),
                rate_bps=self._data.get("rate_bps"),
                message=self._data.get("message") or None,
                queue_remaining=self._data.get("queue_remaining"),
                files_pulled=self._data.get("files_pulled"),
            )

    def pair(
        self,
        *,
        client_id: str,
        hostname: Optional[str] = None,
        override: bool = False,
    ) -> PullClientInfo:
        client_id = (client_id or "").strip()
        if not client_id:
            raise ValueError("client_id is required")
        hostname = (hostname or "").strip() or None

        with self._lock:
            current_id = self._data.get("client_id")
            if current_id and current_id != client_id and not override:
                raise PairingConflict(self.to_info())

            now = utcnow()
            same = current_id == client_id
            self._data = {
                "client_id": client_id,
                "hostname": hostname,
                "paired_at": (self._data.get("paired_at") if same else now.isoformat()),
                "last_seen": now.isoformat(),
                "phase": PullPhase.IDLE.value,
                "file_id": None,
                "bytes_done": None,
                "bytes_total": None,
                "progress": None,
                "rate_bps": None,
                "message": "paired" if not same else "reconnected",
                "queue_remaining": None,
                "files_pulled": self._data.get("files_pulled") if same else 0,
            }
            if not same:
                log.info(
                    "pull client paired: id=%s hostname=%s override=%s",
                    client_id,
                    hostname,
                    override,
                )
            self._save(force=True)
            return self.to_info()

    def clear(self) -> None:
        with self._lock:
            self._data = {}
            if self.path.is_file():
                self.path.unlink(missing_ok=True)
            self._dirty_disk = False

    def require_client(self, client_id: Optional[str]) -> None:
        """Raise PermissionError if client_id is not the paired one."""
        client_id = (client_id or "").strip()
        with self._lock:
            paired = self._data.get("client_id")
            if not paired:
                raise PermissionError("no pull client paired")
            if not client_id:
                raise PermissionError("X-Aestor-Client-Id required")
            if client_id != paired:
                raise PermissionError(
                    f"paired to a different client ({paired}); use --override to take over"
                )

    def touch(self, client_id: str) -> None:
        with self._lock:
            if self._data.get("client_id") != client_id:
                return
            self._data["last_seen"] = utcnow().isoformat()
            self._save()

    def update_status(
        self,
        *,
        client_id: str,
        phase: PullPhase,
        file_id: Optional[str] = None,
        bytes_done: Optional[int] = None,
        bytes_total: Optional[int] = None,
        progress: Optional[float] = None,
        rate_bps: Optional[float] = None,
        message: Optional[str] = None,
        queue_remaining: Optional[int] = None,
        files_pulled: Optional[int] = None,
    ) -> PullClientInfo:
        with self._lock:
            if self._data.get("client_id") != client_id:
                raise PermissionError("not the paired pull client")
            self._data["last_seen"] = utcnow().isoformat()
            self._data["phase"] = phase.value
            self._data["file_id"] = file_id
            self._data["bytes_done"] = bytes_done
            self._data["bytes_total"] = bytes_total
            self._data["progress"] = progress
            self._data["rate_bps"] = rate_bps
            if message is not None:
                self._data["message"] = message
            if queue_remaining is not None:
                self._data["queue_remaining"] = queue_remaining
            if files_pulled is not None:
                self._data["files_pulled"] = files_pulled
            self._save(force=True)
            return self.to_info()
