from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    """Standard UUID string used as the finished-file identity."""
    return str(uuid4())


class JobKind(str, enum.Enum):
    MAGNET = "magnet"
    TORRENT = "torrent"
    HTTP = "http"


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    DOWNLOADING = "downloading"
    PAUSED = "paused"
    ENCRYPTING = "encrypting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobCreate(BaseModel):
    """Add a magnet or direct HTTP(S) URL."""

    url: str = Field(..., min_length=1, max_length=8192)
    name: Optional[str] = Field(None, max_length=512)


class SpeedSample(BaseModel):
    t: float  # unix seconds
    down: float
    up: float = 0.0


class PeerInfo(BaseModel):
    ip: str
    port: int = 0
    client: str = ""
    down_speed: float = 0.0
    up_speed: float = 0.0
    progress: float = 0.0
    seed: bool = False
    encrypted: bool = False
    connection: str = ""
    country: Optional[str] = None  # ISO 3166-1 alpha-2


class JobInfo(BaseModel):
    id: str
    kind: JobKind
    status: JobStatus
    name: str
    progress: float = 0.0
    download_rate: float = 0.0
    upload_rate: float = 0.0
    total_bytes: Optional[int] = None
    downloaded_bytes: int = 0
    uploaded_bytes: int = 0
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_file_id: Optional[str] = None

    # Extended torrent / transfer detail
    state: Optional[str] = None
    eta_seconds: Optional[float] = None
    num_peers: int = 0
    num_seeds: int = 0
    list_peers: int = 0
    list_seeds: int = 0
    num_pieces: int = 0
    pieces_done: int = 0
    distributed_copies: float = 0.0
    current_tracker: Optional[str] = None
    has_metadata: bool = False
    save_path: Optional[str] = None
    info_hash: Optional[str] = None
    active_duration_seconds: float = 0.0
    payload_download_rate: float = 0.0
    payload_upload_rate: float = 0.0
    peers: list[PeerInfo] = Field(default_factory=list)
    speed_history: list[SpeedSample] = Field(default_factory=list)
    source_preview: Optional[str] = None


class CompletedIdInfo(BaseModel):
    """Web UI listing — uuid + size (+ duration); names live in the encrypted manifest."""

    id: str
    encrypted_size_bytes: int
    duration_seconds: Optional[float] = None


class LoginRequest(BaseModel):
    password: str


class PullPhase(str, enum.Enum):
    IDLE = "idle"
    LISTING = "listing"
    DOWNLOADING = "downloading"
    DECRYPTING = "decrypting"
    DELETING = "deleting"
    ERROR = "error"


class PairRequest(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=256)
    hostname: Optional[str] = Field(None, max_length=256)
    override: bool = False


class PullStatusUpdate(BaseModel):
    """Progress from the paired pull client. Never includes plaintext filenames."""

    client_id: str = Field(..., min_length=1, max_length=256)
    phase: PullPhase
    file_id: Optional[str] = Field(None, max_length=64)
    bytes_done: Optional[int] = Field(None, ge=0)
    bytes_total: Optional[int] = Field(None, ge=0)
    progress: Optional[float] = Field(None, ge=0.0, le=1.0)
    rate_bps: Optional[float] = Field(None, ge=0.0)
    message: Optional[str] = Field(None, max_length=512)
    queue_remaining: Optional[int] = Field(None, ge=0)
    files_pulled: Optional[int] = Field(None, ge=0)


class PullClientInfo(BaseModel):
    """Paired pull client + live progress for the web UI."""

    paired: bool = False
    client_id: Optional[str] = None
    hostname: Optional[str] = None
    paired_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    online: bool = False
    phase: Optional[PullPhase] = None
    file_id: Optional[str] = None
    bytes_done: Optional[int] = None
    bytes_total: Optional[int] = None
    progress: Optional[float] = None
    rate_bps: Optional[float] = None
    message: Optional[str] = None
    queue_remaining: Optional[int] = None
    files_pulled: Optional[int] = None


class StatusResponse(BaseModel):
    dev_mode: bool
    public_ip: Optional[str] = None
    active_jobs: int
    completed_files: int
    ntfy_enabled: bool = False
    pull: PullClientInfo = Field(default_factory=PullClientInfo)
