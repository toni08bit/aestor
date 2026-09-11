#!/usr/bin/env python3
"""Continuously pull completed aestor files, decrypt locally, then delete remote.

  python3 scripts/pull.py \\
    --base-url https://aestor.example \\
    --token "$API_BEARER_TOKEN" \\
    --key data/keys/private.pem \\
    --out ./pulled

Pairs exclusively with the server using a stable client id (hostname + machine-id).
If another client is paired, pass --override to take over. After pairing, reports
status/progress to the server for the web UI. Polls /api/v1/list, downloads each
blob, decrypts under --out using the encrypted manifest name, then DELETE
/api/v1/files/{uuid}. When the list is empty, sleeps --interval and tries again.

Decryption and plaintext filenames stay on this machine — never sent to the server.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
ENC_PATH = ROOT / "backend" / "app" / "services" / "encryption.py"

_UNSAFE = re.compile(r"[^\w.\- ()\[\]]+", re.UNICODE)
CLIENT_ID_HEADER = "X-Aestor-Client-Id"


def _load_mod():
    spec = importlib.util.spec_from_file_location("aestor_encryption", ENC_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ENC_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ts() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"[{_ts()}] {msg}", flush=True)


def log_err(msg: str) -> None:
    print(f"[{_ts()}] {msg}", file=sys.stderr, flush=True)


def _fmt_bytes(n: Optional[int]) -> str:
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TiB"


def _fmt_rate(bps: float) -> str:
    if bps <= 0:
        return "—"
    return f"{_fmt_bytes(int(bps))}/s"


def _fmt_dur(seconds: float) -> str:
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m{s:02d}s"


def _safe_name(name: str, fallback: str) -> str:
    base = Path(name or "").name.strip() or fallback
    cleaned = _UNSAFE.sub("_", base).strip(" ._")
    return cleaned or fallback


def _unique_path(directory: Path, filename: str) -> Path:
    dest = directory / filename
    if not dest.exists():
        return dest
    stem = dest.stem
    suffix = dest.suffix
    n = 1
    while True:
        candidate = directory / f"{stem}-{n}{suffix}"
        if not candidate.exists():
            return candidate
        n += 1


def _read_machine_id() -> Optional[str]:
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text
    return None


def _persist_fallback_id() -> str:
    cache = Path.home() / ".cache" / "aestor"
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / "client-id"
    if path.is_file():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    value = str(uuid.uuid4())
    path.write_text(value + "\n", encoding="utf-8")
    return value


def default_client_id() -> str:
    """Stable-ish id: hostname + short hash of machine-id (or persisted UUID)."""
    host = socket.gethostname().strip() or "unknown"
    machine = _read_machine_id() or _persist_fallback_id()
    digest = hashlib.sha256(machine.encode("utf-8")).hexdigest()[:12]
    return f"{host}:{digest}"


def default_hostname() -> str:
    return socket.gethostname().strip() or "unknown"


class Progress:
    """Emit a log line at start, every 5%, and at completion."""

    def __init__(
        self,
        label: str,
        total: Optional[int] = None,
        on_tick: Optional[Callable[["Progress"], None]] = None,
    ) -> None:
        self.label = label
        self.total = total if total and total > 0 else None
        self.done = 0
        self.started = time.monotonic()
        self._next_pct = 0
        self._last_log = 0.0
        self._finished = False
        self._on_tick = on_tick
        if self.total is None:
            log(f"{self.label} starting (size unknown)")
        else:
            log(f"{self.label} starting — {_fmt_bytes(self.total)} total")
            self._emit(force=True)

    @property
    def rate_bps(self) -> float:
        elapsed = max(time.monotonic() - self.started, 1e-9)
        return self.done / elapsed

    @property
    def progress(self) -> Optional[float]:
        if self.total is None or self.total <= 0:
            return None
        return min(1.0, self.done / self.total)

    def update(self, done: int, total: Optional[int] = None) -> None:
        if total is not None and total > 0:
            self.total = total
        self.done = max(0, done)
        self._emit(force=False)

    def finish(self) -> None:
        if self._finished:
            return
        if self.total is not None:
            self.done = self.total
        self._emit(force=True, final=True)

    def _emit(self, *, force: bool, final: bool = False) -> None:
        now = time.monotonic()
        elapsed = max(now - self.started, 1e-9)
        rate = self.done / elapsed

        if self._on_tick is not None:
            try:
                self._on_tick(self)
            except Exception:
                pass

        if self.total is None:
            if not force and not final and (now - self._last_log) < 2.0:
                return
            suffix = " done" if final else ""
            log(
                f"{self.label} {_fmt_bytes(self.done)} received "
                f"({_fmt_rate(rate)}, {_fmt_dur(elapsed)}){suffix}"
            )
            self._last_log = now
            if final:
                self._finished = True
            return

        pct = 100 if final else int(100.0 * self.done / self.total)
        milestone = 100 if final else min(95, (pct // 5) * 5)
        if not force and not final and milestone < self._next_pct:
            return

        eta = ""
        if not final and rate > 0 and self.done < self.total:
            eta = f", ETA {_fmt_dur((self.total - self.done) / rate)}"

        status = "done" if final else "…"
        log(
            f"{self.label} {milestone:3d}%  "
            f"{_fmt_bytes(self.done)} / {_fmt_bytes(self.total)}  "
            f"({_fmt_rate(rate)}, {_fmt_dur(elapsed)}{eta})  {status}"
        )
        self._last_log = now
        self._next_pct = milestone + 5
        if final:
            self._finished = True


class Client:
    def __init__(
        self,
        base_url: str,
        token: str,
        client_id: str,
        timeout: float = 120.0,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.client_id = client_id
        self.timeout = timeout
        self._last_status_at = 0.0

    def _headers(self, *, with_client: bool = True) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.token}"}
        if with_client:
            headers[CLIENT_ID_HEADER] = self.client_id
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        with_client: bool = True,
    ) -> bytes:
        headers = self._headers(with_client=with_client)
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=body,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} → HTTP {exc.code}: {err_body}") from exc

    def pair(self, hostname: str, override: bool) -> dict[str, Any]:
        payload = json.dumps(
            {
                "client_id": self.client_id,
                "hostname": hostname,
                "override": override,
            }
        ).encode("utf-8")
        try:
            raw = self._request(
                "POST",
                "/api/v1/pair",
                body=payload,
                content_type="application/json",
                with_client=False,
            )
        except RuntimeError as exc:
            msg = str(exc)
            if "HTTP 409" in msg:
                raise RuntimeError(
                    "another pull client is already paired; re-run with --override "
                    f"to take over. Server said: {msg}"
                ) from exc
            raise
        return json.loads(raw.decode("utf-8") or "{}")

    def report_status(
        self,
        *,
        phase: str,
        file_id: Optional[str] = None,
        bytes_done: Optional[int] = None,
        bytes_total: Optional[int] = None,
        progress: Optional[float] = None,
        rate_bps: Optional[float] = None,
        message: Optional[str] = None,
        queue_remaining: Optional[int] = None,
        files_pulled: Optional[int] = None,
        force: bool = False,
        min_interval: float = 0.35,
    ) -> None:
        now = time.monotonic()
        if not force and (now - self._last_status_at) < min_interval:
            return
        payload: dict[str, Any] = {
            "client_id": self.client_id,
            "phase": phase,
        }
        if file_id is not None:
            payload["file_id"] = file_id
        if bytes_done is not None:
            payload["bytes_done"] = bytes_done
        if bytes_total is not None:
            payload["bytes_total"] = bytes_total
        if progress is not None:
            payload["progress"] = progress
        if rate_bps is not None:
            payload["rate_bps"] = rate_bps
        if message is not None:
            payload["message"] = message
        if queue_remaining is not None:
            payload["queue_remaining"] = queue_remaining
        if files_pulled is not None:
            payload["files_pulled"] = files_pulled
        try:
            self._request(
                "POST",
                "/api/v1/status",
                body=json.dumps(payload).encode("utf-8"),
                content_type="application/json",
                with_client=False,
            )
            self._last_status_at = now
        except Exception as exc:
            # Status is best-effort — never block the pull loop on UI updates.
            log_err(f"status report failed: {exc}")

    def list_manifest(self) -> str:
        return self._request("GET", "/api/v1/list").decode("utf-8")

    def download(
        self,
        file_id: str,
        dest: Path,
        label: str,
        on_tick: Optional[Callable[[Progress], None]] = None,
    ) -> int:
        req = urllib.request.Request(
            f"{self.base}/api/v1/files/{file_id}",
            method="GET",
            headers=self._headers(with_client=True),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp, dest.open(
                "wb"
            ) as out:
                cl = resp.headers.get("Content-Length")
                total = int(cl) if cl and cl.isdigit() else None
                prog = Progress(label, total, on_tick=on_tick)
                done = 0
                while True:
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    prog.update(done, total)
                prog.finish()
                return done
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GET /api/v1/files/{file_id} → HTTP {exc.code}: {body}") from exc

    def delete(self, file_id: str) -> None:
        self._request("DELETE", f"/api/v1/files/{file_id}")


def process_one(
    *,
    mod,
    client: Client,
    key: Path,
    out_dir: Path,
    work_dir: Path,
    file_id: str,
    name: str,
    index: int,
    total_files: int,
    files_pulled: int,
) -> Path:
    enc_path = work_dir / file_id
    safe = _safe_name(name, file_id)
    plain_path = _unique_path(out_dir, safe)
    tag = f"[{index}/{total_files}]"
    queue_remaining = max(0, total_files - index + 1)

    log(f"{tag} queue item id={file_id}")
    log(f"{tag} remote name: {name!r} → local {plain_path.name}")

    try:
        log(f"{tag} downloading encrypted blob…")

        def on_dl(prog: Progress) -> None:
            client.report_status(
                phase="downloading",
                file_id=file_id,
                bytes_done=prog.done,
                bytes_total=prog.total,
                progress=prog.progress,
                rate_bps=prog.rate_bps,
                message=f"downloading {file_id}",
                queue_remaining=queue_remaining,
                files_pulled=files_pulled,
            )

        client.report_status(
            phase="downloading",
            file_id=file_id,
            message=f"downloading {file_id}",
            queue_remaining=queue_remaining,
            files_pulled=files_pulled,
            force=True,
        )
        enc_bytes = client.download(file_id, enc_path, f"{tag} download", on_tick=on_dl)

        log(f"{tag} decrypting {_fmt_bytes(enc_bytes)} → {plain_path.name}…")
        client.report_status(
            phase="decrypting",
            file_id=file_id,
            bytes_done=0,
            bytes_total=enc_path.stat().st_size,
            progress=0.0,
            message=f"decrypting {file_id}",
            queue_remaining=queue_remaining,
            files_pulled=files_pulled,
            force=True,
        )
        dec_prog = Progress(f"{tag} decrypt", enc_path.stat().st_size)

        def on_dec(done: int, total: int) -> None:
            dec_prog.update(done, total)
            client.report_status(
                phase="decrypting",
                file_id=file_id,
                bytes_done=done,
                bytes_total=total,
                progress=(done / total) if total else None,
                rate_bps=dec_prog.rate_bps,
                message=f"decrypting {file_id}",
                queue_remaining=queue_remaining,
                files_pulled=files_pulled,
            )

        plain_bytes = mod.decrypt_file(key, enc_path, plain_path, on_progress=on_dec)
        dec_prog.finish()
        log(f"{tag} decrypted {_fmt_bytes(plain_bytes)} plaintext")

        log(f"{tag} deleting remote {file_id}…")
        client.report_status(
            phase="deleting",
            file_id=file_id,
            progress=1.0,
            message=f"deleting {file_id}",
            queue_remaining=queue_remaining,
            files_pulled=files_pulled,
            force=True,
        )
        client.delete(file_id)
        log(f"{tag} remote deleted")
    except Exception:
        log_err(f"{tag} FAILED — cleaning local partials")
        plain_path.unlink(missing_ok=True)
        raise
    finally:
        if enc_path.exists():
            enc_path.unlink(missing_ok=True)
            log(f"{tag} removed temp blob {enc_path.name}")

    log(f"{tag} ✓ done → {plain_path}")
    return plain_path


def run(args: argparse.Namespace) -> int:
    log(f"loading encryption module from {ENC_PATH}")
    mod = _load_mod()
    if not args.key.is_file():
        log_err(f"private key not found: {args.key}")
        return 1

    out_dir: Path = args.out
    work_dir = out_dir / ".tmp"
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    client_id = args.client_id or default_client_id()
    hostname = args.hostname or default_hostname()
    client = Client(args.base_url, args.token, client_id, timeout=args.timeout)

    log(f"pulling from {client.base}")
    log(f"client id: {client_id}")
    log(f"hostname: {hostname}")
    log(f"output dir: {out_dir.resolve()}")
    log(f"private key: {args.key}")
    log(f"idle interval: {args.interval}s  http timeout: {args.timeout}s")
    if args.override:
        log("override enabled — will displace any currently paired client")

    try:
        info = client.pair(hostname, override=args.override)
        log(
            f"paired ok — online={info.get('online')} "
            f"files_pulled={info.get('files_pulled')}"
        )
    except Exception as exc:
        log_err(f"pairing failed: {exc}")
        return 1

    log("entering poll loop (Ctrl-C to stop)")

    cycle = 0
    pulled_total = int(info.get("files_pulled") or 0)

    while True:
        cycle += 1
        log(f"── cycle {cycle}: listing remote files…")
        client.report_status(
            phase="listing",
            message="listing remote files",
            files_pulled=pulled_total,
            force=True,
        )
        try:
            text = client.list_manifest()
            rows = mod.parse_manifest_text(text)
        except Exception as exc:
            log_err(f"list failed: {exc}")
            client.report_status(
                phase="error",
                message=str(exc)[:500],
                files_pulled=pulled_total,
                force=True,
            )
            log(f"retrying in {args.interval}s")
            time.sleep(args.interval)
            continue

        if not rows:
            log(f"remote list empty — idle {args.interval}s (pulled so far: {pulled_total})")
            client.report_status(
                phase="idle",
                message="waiting for completed files",
                queue_remaining=0,
                files_pulled=pulled_total,
                force=True,
            )
            # Heartbeat during idle so the UI stays "online".
            deadline = time.monotonic() + max(0.0, args.interval)
            while time.monotonic() < deadline:
                time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))
                if time.monotonic() < deadline:
                    client.report_status(
                        phase="idle",
                        message="waiting for completed files",
                        queue_remaining=0,
                        files_pulled=pulled_total,
                        force=True,
                    )
            continue

        log(f"found {len(rows)} file(s) pending (session total pulled: {pulled_total})")

        for i, (file_id, b64) in enumerate(rows, start=1):
            tag = f"[{i}/{len(rows)}]"
            try:
                log(f"{tag} decrypting manifest line for {file_id}…")
                payload = mod.decrypt_manifest_line(args.key, b64)
                name = str(payload.get("name") or file_id)
                extras = {k: v for k, v in payload.items() if k != "name"}
                if extras:
                    log(f"{tag} manifest extras: {extras}")
                process_one(
                    mod=mod,
                    client=client,
                    key=args.key,
                    out_dir=out_dir,
                    work_dir=work_dir,
                    file_id=file_id,
                    name=name,
                    index=i,
                    total_files=len(rows),
                    files_pulled=pulled_total,
                )
                pulled_total += 1
                client.report_status(
                    phase="idle",
                    message=f"pulled {file_id}",
                    queue_remaining=max(0, len(rows) - i),
                    files_pulled=pulled_total,
                    force=True,
                )
            except Exception as exc:
                log_err(f"{tag} {file_id}: {exc}")
                client.report_status(
                    phase="error",
                    file_id=file_id,
                    message=str(exc)[:500],
                    files_pulled=pulled_total,
                    force=True,
                )
                log(f"{tag} leaving remote file in place for retry")
                continue

        log(f"cycle {cycle} finished — re-listing immediately")
        continue


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pair, pull, decrypt, and delete aestor completed files in a loop"
    )
    parser.add_argument("--base-url", required=True, help="aestor origin, e.g. https://host:8080")
    parser.add_argument("--token", required=True, help="API_BEARER_TOKEN")
    parser.add_argument("--key", required=True, type=Path, help="RSA private key (PEM)")
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Directory for decrypted files",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds to sleep when the remote list is empty (default: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="HTTP timeout seconds per request (default: 300)",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help="Override auto client id (default: hostname:machine-hash)",
    )
    parser.add_argument(
        "--hostname",
        default=None,
        help="Hostname shown in the web UI (default: system hostname)",
    )
    parser.add_argument(
        "--override",
        action="store_true",
        help="Displace whatever client is currently paired",
    )
    return run(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log_err("stopped by Ctrl-C")
        raise SystemExit(130)
