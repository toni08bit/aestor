#!/usr/bin/env python3
"""Continuously pull completed aestor files, decrypt locally, then delete remote.

  python3 scripts/pull.py \\
    --base-url https://aestor.example \\
    --token "$API_BEARER_TOKEN" \\
    --key data/keys/private.pem \\
    --out ./pulled

Polls /api/v1/list, downloads each blob one by one, decrypts under --out using
the encrypted manifest name, then DELETE /api/v1/files/{uuid}. When the list is
empty, sleeps --interval seconds and tries again.

Logs a progress line with stats at least every 5% for download and decrypt.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
ENC_PATH = ROOT / "backend" / "app" / "services" / "encryption.py"

_UNSAFE = re.compile(r"[^\w.\- ()\[\]]+", re.UNICODE)


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


class Progress:
    """Emit a log line at start, every 5%, and at completion."""

    def __init__(self, label: str, total: Optional[int] = None) -> None:
        self.label = label
        self.total = total if total and total > 0 else None
        self.done = 0
        self.started = time.monotonic()
        self._next_pct = 0
        self._last_log = 0.0
        self._finished = False
        if self.total is None:
            log(f"{self.label} starting (size unknown)")
        else:
            log(f"{self.label} starting — {_fmt_bytes(self.total)} total")
            self._emit(force=True)

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

        if self.total is None:
            # Unknown total: log every ~2s or on force/final.
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
        # Milestone: 0, 5, 10, … — 100% only via finish() so it prints once as "done"
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
    def __init__(self, base_url: str, token: str, timeout: float = 120.0) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str) -> bytes:
        req = urllib.request.Request(
            f"{self.base}{path}",
            method=method,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} → HTTP {exc.code}: {body}") from exc

    def list_manifest(self) -> str:
        return self._request("GET", "/api/v1/list").decode("utf-8")

    def download(self, file_id: str, dest: Path, label: str) -> int:
        req = urllib.request.Request(
            f"{self.base}/api/v1/files/{file_id}",
            method="GET",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp, dest.open(
                "wb"
            ) as out:
                cl = resp.headers.get("Content-Length")
                total = int(cl) if cl and cl.isdigit() else None
                prog = Progress(label, total)
                done = 0
                while True:
                    chunk = resp.read(1024 * 1024)
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
) -> Path:
    enc_path = work_dir / file_id
    safe = _safe_name(name, file_id)
    plain_path = _unique_path(out_dir, safe)
    tag = f"[{index}/{total_files}]"

    log(f"{tag} queue item id={file_id}")
    log(f"{tag} remote name: {name!r} → local {plain_path.name}")

    try:
        log(f"{tag} downloading encrypted blob…")
        enc_bytes = client.download(file_id, enc_path, f"{tag} download")

        log(f"{tag} decrypting {_fmt_bytes(enc_bytes)} → {plain_path.name}…")
        dec_prog = Progress(f"{tag} decrypt", enc_path.stat().st_size)

        def on_dec(done: int, total: int) -> None:
            dec_prog.update(done, total)

        plain_bytes = mod.decrypt_file(key, enc_path, plain_path, on_progress=on_dec)
        dec_prog.finish()
        log(f"{tag} decrypted {_fmt_bytes(plain_bytes)} plaintext")

        log(f"{tag} deleting remote {file_id}…")
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

    client = Client(args.base_url, args.token, timeout=args.timeout)
    log(f"pulling from {client.base}")
    log(f"output dir: {out_dir.resolve()}")
    log(f"private key: {args.key}")
    log(f"idle interval: {args.interval}s  http timeout: {args.timeout}s")
    log("entering poll loop (Ctrl-C to stop)")

    cycle = 0
    pulled_total = 0

    while True:
        cycle += 1
        log(f"── cycle {cycle}: listing remote files…")
        try:
            text = client.list_manifest()
            rows = mod.parse_manifest_text(text)
        except Exception as exc:
            log_err(f"list failed: {exc}")
            log(f"retrying in {args.interval}s")
            time.sleep(args.interval)
            continue

        if not rows:
            log(f"remote list empty — idle {args.interval}s (pulled so far: {pulled_total})")
            time.sleep(args.interval)
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
                )
                pulled_total += 1
            except Exception as exc:
                log_err(f"{tag} {file_id}: {exc}")
                log(f"{tag} leaving remote file in place for retry")
                continue

        log(f"cycle {cycle} finished — re-listing immediately")
        continue


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pull, decrypt, and delete aestor completed files in a loop"
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
        default=15.0,
        help="Seconds to sleep when the remote list is empty (default: 15)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="HTTP timeout seconds per request (default: 300)",
    )
    return run(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log_err("stopped by Ctrl-C")
        raise SystemExit(130)
