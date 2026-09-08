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
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

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

    def download(self, file_id: str, dest: Path) -> None:
        req = urllib.request.Request(
            f"{self.base}/api/v1/files/{file_id}",
            method="GET",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp, dest.open(
                "wb"
            ) as out:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
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
) -> Path:
    enc_path = work_dir / file_id
    safe = _safe_name(name, file_id)
    plain_path = _unique_path(out_dir, safe)

    print(f"↓  {file_id}  →  {plain_path.name}", flush=True)
    try:
        client.download(file_id, enc_path)
        mod.decrypt_file(key, enc_path, plain_path)
        client.delete(file_id)
    except Exception:
        plain_path.unlink(missing_ok=True)
        raise
    finally:
        enc_path.unlink(missing_ok=True)

    print(f"✓  deleted remote {file_id}", flush=True)
    return plain_path


def run(args: argparse.Namespace) -> int:
    mod = _load_mod()
    if not args.key.is_file():
        print(f"private key not found: {args.key}", file=sys.stderr)
        return 1

    out_dir: Path = args.out
    work_dir = out_dir / ".tmp"
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    client = Client(args.base_url, args.token, timeout=args.timeout)
    print(
        f"pulling from {client.base} → {out_dir} (interval={args.interval}s)",
        flush=True,
    )

    while True:
        try:
            text = client.list_manifest()
            rows = mod.parse_manifest_text(text)
        except Exception as exc:
            print(f"! list failed: {exc}", file=sys.stderr, flush=True)
            time.sleep(args.interval)
            continue

        if not rows:
            print(f"· idle ({args.interval}s)", flush=True)
            time.sleep(args.interval)
            continue

        for file_id, b64 in rows:
            try:
                payload = mod.decrypt_manifest_line(args.key, b64)
                name = str(payload.get("name") or file_id)
                process_one(
                    mod=mod,
                    client=client,
                    key=args.key,
                    out_dir=out_dir,
                    work_dir=work_dir,
                    file_id=file_id,
                    name=name,
                )
            except Exception as exc:
                print(f"! {file_id}: {exc}", file=sys.stderr, flush=True)
                # Continue with the next file; failed ones stay remote for retry.
                continue

        # Immediately re-list in case more finished while we were pulling.
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
        print("\nstopped", file=sys.stderr)
        raise SystemExit(130)
