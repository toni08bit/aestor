#!/usr/bin/env python3
"""Client-side decrypt helpers for aestor blobs and the outer-API list.

Decrypt a finished file:
  python3 scripts/decrypt.py file --key data/keys/private.pem \\
    --in <uuid-blob> --out restored.bin

Decrypt /api/v1/list contents:
  python3 scripts/decrypt.py list --key data/keys/private.pem --in manifest.db
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENC_PATH = ROOT / "backend" / "app" / "services" / "encryption.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("aestor_encryption", ENC_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ENC_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cmd_file(mod, args: argparse.Namespace) -> int:
    mod.decrypt_file(args.key, args.src, args.dst)
    print(f"Wrote {args.dst}", file=sys.stderr)
    return 0


def cmd_list(mod, args: argparse.Namespace) -> int:
    text = args.src.read_text(encoding="utf-8")
    rows = []
    for uid, b64 in mod.parse_manifest_text(text):
        payload = mod.decrypt_manifest_line(args.key, b64)
        rows.append({"id": uid, "payload": payload})
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt aestor outputs")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_file = sub.add_parser("file", help="Decrypt a completed/{uuid} blob")
    p_file.add_argument("--key", required=True, type=Path)
    p_file.add_argument("--in", dest="src", required=True, type=Path)
    p_file.add_argument("--out", dest="dst", required=True, type=Path)

    p_list = sub.add_parser("list", help="Decrypt an /api/v1/list manifest")
    p_list.add_argument("--key", required=True, type=Path)
    p_list.add_argument("--in", dest="src", required=True, type=Path)

    args = parser.parse_args()
    mod = _load_mod()
    if args.cmd == "file":
        return cmd_file(mod, args)
    if args.cmd == "list":
        return cmd_list(mod, args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
