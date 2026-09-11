"""Hybrid encryption: RSA-OAEP wraps AES-256-GCM keys.

File blob v1 (legacy, completed/{uuid}):
  magic      : b"AESTOR01" (8 bytes)
  rsa_len    : u32 BE
  rsa_blob   : RSA-OAEP(aes_key[32] || nonce[12])
  payload    : AES-256-GCM(entire file)   # limited to < 2 GiB

File blob v2 (streaming, completed/{uuid}):
  magic      : b"AESTOR02" (8 bytes)
  rsa_len    : u32 BE
  rsa_blob   : RSA-OAEP(aes_key[32] || nonce_base[12])
  repeated until EOF:
    ct_len   : u32 BE
    ct||tag  : AES-256-GCM(chunk i)
  Per-chunk nonce = nonce_base[:8] || u32be(i)
  Per-chunk AAD   = magic || u32be(i)

Manifest line ciphertext (base64, one per finished item):
  magic      : b"AESTORL1" (8 bytes)
  rsa_len    : u32
  rsa_blob   : RSA-OAEP(aes_key[32] || nonce[12])
  payload    : AES-256-GCM(json)

Manifest file text format (served as-is to the outer API client):
  {uuid}\\t{base64(line_ciphertext)}\\n

The server never stores the plaintext name. The client decrypts each line.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import time
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FILE_MAGIC_V1 = b"AESTOR01"
FILE_MAGIC_V2 = b"AESTOR02"
FILE_MAGIC = FILE_MAGIC_V2  # current write format
LINE_MAGIC = b"AESTORL1"

# Plaintext chunk size for streaming file encryption (well under AESGCM's 2^31-1 cap).
CHUNK_SIZE = 4 * 1024 * 1024

ProgressCb = Callable[[int, int], None]


def _chunk_nonce(nonce_base: bytes, index: int) -> bytes:
    if len(nonce_base) != 12:
        raise ValueError("nonce base must be 12 bytes")
    if index < 0 or index >= 2**32:
        raise ValueError("chunk index out of range")
    return nonce_base[:8] + struct.pack(">I", index)


def _chunk_aad(magic: bytes, index: int) -> bytes:
    return magic + struct.pack(">I", index)


class Encryptor:
    def __init__(self, public_key_path: Path) -> None:
        if not public_key_path.is_file():
            raise FileNotFoundError(f"Encryption public key not found: {public_key_path}")
        pem = public_key_path.read_bytes()
        self._public_key = serialization.load_pem_public_key(pem, backend=default_backend())

    def _rsa_wrap(self, raw: bytes) -> bytes:
        return self._public_key.encrypt(
            raw,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def encrypt_file(
        self,
        source: Path,
        destination: Path,
        on_progress: Optional[ProgressCb] = None,
    ) -> int:
        """Stream-encrypt file → destination. Returns encrypted size.

        Uses AESTOR02 chunked AES-256-GCM so files larger than ~2 GiB work and
        peak memory stays near CHUNK_SIZE rather than the whole file.
        """
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce_base = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        rsa_blob = self._rsa_wrap(aes_key + nonce_base)

        total = source.stat().st_size
        done = 0
        destination.parent.mkdir(parents=True, exist_ok=True)

        with source.open("rb") as inp, destination.open("wb") as out:
            out.write(FILE_MAGIC_V2)
            out.write(struct.pack(">I", len(rsa_blob)))
            out.write(rsa_blob)

            index = 0
            while True:
                chunk = inp.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = aesgcm.encrypt(
                    _chunk_nonce(nonce_base, index),
                    chunk,
                    associated_data=_chunk_aad(FILE_MAGIC_V2, index),
                )
                out.write(struct.pack(">I", len(ct)))
                out.write(ct)
                done += len(chunk)
                index += 1
                if on_progress is not None:
                    on_progress(done, total)
                # Yield so the asyncio LiveHub thread can push WS snapshots during
                # long encrypts (tight read/encrypt/write otherwise starves it).
                if index % 2 == 0:
                    time.sleep(0.001)

        if on_progress is not None and total == 0:
            on_progress(0, 0)

        return destination.stat().st_size

    def encrypt_manifest_payload(self, payload: dict[str, Any]) -> str:
        """Return base64 ciphertext for one manifest line (uuid→name mapping)."""
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        cipher = AESGCM(aes_key).encrypt(nonce, plain, associated_data=LINE_MAGIC)
        rsa_blob = self._rsa_wrap(aes_key + nonce)
        blob = LINE_MAGIC + struct.pack(">I", len(rsa_blob)) + rsa_blob + cipher
        return base64.b64encode(blob).decode("ascii")


def _load_private(private_key_path: Path) -> RSAPrivateKey:
    pem = private_key_path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("expected RSA private key")
    return key


def _rsa_unwrap(private_key: RSAPrivateKey, rsa_blob: bytes) -> bytes:
    return private_key.decrypt(
        rsa_blob,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _read_exact(fh, n: int) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        raise ValueError("truncated blob truncated")
    return data


def decrypt_file(
    private_key_path: Path,
    source: Path,
    destination: Path,
    on_progress: Optional[ProgressCb] = None,
) -> int:
    """Offline decrypt of a completed/{uuid} blob (AESTOR01 or AESTOR02).

    Returns plaintext byte count. ``on_progress(done, total)`` reports encrypted
    bytes consumed vs source size (same shape as encrypt_file).
    """
    private_key = _load_private(private_key_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = source.stat().st_size
    plain_total = 0

    def _report(pos: int) -> None:
        if on_progress is not None:
            on_progress(min(pos, total), total)

    with source.open("rb") as inp, destination.open("wb") as out:
        magic = _read_exact(inp, 8)
        (rsa_len,) = struct.unpack(">I", _read_exact(inp, 4))
        rsa_blob = _read_exact(inp, rsa_len)
        wrap = _rsa_unwrap(private_key, rsa_blob)
        if len(wrap) < 44:
            raise ValueError("bad wrapped key material")
        aes_key, nonce_base = wrap[:32], wrap[32:44]
        aesgcm = AESGCM(aes_key)
        _report(inp.tell())

        if magic == FILE_MAGIC_V2:
            index = 0
            while True:
                len_bytes = inp.read(4)
                if not len_bytes:
                    break
                if len(len_bytes) != 4:
                    raise ValueError("ciphertext blob truncated")
                (ct_len,) = struct.unpack(">I", len_bytes)
                if ct_len < 16 or ct_len > CHUNK_SIZE + 16:
                    raise ValueError("invalid chunk length")
                ct = _read_exact(inp, ct_len)
                plain = aesgcm.decrypt(
                    _chunk_nonce(nonce_base, index),
                    ct,
                    associated_data=_chunk_aad(FILE_MAGIC_V2, index),
                )
                out.write(plain)
                plain_total += len(plain)
                index += 1
                _report(inp.tell())
            if on_progress is not None and total == 0:
                on_progress(0, 0)
            return plain_total

        if magic == FILE_MAGIC_V1:
            cipher = inp.read()
            plain = aesgcm.decrypt(nonce_base, cipher, associated_data=FILE_MAGIC_V1)
            out.write(plain)
            plain_total = len(plain)
            _report(total)
            return plain_total

        raise ValueError("bad file magic")


def decrypt_manifest_line(private_key_path: Path, b64_ciphertext: str) -> dict[str, Any]:
    """Decrypt one manifest line ciphertext → payload dict."""
    private_key = _load_private(private_key_path)
    data = base64.b64decode(b64_ciphertext.strip())
    if data[:8] != LINE_MAGIC:
        raise ValueError("bad line magic")
    offset = 8
    (rsa_len,) = struct.unpack(">I", data[offset : offset + 4])
    offset += 4
    rsa_blob = data[offset : offset + rsa_len]
    offset += rsa_len
    cipher = data[offset:]
    wrap = _rsa_unwrap(private_key, rsa_blob)
    aes_key, nonce = wrap[:32], wrap[32:44]
    plain = AESGCM(aes_key).decrypt(nonce, cipher, associated_data=LINE_MAGIC)
    return json.loads(plain.decode("utf-8"))


def parse_manifest_text(text: str) -> list[tuple[str, str]]:
    """Parse manifest file into (uuid, b64_ciphertext) pairs."""
    rows: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" not in line:
            raise ValueError(f"malformed manifest line: {line[:40]}")
        uid, b64 = line.split("\t", 1)
        rows.append((uid.strip(), b64.strip()))
    return rows
