"""Hybrid encryption: RSA-OAEP wraps AES-256-GCM keys.

File blob (completed/{uuid}):
  magic      : b"AESTOR01" (8 bytes)
  rsa_len    : u32
  rsa_blob   : RSA-OAEP(aes_key[32] || nonce[12])
  payload    : AES-256-GCM(file_bytes)

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
from pathlib import Path
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FILE_MAGIC = b"AESTOR01"
LINE_MAGIC = b"AESTORL1"


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

    def encrypt_file(self, source: Path, destination: Path) -> int:
        """Encrypt file bytes → destination named by UUID. Returns encrypted size."""
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        cipher = AESGCM(aes_key).encrypt(nonce, source.read_bytes(), associated_data=FILE_MAGIC)
        rsa_blob = self._rsa_wrap(aes_key + nonce)

        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as out:
            out.write(FILE_MAGIC)
            out.write(struct.pack(">I", len(rsa_blob)))
            out.write(rsa_blob)
            out.write(cipher)
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


def decrypt_file(private_key_path: Path, source: Path, destination: Path) -> None:
    """Offline decrypt of a completed/{uuid} blob."""
    private_key = _load_private(private_key_path)
    data = source.read_bytes()
    if data[:8] != FILE_MAGIC:
        raise ValueError("bad file magic")
    offset = 8
    (rsa_len,) = struct.unpack(">I", data[offset : offset + 4])
    offset += 4
    rsa_blob = data[offset : offset + rsa_len]
    offset += rsa_len
    cipher = data[offset:]
    wrap = _rsa_unwrap(private_key, rsa_blob)
    aes_key, nonce = wrap[:32], wrap[32:44]
    plain = AESGCM(aes_key).decrypt(nonce, cipher, associated_data=FILE_MAGIC)
    destination.write_bytes(plain)


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
