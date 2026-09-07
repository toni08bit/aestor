"""Offline country lookup for peer IPs (MaxMind GeoLite2 Country)."""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_reader = None
_tried = False


def _load_reader(path: Path):
    global _reader, _tried
    if _tried:
        return _reader
    _tried = True
    if not path.is_file():
        log.warning("GeoIP DB missing at %s — peer flags disabled", path)
        return None
    try:
        import geoip2.database

        _reader = geoip2.database.Reader(str(path))
        log.info("GeoIP loaded from %s", path)
    except Exception:
        log.exception("failed to load GeoIP DB")
        _reader = None
    return _reader


@lru_cache(maxsize=4096)
def country_code_for_ip(ip: str, db_path: str = "/usr/share/GeoIP/GeoLite2-Country.mmdb") -> Optional[str]:
    """Return ISO 3166-1 alpha-2 country code, or None."""
    if not ip or ip in {"?", "127.0.0.1", "::1"}:
        return None
    # Skip private / link-local ranges quickly
    if ip.startswith(("10.", "192.168.", "169.254.", "fc", "fd", "fe80")):
        return None
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return None
        except Exception:
            pass

    # Allow override from env via settings path when called with explicit path
    import os

    path = os.environ.get("GEOIP_DB_PATH", db_path)
    reader = _load_reader(Path(path))
    if reader is None:
        return None
    try:
        return reader.country(ip).country.iso_code
    except Exception:
        return None
