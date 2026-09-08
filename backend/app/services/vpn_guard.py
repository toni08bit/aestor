"""VPN / gluetun health gate. Blocks downloads when the tunnel is down."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from app.config import Settings

log = logging.getLogger(__name__)


class VpnGuard:
    """Tracks whether outbound download traffic is allowed.

    Production: polls gluetun's HTTP control server. Gluetun's firewall is the
    real kill switch (clearnet blocked when the tunnel is down). This layer
    pauses libtorrent/HTTP so we do not keep trying a dead path.

    Dev mode: intentional clearnet — always allows traffic (no gluetun).
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # Fail closed until the first successful check (unless DEV_MODE).
        self._ok = bool(settings.dev_mode)
        self._detail: dict = {"mode": "dev" if settings.dev_mode else "gluetun"}
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None
        self._listeners: list = []

    @property
    def ok(self) -> bool:
        return self._ok

    @property
    def detail(self) -> dict:
        return dict(self._detail)

    def on_change(self, callback) -> None:
        self._listeners.append(callback)

    async def start(self) -> None:
        if self._settings.dev_mode:
            self._ok = True
            self._detail = {"mode": "dev", "vpn_required": False}
            log.warning("DEV_MODE enabled — VPN gate disabled; traffic may use clearnet")
            return
        # Fail closed until we confirm the tunnel is up.
        self._ok = False
        await self.refresh()
        if not self._ok:
            log.warning("VPN not confirmed at startup — downloads blocked until tunnel is up")
        self._task = asyncio.create_task(self._loop(), name="vpn-guard")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self.refresh()
            except Exception:
                log.exception("vpn guard refresh failed")
            await asyncio.sleep(self._settings.vpn_poll_interval)

    async def refresh(self) -> bool:
        if self._settings.dev_mode:
            async with self._lock:
                self._ok = True
                self._detail = {"mode": "dev", "vpn_required": False}
            return True

        base = self._settings.gluetun_control_url.rstrip("/")
        previous = self._ok
        ok = False
        detail: dict = {"mode": "gluetun", "vpn_required": True}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # /v1/vpn/status works for WireGuard and OpenVPN.
                # /v1/openvpn/status reports "stopped" under WireGuard even when up.
                status_resp = await client.get(f"{base}/v1/vpn/status")
                if status_resp.status_code == 200:
                    body = status_resp.json()
                    status_val = str(body.get("status", "")).lower()
                    ok = status_val in {"running", "connected"}
                    detail["vpn_status"] = body
                else:
                    detail["vpn_status_http"] = status_resp.status_code
                    ok = False

                try:
                    ip_resp = await client.get(f"{base}/v1/publicip/ip")
                    if ip_resp.status_code == 200:
                        detail["public_ip"] = ip_resp.json()
                except Exception as exc:
                    detail["public_ip_error"] = str(exc)
        except Exception as exc:
            detail["error"] = str(exc)
            ok = False
            log.warning("gluetun unreachable: %s", exc)

        async with self._lock:
            self._ok = ok
            self._detail = detail

        if previous != ok:
            log.warning("VPN gate changed: ok=%s detail=%s", ok, detail)
            for cb in self._listeners:
                try:
                    result = cb(ok)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    log.exception("vpn listener error")

        return ok

    async def wait_until_ok(self, check_interval: float = 2.0) -> None:
        while not self._ok:
            await asyncio.sleep(check_interval)
