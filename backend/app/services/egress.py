"""Cached egress public IP for the UI status strip (not a kill switch)."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import httpx

log = logging.getLogger(__name__)

_IP_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
)


class EgressInfo:
    def __init__(self, *, poll_interval: float = 60.0) -> None:
        self._poll_interval = poll_interval
        self._ip: Optional[str] = None
        self._task: Optional[asyncio.Task] = None

    @property
    def public_ip(self) -> Optional[str]:
        return self._ip

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(initial=True), name="egress-ip")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self, *, initial: bool = False) -> None:
        if initial:
            try:
                await self.refresh()
            except Exception:
                log.exception("egress ip initial refresh failed")
        while True:
            await asyncio.sleep(self._poll_interval)
            try:
                await self.refresh()
            except Exception:
                log.exception("egress ip refresh failed")

    async def refresh(self) -> Optional[str]:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            for url in _IP_URLS:
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    ip = resp.text.strip().split()[0]
                    if not ip:
                        continue
                    if self._ip and ip != self._ip:
                        # Last resort: egress changed. Die hard — no recovery path.
                        log.error("egress IP changed %s → %s — exiting", self._ip, ip)
                        os._exit(1)
                    if ip != self._ip:
                        log.info("egress public ip: %s", ip)
                    self._ip = ip
                    return self._ip
                except Exception as exc:
                    log.debug("egress lookup via %s failed: %s", url, exc)
        return self._ip
