"""Optional ntfy.sh (or self-hosted) push notifications."""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import Settings

log = logging.getLogger(__name__)


class NtfyNotifier:
    def __init__(self, settings: Settings) -> None:
        self._enabled = bool(settings.ntfy_topic.strip()) and settings.ntfy_enabled
        self._server = settings.ntfy_server.rstrip("/")
        self._topic = settings.ntfy_topic.strip()
        self._token = (settings.ntfy_token or "").strip()
        self._default_priority = settings.ntfy_priority
        self._events = {
            e.strip().lower()
            for e in settings.ntfy_events.split(",")
            if e.strip()
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    def wants(self, event: str) -> bool:
        if not self._enabled:
            return False
        if "all" in self._events:
            return True
        return event.lower() in self._events

    async def send(
        self,
        *,
        event: str,
        title: str,
        message: str,
        tags: Optional[str] = None,
        priority: Optional[int] = None,
        click: Optional[str] = None,
        force: bool = False,
    ) -> None:
        if not self._enabled:
            return
        if not force and not self.wants(event):
            return
        url = f"{self._server}/{self._topic}"
        headers = {
            "Title": title[:250],
            "Priority": str(priority if priority is not None else self._default_priority),
        }
        if tags:
            headers["Tags"] = tags
        if click:
            headers["Click"] = click
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, content=message.encode("utf-8"), headers=headers)
                resp.raise_for_status()
            log.info("ntfy sent event=%s title=%s", event, title)
        except Exception:
            log.exception("ntfy send failed event=%s", event)

    async def completed(self, *, name: str, file_id: str, size_bytes: int) -> None:
        await self.send(
            event="completed",
            title="aestor · download complete",
            message=f"{name}\nuuid: {file_id}\nencrypted & listed",
            tags="white_check_mark,inbox_tray",
            priority=3,
        )

    async def failed(self, *, name: str, error: str) -> None:
        await self.send(
            event="failed",
            title="aestor · download failed",
            message=f"{name}\n{error}",
            tags="x,warning",
            priority=4,
        )
