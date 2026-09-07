"""WebSocket live updates for the web UI."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Optional, Set

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

log = logging.getLogger(__name__)

SnapshotFn = Callable[[], dict[str, Any]]


class LiveHub:
    def __init__(self) -> None:
        self._clients: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._dirty = True
        self._task: Optional[asyncio.Task] = None
        self._get_snapshot: Optional[SnapshotFn] = None
        self._interval = 0.35

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def mark_dirty(self) -> None:
        self._dirty = True

    async def start(self, get_snapshot: SnapshotFn, interval: float = 0.35) -> None:
        self._get_snapshot = get_snapshot
        self._interval = interval
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="live-hub")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        async with self._lock:
            clients = list(self._clients)
            self._clients.clear()
        for ws in clients:
            try:
                await ws.close()
            except Exception:
                pass

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        self._dirty = True
        # Immediate snapshot so the UI is not blank while waiting for the ticker
        await self._send_one(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def _loop(self) -> None:
        while True:
            try:
                if self._clients and (self._dirty or True):
                    # Always push while clients are connected for smooth speed graphs
                    await self.broadcast()
                    self._dirty = False
            except Exception:
                log.exception("live hub broadcast failed")
            await asyncio.sleep(self._interval)

    async def broadcast(self) -> None:
        if not self._get_snapshot:
            return
        payload = self._get_snapshot()
        async with self._lock:
            clients = list(self._clients)
        stale: list[WebSocket] = []
        for ws in clients:
            try:
                if ws.client_state != WebSocketState.CONNECTED:
                    stale.append(ws)
                    continue
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            await self.disconnect(ws)

    async def _send_one(self, ws: WebSocket) -> None:
        if not self._get_snapshot:
            return
        try:
            await ws.send_json(self._get_snapshot())
        except Exception:
            await self.disconnect(ws)

    async def listen(self, ws: WebSocket) -> None:
        """Keep the socket open; client may send ping / refresh."""
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("type") in {"ping", "refresh"}:
                    await self._send_one(ws)
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            await self.disconnect(ws)
