"""
Lightweight pub/sub for pushing live updates to the dashboard via
Server-Sent Events (SSE). Chosen over WebSockets because it needs no extra
dependency beyond plain HTTP/ASGI streaming -- a better fit for a
low-memory box per the project's constraints.
"""
from __future__ import annotations

import asyncio
import json


class Broadcaster:
    def __init__(self):
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, message: dict) -> None:
        payload = json.dumps(message, default=str)
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                # Slow consumer -- drop the oldest rather than block the collector.
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except asyncio.QueueEmpty:
                    pass


broadcaster = Broadcaster()


async def sse_event_stream(q: asyncio.Queue):
    try:
        yield "retry: 2000\n\n"
        while True:
            payload = await q.get()
            yield f"data: {payload}\n\n"
    except asyncio.CancelledError:
        raise
