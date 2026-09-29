import asyncio
from typing import Optional, Dict, Any
from src.ingestion.parser import NetworkEvent


class EventQueue:
    """
    Bounded async queue for streaming network events with backpressure and drop tracking.
    """

    def __init__(self, max_size: int = 10000, drop_on_overflow: bool = True):
        self.max_size = max_size
        self.drop_on_overflow = drop_on_overflow
        self._queue: asyncio.Queue[NetworkEvent] = asyncio.Queue(maxsize=max_size)
        self.events_received: int = 0
        self.events_processed: int = 0
        self.events_dropped: int = 0

    def put_nowait(self, event: NetworkEvent) -> bool:
        """
        Attempts to put an event into the queue non-blockingly.
        If full and drop_on_overflow is True, increments events_dropped and drops event.
        Returns True if queued, False if dropped.
        """
        self.events_received += 1
        if self._queue.full():
            if self.drop_on_overflow:
                self.events_dropped += 1
                return False
            else:
                raise asyncio.QueueFull("Event queue is full")
        else:
            self._queue.put_nowait(event)
            return True

    async def put(self, event: NetworkEvent) -> bool:
        """
        Puts event in queue, dropping if full or waiting if backpressure configured.
        """
        self.events_received += 1
        if self._queue.full() and self.drop_on_overflow:
            self.events_dropped += 1
            return False
        
        await self._queue.put(event)
        return True

    async def get(self) -> NetworkEvent:
        """
        Retrieves the next event from queue and increments processed count.
        """
        event = await self._queue.get()
        self.events_processed += 1
        self._queue.task_done()
        return event

    def get_nowait(self) -> NetworkEvent:
        """
        Non-blocking get from queue.
        """
        event = self._queue.get_nowait()
        self.events_processed += 1
        self._queue.task_done()
        return event

    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()

    def get_stats(self) -> Dict[str, Any]:
        return {
            "events_received": self.events_received,
            "events_processed": self.events_processed,
            "events_dropped": self.events_dropped,
            "queue_size": self.size(),
            "max_size": self.max_size
        }
