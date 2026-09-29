import asyncio
import time
from typing import AsyncGenerator, Optional
from src.ingestion.parser import parse_jsonl, NetworkEvent


class EventReplayer:
    """
    Replays network events from a JSONL file at specified speed multiplier.
    """

    def __init__(self, speed: float = 1.0):
        self.speed = speed

    async def replay(self, filepath: str) -> AsyncGenerator[NetworkEvent, None]:
        events = list(parse_jsonl(filepath))
        if not events:
            return

        # Sort events by timestamp to ensure chronological order
        events.sort(key=lambda e: e.timestamp)
        
        prev_ts: Optional[float] = None

        for event in events:
            if prev_ts is not None and self.speed > 0 and self.speed < 1000:
                time_diff = event.timestamp - prev_ts
                if time_diff > 0:
                    delay = time_diff / self.speed
                    # Cap single event delay to 2 seconds for smooth demo execution
                    delay = min(delay, 2.0)
                    await asyncio.sleep(delay)

            prev_ts = event.timestamp
            yield event
