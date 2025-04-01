import asyncio
import logging
from typing import Any

LOGGER = logging.getLogger(__name__)


class AsyncMaxSizeQueue(asyncio.Queue):
    """An asyncio queue with maximum size that discards oldest items when full."""

    def __init__(self, maxsize: int = 1000):
        """Initialize queue with maximum size.

        Args:
            maxsize: Maximum number of items in queue. Defaults to 1000.
        """
        super().__init__(maxsize=maxsize)
        self._discarded_count = 0
        self._first_overflow_logged = False
        self._log_threshold = max(1, int(maxsize * 0.1))  # 10% of maxsize

    def _should_log(self) -> bool:
        """Determine if we should log based on threshold rules.

        Returns:
            bool: True if the discard event should be logged
        """
        if not self._first_overflow_logged:
            self._first_overflow_logged = True
            return True
        return self._discarded_count % self._log_threshold == 0

    async def put(self, item: Any) -> None:
        """Put an item into the queue, removing oldest if full.

        When the queue is full, removes the oldest item to make room for the new item.
        Tracks discarded items and logs at appropriate intervals.

        Args:
            item: Item to put in queue
        """
        while True:
            try:
                # Try to put the item without waiting
                self.put_nowait(item)
                break
            except asyncio.QueueFull:
                try:
                    # If queue is full, remove oldest item
                    _ = self.get_nowait()
                    self._discarded_count += 1
                    if self._should_log():
                        LOGGER.warning(
                            f"{self._discarded_count=} items discarded due to queue overflow "
                            f"(logging every {self._log_threshold=} items)"
                        )
                except asyncio.QueueEmpty:
                    # This should not happen with a full queue, but just in case
                    await asyncio.sleep(0.01)
