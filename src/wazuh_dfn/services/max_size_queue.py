import logging
import queue
from typing import Any

LOGGER = logging.getLogger(__name__)


class MaxSizeQueue(queue.Queue):
    """A queue with maximum size that discards oldest items when full."""

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
        """Determine if we should log based on threshold rules."""
        if not self._first_overflow_logged:
            self._first_overflow_logged = True
            return True
        return self._discarded_count % self._log_threshold == 0

    def put(self, item: Any, block: bool = True, timeout: float | None = None) -> None:
        """Put an item into the queue, removing oldest if full.

        Args:
            item: Item to put in queue
            block: Whether to block if queue is full (ignored, always False)
            timeout: How long to wait if blocking (ignored)
        """
        while True:
            try:
                super().put(item, block=False)
                break
            except queue.Full:
                try:
                    _ = self.get_nowait()
                    self._discarded_count += 1
                    if self._should_log():
                        LOGGER.warning(
                            f"{self._discarded_count=} items discarded due to queue overflow "
                            f"(logging every {self._log_threshold=} items)"
                        )
                except queue.Empty:
                    pass  # Should not happen, but just in case
