import json
import logging
import os
from datetime import datetime
from queue import Queue
from typing import Optional

LOGGER = logging.getLogger(__name__)

# Maximum chunk size to read at once
CHUNK_SIZE = 8192


class FileMonitor:
    def __init__(
        self,
        file_path: str,
        alert_queue: Queue,
        alert_prefix: str,
        tail: bool = False,
    ) -> None:
        self.file_path = file_path
        self.alert_queue = alert_queue
        self.alert_prefix = alert_prefix.encode("utf-8")
        self.alert_suffix = b"}"  # Just the closing brace
        self.tail = tail

        self.fp = None
        self.buffer = bytearray()
        self.current_inode = None
        self.latest_queue_put: Optional[datetime] = None

        # Stats tracking
        self.processed_alerts = 0
        self.errors = 0
        self.last_stats_time = datetime.now()
        self.last_processed_alerts = 0
        self.last_errors = 0

        LOGGER.info(f"Initialized FileMonitor for {file_path}")

    def open(self) -> bool:
        """Open the file and initialize position."""
        if self.fp:
            try:
                self.fp.close()
            except Exception:
                pass

        try:
            self.fp = open(self.file_path, "rb")
            if not self.tail:
                self.fp.seek(0, os.SEEK_END)

            stat = os.stat(self.file_path)
            self.current_inode = stat.st_ino
            return True
        except Exception as e:
            LOGGER.error(f"Error opening file: {str(e)}")
            self.fp = None
            return False

    def close(self) -> None:
        if self.fp:
            try:
                self.fp.close()
            except Exception:
                pass
        self.fp = None
        self.buffer = bytearray()

    def _check_inode(self) -> bool:
        try:
            current_stat = os.stat(self.file_path)
            if current_stat.st_ino != self.current_inode:
                LOGGER.info(f"File {self.file_path} rotated (inode changed)")
                self.current_inode = current_stat.st_ino
                self.buffer = bytearray()
                return True
            return False
        except Exception as e:
            LOGGER.error(f"Error checking inode: {str(e)}")
            return False

    def _find_line_ending(self, start_pos: int) -> int:
        """Find the next line ending position after start_pos."""
        pos = start_pos
        while pos < len(self.buffer):
            if self.buffer[pos : pos + 2] == b"\r\n":
                return pos + 2
            if self.buffer[pos : pos + 1] in [b"\n", b"\r"]:
                return pos + 1
            pos += 1
        return -1

    def _extract_alert(self) -> Optional[bytes]:
        """Extract a complete alert from the buffer if available."""
        start = self.buffer.find(self.alert_prefix)
        if start == -1:
            if len(self.buffer) > CHUNK_SIZE * 2:
                self.buffer.clear()
            return None

        if start > 0:
            del self.buffer[:start]

        end = self.buffer.find(self.alert_suffix)
        if end == -1:
            return None

        end_pos = end + len(self.alert_suffix)
        if end_pos >= len(self.buffer):
            return None

        line_end = self._find_line_ending(end_pos)
        if line_end == -1:
            return None

        alert_bytes = bytes(self.buffer[:line_end])
        del self.buffer[:line_end]
        return alert_bytes

    def _queue_alert(self, alert_bytes: bytes) -> None:
        """Process and queue an alert."""
        try:
            alert_str = alert_bytes.decode("utf-8").rstrip()
            LOGGER.debug(f"Processing alert: {alert_str}")
            alert_data = json.loads(alert_str)
            self.alert_queue.put(alert_data)
            self.latest_queue_put = datetime.now()
            self.processed_alerts += 1
            LOGGER.debug("Queued alert successfully")
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            self.errors += 1
            LOGGER.debug(f"Error processing alert: {str(e)}")

    def _process_buffer(self) -> None:
        """Process buffer content to find and queue complete alerts."""
        while True:
            alert_bytes = self._extract_alert()
            if not alert_bytes:
                break
            self._queue_alert(alert_bytes)

    def check_file(self) -> None:
        """Check file for new alerts."""
        try:
            LOGGER.debug("Checking file")
            if not self.fp and not self.open():
                return

            if not os.path.exists(self.file_path):
                LOGGER.warning(f"File {self.file_path} no longer exists")
                return

            if self._check_inode() and not self.open():
                return

            # Read new content
            while True:
                chunk = self.fp.read(CHUNK_SIZE)
                if not chunk:
                    break
                LOGGER.debug(f"Read chunk: {chunk}")
                self.buffer.extend(chunk)
                self._process_buffer()

        except Exception as e:
            LOGGER.error(f"Error checking file {self.file_path}: {str(e)}")

    def log_stats(self) -> tuple[float, float, int, int]:
        """Calculate and return statistics since last call.

        Returns:
            tuple[float, float, int, int]: (alerts per second, error rate percentage,
                                          total processed alerts, total errors)
        """
        current_time = datetime.now()
        time_diff = (current_time - self.last_stats_time).total_seconds()

        if time_diff <= 0:
            return 0.0, 0.0, self.processed_alerts, self.errors

        alerts_diff = self.processed_alerts - self.last_processed_alerts
        errors_diff = self.errors - self.last_errors

        alerts_per_second = alerts_diff / time_diff
        error_rate = (errors_diff / max(alerts_diff, 1)) * 100 if alerts_diff > 0 else 0.0

        # Update last values
        self.last_stats_time = current_time
        self.last_processed_alerts = self.processed_alerts
        self.last_errors = self.errors

        return alerts_per_second, error_rate, self.processed_alerts, self.errors
