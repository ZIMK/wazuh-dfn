import json
import logging
import secrets
import time
from datetime import datetime
from pathlib import Path
from wazuh_dfn.services.max_size_queue import MaxSizeQueue

LOGGER = logging.getLogger(__name__)

# Maximum chunk size to read at once
CHUNK_SIZE = 8192

# Maximum message size (64KB as per Wazuh server)
MAX_MESSAGE_SIZE = 64 * 1024 * 2

# Maximum time to wait for incomplete alerts (seconds)
MAX_WAIT_TIME = 1.0


class FileMonitor:

    def __init__(
        self,
        file_path: str,
        alert_queue: MaxSizeQueue,
        alert_prefix: str,
        tail: bool = False,
        failed_alerts_path: str | None = None,  # Add path for storing failed alerts
        max_failed_files: int = 100,  # Maximum number of failed alert files to keep
        store_failed_alerts: bool = False,
    ) -> None:
        self.file_path = file_path
        self.alert_queue = alert_queue
        self.alert_prefix = alert_prefix.encode("utf-8")
        self.alert_suffix = b"}"  # Just the closing brace
        self.tail = tail
        self.failed_alerts_path = failed_alerts_path
        self.max_failed_files = max_failed_files
        self.store_failed_alerts = store_failed_alerts

        self.fp = None
        self.buffer = bytearray()
        self.current_inode = None
        self.latest_queue_put: datetime | None = None
        self.last_complete_position = 0  # Track position of last complete alert

        # Stats tracking
        self.processed_alerts = 0
        self.errors = 0
        self.replaced_alerts = 0  # Add counter for replaced alerts
        self.last_stats_time = datetime.now()

        LOGGER.info(f"Initialized FileMonitor for {file_path}")

    def open(self) -> bool:
        """Open the file and initialize position."""
        if self.fp:
            try:
                self.fp.close()
            except Exception as e:
                LOGGER.error(f"Error closing file: {e!s}")

        try:
            file_path_obj = Path(self.file_path)
            self.fp = file_path_obj.open("rb")
            if not self.tail:
                self.fp.seek(0, 2)  # SEEK_END
                self.last_complete_position = self.fp.tell()

            stat = file_path_obj.stat()
            self.current_inode = stat.st_ino
            return True
        except Exception as e:
            LOGGER.error(f"Error opening file: {e!s}")
            self.fp = None
            return False

    def close(self) -> None:
        if self.fp:
            try:
                self.fp.close()
            except Exception as e:
                LOGGER.error(f"Error closing file: {e!s}")
        self.fp = None
        self.buffer = bytearray()

    def _check_inode(self) -> bool:
        try:
            file_path_obj = Path(self.file_path)
            current_stat = file_path_obj.stat()
            if current_stat.st_ino != self.current_inode:
                LOGGER.info(f"File {self.file_path} rotated (inode changed)")
                self.current_inode = current_stat.st_ino
                self.buffer = bytearray()
                return True
            return False
        except Exception as e:
            LOGGER.error(f"Error checking inode: {e!s}")
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

    def _extract_alert(self) -> bytes | None:
        """Extract a complete alert from the buffer if available."""
        start = self.buffer.find(self.alert_prefix)
        if start == -1:
            if len(self.buffer) > MAX_MESSAGE_SIZE:
                LOGGER.debug(f"{len(self.buffer)=} - no alert prefix found, clearing buffer")
                self.buffer.clear()
            return None

        if start > 0:
            LOGGER.debug(f"{start=} bytes of leading data before alert prefix, removing")
            del self.buffer[:start]

        end = self.buffer.find(self.alert_suffix, len(self.alert_prefix))
        if end == -1:
            # If we have too much data without finding a suffix, something is wrong
            if len(self.buffer) > MAX_MESSAGE_SIZE:
                LOGGER.warning(f"Buffer overflow ({len(self.buffer)} bytes) without finding alert suffix")
                self.buffer.clear()
            return None

        end_pos = end + len(self.alert_suffix)
        if end_pos >= len(self.buffer):
            return None

        line_end = self._find_line_ending(end_pos)
        if line_end == -1:
            if len(self.buffer) > MAX_MESSAGE_SIZE:
                LOGGER.warning("No line ending found in large buffer, possible corrupted data")
                self.buffer.clear()
            return None

        alert_bytes = bytes(self.buffer[:line_end])
        LOGGER.debug(f"Extracted alert of {len(alert_bytes)} bytes")
        del self.buffer[:line_end]
        return alert_bytes

    def _save_failed_alert(self, alert_bytes: bytes, alert_str: str | None = None) -> None:
        """Save failed alert to file."""
        if not self.store_failed_alerts or not self.failed_alerts_path:
            return

        try:
            self._cleanup_failed_alerts()
            # Add random component to timestamp to ensure uniqueness
            random_suffix = str(secrets.randbelow(999999) + 100000)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            failed_path = Path(self.failed_alerts_path)
            failed_file = failed_path / f"{timestamp}_{random_suffix}_failed_alert.json"

            failed_file.write_bytes(alert_bytes)

            if alert_str:
                replaced_file = failed_path / f"{timestamp}_{random_suffix}_replaced_alert.json"
                replaced_file.write_bytes(alert_str.encode("utf-8"))
                LOGGER.info(f"Saved failed alert and replaced version to {failed_file} and {replaced_file}")
            else:
                LOGGER.info(f"Saved failed alert to {failed_file}")
        except Exception as save_error:
            LOGGER.error(f"Error saving failed alert: {save_error!s}")

    def _process_alert_with_replace(self, alert_bytes: bytes) -> bool:
        """Try processing alert with character replacement."""
        try:
            alert_str = alert_bytes.decode("utf-8", errors="replace").rstrip()
            alert_data = json.loads(alert_str)
            self.alert_queue.put(alert_data)
            self.latest_queue_put = datetime.now()
            self.processed_alerts += 1
            self.replaced_alerts += 1  # Increment replaced alerts counter
            LOGGER.warning("Alert processed with character replacement")
            self._save_failed_alert(alert_bytes, alert_str)
            return True
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False

    def _queue_alert(self, alert_bytes: bytes) -> None:
        """Process and queue an alert."""
        try:
            # First try strict decoding
            alert_str = alert_bytes.decode("utf-8", errors="strict").rstrip()
            alert_data = json.loads(alert_str)
            self.alert_queue.put(alert_data)
            self.latest_queue_put = datetime.now()
            self.processed_alerts += 1
            LOGGER.debug("Queued alert successfully")
            return
        except UnicodeDecodeError:
            # Try with replace if strict decode fails
            if self._process_alert_with_replace(alert_bytes):
                return
        except json.JSONDecodeError:
            pass  # Fall through to error handling

        # Handle all failures
        self.errors += 1
        LOGGER.error(f"Error processing alert, raw content: {alert_bytes.hex()}")
        self._save_failed_alert(alert_bytes)

    def _cleanup_failed_alerts(self) -> None:
        """Remove oldest failed alert files if exceeding max_failed_files."""
        if not self.failed_alerts_path:
            return

        try:
            failed_path = Path(self.failed_alerts_path)
            files = [
                f for f in failed_path.iterdir() if "_failed_alert.json" in f.name or "_replaced_alert.json" in f.name
            ]

            if len(files) <= self.max_failed_files:
                return

            # Sort files by creation time, oldest first
            files.sort(key=lambda x: x.stat().st_ctime)

            # Remove oldest files that exceed the limit
            files_to_remove = files[: (len(files) - self.max_failed_files)]
            for file_path in files_to_remove:
                try:
                    file_path.unlink()
                    LOGGER.debug(f"Removed old failed alert file: {file_path}")
                except Exception as e:
                    LOGGER.error(f"Error removing old failed alert file {file_path}: {e!s}")

        except Exception as e:
            LOGGER.error(f"Error during failed alerts cleanup: {e!s}")

    def _process_buffer(self) -> None:
        """Process buffer content to find and queue complete alerts."""
        while alert_bytes := self._extract_alert():
            self._queue_alert(alert_bytes)

    def _wait_for_data(self, wait_start: float | None) -> float | None:
        """Wait for more data if buffer contains incomplete alert."""
        if len(self.buffer) > 0:
            if wait_start is None:
                return time.time()
            elif time.time() - wait_start > MAX_WAIT_TIME:
                LOGGER.debug("Max wait time reached, will process buffer in next round")
                return None
            time.sleep(0.1)
            return wait_start
        return None

    def _handle_file_status(self) -> bool:
        """Check file existence and handle rotation."""
        if not self.fp and not self.open():
            return False

        file_path_obj = Path(self.file_path)
        if not file_path_obj.exists():
            LOGGER.warning(f"File {self.file_path} no longer exists")
            return False

        if self._check_inode():
            LOGGER.info("File rotation detected, clearing buffer")
            self.buffer.clear()
            return self.open()

        return True

    def _process_chunk(self, chunk: bytes) -> tuple[bool, int]:
        """Process a chunk of data from the file."""
        if not chunk:
            return False, 0

        LOGGER.debug(f"{len(chunk)=} bytes at position {self.fp.tell()}")
        self.buffer.extend(chunk)

        buffer_position = 0
        alerts_found = False

        while True:
            buffer_size_before = len(self.buffer)
            alert_bytes = self._extract_alert()
            if not alert_bytes:
                break

            try:
                self._queue_alert(alert_bytes)
                alerts_found = True
                buffer_position += buffer_size_before - len(self.buffer)
            except Exception as e:
                LOGGER.error(f"Error processing alert: {e!s}, alert size: {len(alert_bytes)}")
                if len(alert_bytes) > 0:
                    LOGGER.debug(f"First 100 bytes of failed alert: {alert_bytes[:100].hex()}")
                raise

        return alerts_found, buffer_position

    def check_file(self) -> None:
        """Check file for new alerts."""
        try:
            LOGGER.debug(f"{len(self.buffer)=}, checking file")

            if not self._handle_file_status():
                return

            start_position = self.fp.tell()
            alerts_found = False
            wait_start = None
            buffer_position = 0

            while True:
                chunk = self.fp.read(CHUNK_SIZE)
                if not chunk:
                    wait_start = self._wait_for_data(wait_start)
                    if wait_start is None:
                        break
                    continue

                wait_start = None
                chunk_alerts_found, chunk_position = self._process_chunk(chunk)  # Remove start_position argument
                alerts_found = alerts_found or chunk_alerts_found
                buffer_position += chunk_position
                self.last_complete_position = start_position + buffer_position

            if len(self.buffer) > 0 and not alerts_found:
                LOGGER.debug(
                    f"No complete alerts found, reverting to position {self.last_complete_position=}, {len(self.buffer)=}"
                )
                self.fp.seek(self.last_complete_position)
                self.buffer.clear()

        except Exception as e:
            LOGGER.error(f"Error checking file {self.file_path}: {e!s}")

    def log_stats(self) -> tuple[float, float, int, int, int]:
        """Calculate and return statistics for the current interval.
        Resets counters after calculation.

        Returns:
            tuple[float, float, int, int, int]: (alerts per second, error rate percentage,
                                             interval processed alerts, interval errors,
                                             interval replaced alerts)
        """
        current_time = datetime.now()
        time_diff = (current_time - self.last_stats_time).total_seconds()

        if time_diff <= 0:
            return 0.0, 0.0, 0, 0, 0

        alerts_per_second = self.processed_alerts / time_diff
        error_rate = (self.errors / max(self.processed_alerts, 1)) * 100 if self.processed_alerts > 0 else 0.0

        # Store current values for return
        interval_processed = self.processed_alerts
        interval_errors = self.errors
        interval_replaced = self.replaced_alerts

        # Reset counters and update time
        self.last_stats_time = current_time
        self.processed_alerts = 0
        self.errors = 0
        self.replaced_alerts = 0

        return alerts_per_second, error_rate, interval_processed, interval_errors, interval_replaced
