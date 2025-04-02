import aiofiles
import asyncio
import json
import logging
import secrets
import time
from datetime import datetime
from pathlib import Path
from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue

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
        alert_queue: AsyncMaxSizeQueue,
        alert_prefix: str,
        tail: bool = False,
        failed_alerts_path: str | None = None,
        max_failed_files: int = 100,
        store_failed_alerts: bool = False,
    ) -> None:
        """Initialize FileMonitor.

        Args:
            file_path: Path to the file to monitor
            alert_queue: Queue to store parsed alerts
            alert_prefix: Expected prefix for alert lines
            tail: Whether to tail the file (start at end)
            failed_alerts_path: Path to store alerts that fail processing
            max_failed_files: Maximum number of failed alert files to keep
            store_failed_alerts: Whether to store failed alerts
        """
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

    async def open(self) -> bool:
        """Open the file and initialize position asynchronously.

        Opens the monitored file, sets up the file pointer position, and records
        the initial inode to detect file rotation.

        Returns:
            bool: True if the file was successfully opened, False otherwise
        """
        # Always properly close any existing file handle first
        if self.fp:
            try:
                await self.close()  # Use our enhanced close method
            except Exception as e:
                LOGGER.error(f"Error closing existing file handle: {e!s}")

        try:
            file_path_obj = Path(self.file_path)
            stat = file_path_obj.stat()
            self.current_inode = stat.st_ino

            # Open file asynchronously
            self.fp = await aiofiles.open(self.file_path, mode="rb")

            if not self.tail:
                await self.fp.seek(0, 2)  # SEEK_END
                self.last_complete_position = await self.fp.tell()

            return True
        except Exception as e:
            LOGGER.error(f"Error opening file: {e!s}")
            self.fp = None
            return False

    async def close(self) -> None:
        """Close the file and clear buffer asynchronously.

        Safely closes the file handle if open and clears the internal buffer.
        Logs any errors that occur during closing.
        """
        if self.fp:
            try:
                # First try standard close
                LOGGER.info(f"Closing file {self.file_path}")
                await self.fp.close()
            except Exception as e:
                LOGGER.error(f"Error closing file: {e!s}")

            # Additional Windows-specific cleanup
            if hasattr(self.fp, "_file"):
                try:
                    # Access the underlying file descriptor and close it if possible
                    if hasattr(self.fp._file, "close"):  # type: ignore[]
                        self.fp._file.close()  # type: ignore[]
                except Exception as e:
                    LOGGER.error(f"Error closing underlying file handle: {e!s}")

            # Force cleanup
            import gc

            gc.collect()

            # Reset to prevent further usage of closed handle
            self.fp = None

        # Always clear buffer
        self.buffer = bytearray()

    async def _check_inode(self) -> bool:
        """Check if the file's inode has changed (indicating rotation) asynchronously.

        Detects file rotation by comparing current inode with the stored inode.

        Returns:
            bool: True if rotation was detected, False otherwise
        """
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
        """Find the next line ending position after start_pos.

        Searches for various line ending formats (CR, LF, CRLF) in the buffer.

        Args:
            start_pos: Starting position in the buffer to search from

        Returns:
            int: Position after the line ending, or -1 if no ending found
        """
        pos = start_pos
        while pos < len(self.buffer):
            if self.buffer[pos : pos + 2] == b"\r\n":
                return pos + 2
            if self.buffer[pos : pos + 1] in [b"\n", b"\r"]:
                return pos + 1
            pos += 1
        return -1

    def _extract_alert(self) -> bytes | None:
        """Extract a complete alert from the buffer if available.

        Searches the buffer for a complete alert starting with the configured prefix
        and ending with the alert suffix. Handles buffer cleanup and overflow conditions.

        Returns:
            bytes | None: The extracted alert as bytes if found, None otherwise
        """
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

    async def _save_failed_alert(self, alert_bytes: bytes, alert_str: str | None = None) -> None:
        """Save failed alert to file asynchronously.

        Stores alerts that failed processing in a dedicated directory for later analysis.
        Can also save a version with character replacement for comparison.

        Args:
            alert_bytes: The raw bytes of the failed alert
            alert_str: Optional string version with replaced characters
        """
        if not self.store_failed_alerts or not self.failed_alerts_path:
            return

        try:
            await self._cleanup_failed_alerts()
            # Add random component to timestamp to ensure uniqueness
            random_suffix = str(secrets.randbelow(999999) + 100000)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            failed_path = Path(self.failed_alerts_path)
            failed_file = failed_path / f"{timestamp}_{random_suffix}_failed_alert.json"

            async with aiofiles.open(failed_file, "wb") as f:
                await f.write(alert_bytes)

            if alert_str:
                replaced_file = failed_path / f"{timestamp}_{random_suffix}_replaced_alert.json"
                async with aiofiles.open(replaced_file, "wb") as f:
                    await f.write(alert_str.encode("utf-8"))
                LOGGER.info(f"Saved failed alert and replaced version to {failed_file} and {replaced_file}")
            else:
                LOGGER.info(f"Saved failed alert to {failed_file}")
        except Exception as save_error:
            LOGGER.error(f"Error saving failed alert: {save_error!s}")

    async def _process_alert_with_replace(self, alert_bytes: bytes) -> bool:
        """Try processing alert with character replacement asynchronously.

        Attempts to decode and parse an alert after replacing invalid UTF-8 sequences.
        Used as a fallback when strict decoding fails.

        Args:
            alert_bytes: The raw bytes of the alert to process

        Returns:
            bool: True if processing succeeded with replacement, False otherwise
        """
        try:
            alert_str = alert_bytes.decode("utf-8", errors="replace").rstrip()
            alert_data = json.loads(alert_str)
            await self.alert_queue.put(alert_data)
            self.latest_queue_put = datetime.now()
            self.processed_alerts += 1
            self.replaced_alerts += 1  # Increment replaced alerts counter
            LOGGER.warning("Alert processed with character replacement")
            await self._save_failed_alert(alert_bytes, alert_str)
            return True
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False

    async def _queue_alert(self, alert_bytes: bytes) -> None:
        """Process and queue an alert asynchronously.

        Attempts to decode and parse alert bytes, first with strict UTF-8 decoding,
        then falling back to character replacement if needed. Successfully parsed
        alerts are added to the processing queue.

        Args:
            alert_bytes: The raw bytes of the alert to process
        """
        try:
            # First try strict decoding
            alert_str = alert_bytes.decode("utf-8", errors="strict").rstrip()
            alert_data = json.loads(alert_str)
            await self.alert_queue.put(alert_data)
            self.latest_queue_put = datetime.now()
            self.processed_alerts += 1
            LOGGER.debug("Queued alert successfully")
            return
        except UnicodeDecodeError:
            # Try with replace if strict decode fails
            if await self._process_alert_with_replace(alert_bytes):
                return
        except json.JSONDecodeError:
            pass  # Fall through to error handling

        # Handle all failures
        self.errors += 1
        LOGGER.error(f"Error processing alert, raw content: {alert_bytes.hex()}")
        await self._save_failed_alert(alert_bytes)

    async def _cleanup_failed_alerts(self) -> None:
        """Remove oldest failed alert files if exceeding max_failed_files asynchronously.

        Manages the stored failed alerts directory by removing older files
        when the maximum number of files is exceeded.
        """
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

    async def _process_buffer(self) -> None:
        """Process buffer content to find and queue complete alerts asynchronously.

        Repeatedly extracts and processes alerts from the buffer until no more
        complete alerts can be found.
        """
        while alert_bytes := self._extract_alert():
            await self._queue_alert(alert_bytes)

    async def _wait_for_data(self, wait_start: float | None) -> float | None:
        """Wait for more data if buffer contains incomplete alert asynchronously.

        Implements a timed waiting mechanism for incomplete alerts in the buffer.

        Args:
            wait_start: Optional timestamp when waiting started

        Returns:
            float | None: Updated wait timestamp or None if wait completed/not needed
        """
        if len(self.buffer) > 0:
            if wait_start is None:
                return time.time()
            elif time.time() - wait_start > MAX_WAIT_TIME:  # Use module-level constant
                LOGGER.debug("Max wait time reached, will process buffer in next round")
                return None
            await asyncio.sleep(0.1)
            return wait_start
        return None

    async def _handle_file_status(self) -> bool:
        """Check file existence and handle rotation asynchronously.

        Verifies that the monitored file exists and checks for file rotation.
        Reopens the file if needed.

        Returns:
            bool: True if the file is available and ready, False otherwise
        """
        if not self.fp and not await self.open():
            return False

        file_path_obj = Path(self.file_path)
        if not file_path_obj.exists():
            LOGGER.warning(f"File {self.file_path} no longer exists")
            # Make sure file handle is closed if file doesn't exist
            await self.close()
            return False

        if await self._check_inode():
            LOGGER.info("File rotation detected, clearing buffer")
            # Explicitly close before reopening to prevent handle leaks on Windows
            await self.close()
            self.buffer.clear()
            return await self.open()

        return True

    async def _process_chunk(self, chunk: bytes) -> tuple[bool, int]:
        """Process a chunk of data from the file asynchronously.

        Adds the chunk to the buffer and attempts to extract and process alerts from it.

        Args:
            chunk: Raw bytes read from the file

        Returns:
            tuple[bool, int]: Tuple containing (alerts_found, buffer_position)
        """
        if not chunk:
            return False, 0

        LOGGER.debug(f"{len(chunk)=} bytes at position {await self.fp.tell()}")
        self.buffer.extend(chunk)

        buffer_position = 0
        alerts_found = False

        while True:
            buffer_size_before = len(self.buffer)
            alert_bytes = self._extract_alert()
            if not alert_bytes:
                break

            try:
                await self._queue_alert(alert_bytes)
                alerts_found = True
                buffer_position += buffer_size_before - len(self.buffer)
            except Exception as e:
                LOGGER.error(f"Error processing alert: {e!s}, alert size: {len(alert_bytes)}")
                if len(alert_bytes) > 0:
                    LOGGER.debug(f"First 100 bytes of failed alert: {alert_bytes[:100].hex()}")
                raise

        return alerts_found, buffer_position

    async def check_file(self) -> None:
        """Check file for new alerts asynchronously.

        Main monitoring method that reads new data from the file, processes it into alerts,
        and handles file rotations. Manages internal buffer state and alert extraction.

        This method performs several key operations:
        - Verifies file existence and handles file rotation detection
        - Reads data in chunks from the monitored file
        - Processes chunks to extract complete alerts
        - Handles incomplete alerts at buffer boundaries
        - Updates file position tracking for reliable processing
        """
        try:
            LOGGER.debug(f"{len(self.buffer)=}, checking file")

            if not await self._handle_file_status():
                return

            start_position = await self.fp.tell()
            alerts_found = False
            wait_start = None
            buffer_position = 0

            while True:
                chunk = await self.fp.read(CHUNK_SIZE)
                if not chunk:
                    wait_start = await self._wait_for_data(wait_start)
                    if wait_start is None:
                        break
                    continue

                wait_start = None
                chunk_alerts_found, chunk_position = await self._process_chunk(chunk)
                alerts_found = alerts_found or chunk_alerts_found
                buffer_position += chunk_position
                self.last_complete_position = start_position + buffer_position

            if len(self.buffer) > 0 and not alerts_found:
                LOGGER.debug(
                    f"No complete alerts found, reverting to position {self.last_complete_position=},"
                    f" {len(self.buffer)=}"
                )
                await self.fp.seek(self.last_complete_position)
                self.buffer.clear()

        except Exception as e:
            LOGGER.error(f"Error checking file {self.file_path}: {e!s}")

    async def log_stats(self) -> tuple[float, float, int, int, int]:
        """Calculate and return statistics for the current monitoring interval asynchronously.

        Computes performance metrics for alert processing including alerts per second,
        error rates, and alert counts. Resets counters after calculation for the next interval.

        Returns:
            tuple: (alerts_per_second, error_rate, total_alerts, error_count, replaced_count)
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
