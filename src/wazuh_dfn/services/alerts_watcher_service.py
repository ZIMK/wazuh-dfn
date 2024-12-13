"""Observer service module for monitoring alert files."""

import json
import logging
import os
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Optional, Tuple

from ..config import WazuhConfig
from ..validators import WazuhConfigValidator

LOGGER = logging.getLogger(__name__)

# Maximum line size to read at once (64KB like Wazuh)
MAX_LINE_SIZE = 65536


class FileMonitor:
    """Monitor for a single alert file."""

    def __init__(
        self,
        file_path: str,
        alert_queue: Queue,
        alert_prefix: str,
        alert_suffix: str,
        shutdown_event: threading.Event,
    ) -> None:
        """Initialize FileMonitor.

        Args:
            file_path: Path to file to monitor
            alert_queue: Queue to put alerts into
            alert_prefix: Prefix for alert files
            alert_suffix: Suffix for alert files
            shutdown_event: Event to signal shutdown
        """
        self.file_path = file_path
        self.alert_queue = alert_queue
        self.alert_prefix = alert_prefix
        self.alert_suffix = alert_suffix
        self.shutdown_event = shutdown_event

        self.file_position = 0
        self.current_inode = None
        self.latest_event = ""
        self.latest_queue_put: Optional[datetime] = None
        self._last_event_time = time.time()
        self._consecutive_decode_errors = 0
        self._consecutive_read_errors = 0

        LOGGER.info(f"Initialized FileMonitor for {file_path}")
        self._get_initial_position()

    def _get_initial_position(self) -> None:
        """Set initial file position and inode."""
        try:
            stat = os.stat(self.file_path)
            self.current_inode = stat.st_ino
            with open(self.file_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                self.file_position = f.tell()
        except Exception as e:
            LOGGER.error(f"Error getting initial file position: {str(e)}")
            self.file_position = 0

    def _check_inode(self) -> bool:
        """Check if file inode has changed.

        Returns:
            bool: True if inode changed, False otherwise
        """
        try:
            current_stat = os.stat(self.file_path)
            if current_stat.st_ino != self.current_inode:
                LOGGER.info(f"File {self.file_path} rotated (inode changed)")
                self.current_inode = current_stat.st_ino
                self.file_position = 0
                self.latest_event = ""
                return True
            return False
        except Exception as e:
            LOGGER.error(f"Error checking inode: {str(e)}")
            return False

    def _read_chunk_until_newline(self, file_handle, initial_pos: int) -> Tuple[str, int]:
        """Read chunks until newline is found or max size reached."""
        line = ""
        bytes_read = 0

        while True:
            chunk = file_handle.read(MAX_LINE_SIZE).decode("utf-8")
            if not chunk:
                break

            newline_pos = chunk.find("\n")
            if newline_pos >= 0:
                line += chunk[: newline_pos + 1]
                bytes_read += len(chunk[: newline_pos + 1].encode("utf-8"))
                file_handle.seek(initial_pos + bytes_read)
                break

            line += chunk
            bytes_read += len(chunk.encode("utf-8"))

            if bytes_read > MAX_LINE_SIZE * 2:
                LOGGER.warning(f"Overlong line (>{MAX_LINE_SIZE * 2} bytes) in {self.file_path}")
                break

        return line, bytes_read

    def _read_line(self, file_handle) -> Tuple[str, int]:
        """Read a line from file with position tracking and error recovery."""
        initial_pos = file_handle.tell()
        LOGGER.debug(f"Reading line from position {initial_pos}")

        try:
            chunk = file_handle.read(MAX_LINE_SIZE).decode("utf-8")
            if not chunk:
                LOGGER.debug("No data read from file")
                return "", 0

            newline_pos = chunk.find("\n")
            if newline_pos >= 0:
                line = chunk[: newline_pos + 1]
                bytes_read = len(line.encode("utf-8"))
                file_handle.seek(initial_pos + bytes_read)
                LOGGER.debug(f"Read line: {line!r}, bytes_read: {bytes_read}, new position: {initial_pos + bytes_read}")
                return line, bytes_read

            # No newline found, continue reading
            line = chunk
            bytes_read = len(chunk.encode("utf-8"))
            LOGGER.debug(f"No newline found, continuing to read. Current chunk: {chunk!r}")
            rest_line, rest_bytes = self._read_chunk_until_newline(file_handle, initial_pos + bytes_read)
            return line + rest_line, bytes_read + rest_bytes

        except UnicodeDecodeError:
            LOGGER.debug(f"UnicodeDecodeError at position {initial_pos}, attempting recovery")
            file_handle.seek(initial_pos)
            try:
                chunk = file_handle.read(MAX_LINE_SIZE).decode("utf-8", errors="replace")
                self._consecutive_decode_errors += 1
                bytes_read = len(chunk.encode("utf-8"))
                LOGGER.debug(f"Recovered with replacement: {chunk!r}, bytes_read: {bytes_read}")
                if self._consecutive_decode_errors > 5:
                    LOGGER.warning(
                        f"Failed to decode {self.file_path} with strict UTF-8 for {self._consecutive_decode_errors} consecutive cycles from {initial_pos}"
                    )
                return chunk, bytes_read
            except Exception as e:
                LOGGER.error(f"Error reading with replacement encoding: {str(e)}")
                file_handle.seek(initial_pos)
                return "", 0

        except Exception as e:
            LOGGER.error(f"Error reading from file: {str(e)}")
            file_handle.seek(initial_pos)
            return "", 0

    def _process_line(self, line: str) -> None:
        """Process a single line from the file.

        Args:
            line: Line to process
        """
        cur_line = line.strip()
        if not cur_line:
            LOGGER.debug("Skipping empty line")
            return

        LOGGER.debug(f"Processing line: {cur_line!r}")

        # Handle new event start
        if cur_line.startswith(self.alert_prefix):
            LOGGER.debug("Found new event start")
            if self.latest_event and self.latest_event.count("{") == self.latest_event.count("}"):
                LOGGER.debug("Queueing previous complete event before starting new one")
                self._queue_event()
            self.latest_event = line
            LOGGER.debug(f"Started new event: {self.latest_event!r}")
        # Append to existing event
        elif self.latest_event:
            LOGGER.debug(f"Appending to existing event. Current: {self.latest_event!r}, Adding: {line!r}")
            self.latest_event += line

        # Queue complete events
        if self.latest_event and self.latest_event.count("{") == self.latest_event.count("}"):
            LOGGER.debug("Found complete event, queueing")
            self._queue_event()

    def _queue_event(self) -> None:
        """Queue the current event if valid."""
        if not self.latest_event:
            LOGGER.debug("No event to queue")
            return

        try:
            event = self.latest_event.strip()
            LOGGER.debug(f"Attempting to parse event: {event!r}")
            if event.count("{") == event.count("}"):
                json_data = json.loads(event)
                self.alert_queue.put(json_data)
                self.latest_queue_put = datetime.now()
                LOGGER.debug(f"Successfully queued alert: {json_data}")
            self.latest_event = ""
        except json.JSONDecodeError as e:
            LOGGER.debug(f"Error parsing json alert: {e}")
            LOGGER.debug(f"Raw event content: {self.latest_event!r}")
            self.latest_event = ""

    def check_file(self) -> None:
        """Check file for new content."""
        try:
            if not os.path.exists(self.file_path):
                LOGGER.warning(f"File {self.file_path} no longer exists")
                return

            self._check_inode()

            try:
                with open(self.file_path, "rb") as f:
                    f.seek(self.file_position)

                    while True:
                        line, bytes_read = self._read_line(f)
                        if not line:
                            break

                        self._process_line(line)
                        self.file_position += bytes_read

                    self._last_event_time = time.time()
                    self._consecutive_decode_errors = 0  # Reset on successful read
                    self._consecutive_read_errors = 0

            except Exception as e:
                self._consecutive_read_errors += 1
                if self._consecutive_read_errors > 5:
                    LOGGER.warning(
                        f"Failed to read {self.file_path} for {self._consecutive_read_errors} consecutive cycles: {str(e)}"
                    )
                else:
                    LOGGER.debug(f"Error reading file (attempt {self._consecutive_read_errors}): {str(e)}")
                return

        except Exception as e:
            LOGGER.error(f"Error accessing file {self.file_path}: {str(e)}")


class AlertsWatcherService:
    """Service for monitoring alert files."""

    def __init__(
        self,
        config: WazuhConfig,
        alert_queue: Queue,
        shutdown_event: threading.Event,
    ) -> None:
        """Initialize AlertsWatcherService.

        Args:
            config: Wazuh-specific configuration
            alert_queue: Queue to put alerts into
            shutdown_event: Event to signal shutdown
        """
        WazuhConfigValidator.validate(config)
        self.config = config
        self.alert_queue = alert_queue
        self.shutdown_event = shutdown_event
        self.file_path = config.json_alert_file
        self.monitor: Optional[FileMonitor] = None

    def start(self) -> None:
        """Start monitoring alert files."""
        LOGGER.info(f"Starting file monitoring for {self.file_path}")

        self.monitor = FileMonitor(
            file_path=self.file_path,
            alert_queue=self.alert_queue,
            alert_prefix=self.config.json_alert_prefix,
            alert_suffix=self.config.json_alert_suffix,
            shutdown_event=self.shutdown_event,
        )

        while not self.shutdown_event.is_set():
            if self.monitor:
                self.monitor.check_file()
            time.sleep(self.config.json_alert_file_poll_interval)

        LOGGER.info("Stopping file monitoring")

    def stop(self) -> None:
        """Stop the monitoring."""
        LOGGER.info("Stopping file monitoring")
        self.monitor = None
