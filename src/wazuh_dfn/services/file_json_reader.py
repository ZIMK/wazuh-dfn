import json
import logging
import os
import platform
from datetime import datetime
from queue import Queue
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class FileJsonReader:
    """Cross-platform file monitor and JSON parser."""

    def __init__(
        self,
        file_path: str,
        alert_queue: Queue,
        alert_prefix: str = '{"timestamp"',
        tail: bool = False,  # Add tail parameter
    ) -> None:
        self.file_path = file_path
        self.alert_queue = alert_queue
        self.alert_prefix = alert_prefix.encode("utf-8")
        self.tail = tail  # Store tail parameter

        # File handling state
        self.position = 0
        self.current_inode = None
        self.last_size = 0
        self.fp = None
        self.is_windows = platform.system().lower() == "windows"
        self.latest_queue_put: Optional[datetime] = None

        # Buffer state
        self.buffer = bytearray()
        self._brace_count = 0
        self._in_string = False
        self._escape_next = False

        logger.info(f"Initialized FileJsonReader for {file_path} on {platform.system()}")
        self._initialize()

    def _initialize(self) -> None:
        """Initialize file position with platform-specific handling."""
        try:
            if os.path.exists(self.file_path):
                stat = os.stat(self.file_path)
                self.last_size = stat.st_size
                if not self.is_windows:
                    self.current_inode = stat.st_ino
                self._open_file()
        except Exception as e:
            logger.error(f"Error initializing: {str(e)}")
            self.position = 0

    def open(self) -> bool:
        """Open the file and initialize position."""
        return self._open_file()

    def _open_file(self) -> bool:
        """Open file with platform-specific handling."""
        if self.fp:
            try:
                self.fp.close()
            except Exception:
                pass

        try:
            # Use binary mode for consistent newline handling
            self.fp = open(self.file_path, "rb")
            if not self.tail:
                self.fp.seek(0, os.SEEK_END)
            self.position = self.fp.tell()
            return True
        except Exception as e:
            logger.error(f"Error opening file: {str(e)}")
            self.fp = None
            return False

    def _check_rotation(self) -> bool:
        """Check file rotation with platform-specific handling."""
        try:
            if not os.path.exists(self.file_path):
                return False

            current_stat = os.stat(self.file_path)
            current_size = current_stat.st_size

            # Detect rotation
            rotated = False
            if self.is_windows:
                # Windows: Use file size for rotation detection
                if current_size < self.last_size:
                    logger.info(f"File {self.file_path} rotated (size decreased)")
                    rotated = True
            else:
                # Linux: Use inode for rotation detection
                if current_stat.st_ino != self.current_inode:
                    logger.info(f"File {self.file_path} rotated (inode changed)")
                    self.current_inode = current_stat.st_ino
                    rotated = True

            if rotated:
                self.position = 0
                self.buffer.clear()
                self.last_size = current_size
                return True

            self.last_size = current_size
            return False

        except Exception as e:
            logger.error(f"Error checking rotation: {str(e)}")
            return False

    def check_file(self) -> None:
        """Check file for new content with platform-specific handling."""
        try:
            if not os.path.exists(self.file_path):
                logger.warning(f"File {self.file_path} does not exist")
                return

            if self._check_rotation() or not self.fp:
                self._open_file()

            if not self.fp:
                return

            try:
                self.fp.seek(self.position)
                chunk = self.fp.read(8192)  # Read reasonable chunks

                if chunk:
                    self.buffer.extend(chunk)
                    self.position = self.fp.tell()
                    self._process_buffer()

            except Exception as e:
                logger.error(f"Error reading file: {str(e)}")
                self._open_file()  # Try to recover by reopening

        except Exception as e:
            logger.error(f"Error checking file: {str(e)}")

    def _read_and_process(self) -> None:
        """Read and process file data."""
        try:
            self.fp.seek(self.position)
            data = self.fp.read(8192)  # Read in chunks

            if data:
                self.buffer.extend(data)
                self.position = self.fp.tell()
                self._process_buffer()

                # Limit buffer size
                if len(self.buffer) > 1024 * 1024:  # 1MB limit
                    if self._brace_count > 0:
                        self.buffer = self.buffer[-65536:]  # Keep last 64KB
                    else:
                        self.buffer.clear()
                    logger.warning("Buffer too large, truncating")

        except Exception as e:
            logger.error(f"Error reading data: {str(e)}")

    def _clean_utf8(self, data: bytearray) -> bytearray:
        """Clean invalid UTF-8 sequences from data."""
        clean = bytearray()
        i = 0
        while i < len(data):
            # Fast path for ASCII
            if data[i] < 0x80:
                clean.append(data[i])
                i += 1
                continue

            # Handle multi-byte sequences
            length = 0
            byte = data[i]
            if (byte & 0xE0) == 0xC0:  # 2-byte sequence
                length = 2
            elif (byte & 0xF0) == 0xE0:  # 3-byte sequence
                length = 3
            elif (byte & 0xF8) == 0xF0:  # 4-byte sequence
                length = 4

            if length > 0 and i + length <= len(data):
                try:
                    sequence = data[i : i + length].decode("utf-8")
                    clean.extend(sequence.encode("utf-8"))  # Use the validated sequence
                    i += length
                    continue
                except UnicodeDecodeError:
                    pass

            i += 1

        return clean

    def _find_json_boundaries(self) -> List[Dict]:
        """Find and extract complete JSON objects from buffer."""
        alerts = []
        start = 0
        pos = 0

        try:
            text = self.buffer.decode("utf-8")

            while pos < len(text):
                char = text[pos]

                # Handle string processing
                if char == '"' and not self._escape_next:
                    self._in_string = not self._in_string
                elif char == "\\" and not self._escape_next:
                    self._escape_next = True
                    pos += 1
                    continue
                elif self._escape_next:
                    self._escape_next = False
                    pos += 1
                    continue

                if not self._in_string:
                    if char == "{":
                        if self._brace_count == 0:
                            start = pos
                        self._brace_count += 1
                    elif char == "}":
                        self._brace_count -= 1
                        if self._brace_count == 0 and start is not None:
                            try:
                                alert_str = text[start : pos + 1]
                                # Only process if it starts with prefix or continues previous
                                if alert_str.startswith(self.alert_prefix.decode("utf-8")) or start == 0:
                                    alert = json.loads(alert_str)
                                    if isinstance(alert, dict):
                                        alerts.append(alert)
                                        self.latest_queue_put = datetime.now()
                            except json.JSONDecodeError as e:
                                logger.debug(f"Invalid JSON: {str(e)}")

                            # Move buffer forward
                            if pos + 1 < len(text):
                                self.buffer = self.buffer[start + pos + 1 :]
                            else:
                                self.buffer.clear()
                            break

                pos += 1

        except UnicodeDecodeError as e:
            logger.error(f"Unicode decode error: {str(e)}")
            # Remove first byte and try again next time
            if self.buffer:
                self.buffer = self.buffer[1:]

        return alerts

    def _process_buffer(self) -> None:
        """Process buffer to find JSON objects and queue alerts."""
        self.buffer = self._clean_utf8(self.buffer)
        alerts = self._find_json_boundaries()

        # Queue found alerts
        for alert in alerts:
            self.alert_queue.put(alert)

    def close(self) -> None:
        """Clean up resources."""
        if self.fp:
            try:
                self.fp.close()
            except Exception:
                pass
            self.fp = None
        self.buffer.clear()
        self.position = 0
        self._brace_count = 0
        self._in_string = False
        self._escape_next = False
