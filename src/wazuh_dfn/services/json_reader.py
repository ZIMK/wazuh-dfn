import json
import logging
import os
import time
from typing import Dict, List

from wazuh_dfn.services.json_queue import JSONQueue

logger = logging.getLogger(__name__)


class JSONReader:
    def __init__(self, file_path: str, alert_prefix: str = "", tail: bool = True, check_interval: float = 1.0):
        """
        Initialize JSON file reader
        Args:
            file_path: Path to the JSON file
            alert_prefix: Expected prefix for JSON objects (e.g., '{"alert":')
            tail: If True, start reading from end of file
        """
        self.file_path = file_path
        self.alert_prefix = alert_prefix
        self.tail = tail
        self.fp = None
        self.f_status = None
        self.json_queue = None
        self.last_check_time = 0
        self.check_interval = check_interval  # seconds

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open_file(self, tail: bool = False) -> bool:
        if self.fp:
            self.fp.close()

        try:
            self.fp = open(self.file_path, "rb")

            if tail and self.fp.seek(0, os.SEEK_END) == -1:
                logger.error(f"Failed to seek in file {self.file_path}")
                self.fp.close()
                self.fp = None
                return False

            self.f_status = os.fstat(self.fp.fileno())

            return True

        except Exception as e:
            logger.error(f"Error opening file {self.file_path}: {str(e)}")
            if self.fp:
                self.fp.close()
                self.fp = None
            return False

    def read_file(self):
        try:
            # Get current position and file size
            current_pos = self.fp.tell()
            self.fp.seek(0, os.SEEK_END)
            file_size = self.fp.tell()
            self.fp.seek(current_pos)

            # Calculate remaining bytes
            remaining = file_size - current_pos
            if remaining > 0:
                data = self.fp.read()
                read_size = len(data) if data else 0
                if read_size < remaining:
                    logger.warning(
                        f"Data loss: Read {read_size} of {remaining} available bytes at position {current_pos}"
                    )
                else:
                    logger.debug(f"Read {read_size} bytes from file at position {current_pos}")
                return data
            return None
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            return None

    def next_alerts(self) -> List[Dict]:
        alerts = []

        try:
            current_time = time.time()
            if current_time - self.last_check_time >= self.check_interval:
                logger.debug(f"Checking for rotation at {current_time}")
                self.last_check_time = current_time
                self.check_rotation()

            data = self.read_file()
            if data:
                bytes_read = len(data)
                logger.debug(f"Processing {bytes_read} bytes of data")
                new_alerts = self.json_queue.add_data(data)
                if new_alerts:
                    total_alert_size = sum(len(json.dumps(alert).encode("utf-8")) for alert in new_alerts)
                    alerts.extend(new_alerts)
                    logger.debug(f"Processed {total_alert_size}/{bytes_read} bytes into {len(new_alerts)} alerts")
                else:
                    logger.warning(f"No alerts found in {bytes_read} bytes of data: {data.decode("utf-8")}")
            elif data is not None:
                logger.warning("Empty data read from file, possible end of file or truncation")

        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")

        return alerts

    def open(self):
        """Open the file for reading"""
        self.json_queue = JSONQueue(self.alert_prefix)
        self.open_file(self.tail)

    def is_active(self) -> bool:
        """Check if the reader is still active"""
        return bool(self.fp)

    def check_rotation(self) -> bool:
        """Check if file has been rotated"""
        try:
            current_stat = os.stat(self.file_path)
            if current_stat.st_ino != self.f_status.st_ino:
                logger.info(f"File rotation detected. Reopening file {self.file_path}")
                return self.open_file(False)
        except Exception as e:
            logger.warning(f"Failed to check file stats: {str(e)}")
        return False

    def close(self):
        """Close the reader"""
        if self.fp:
            self.fp.close()
            self.fp = None
        if self.json_queue:
            self.json_queue.reset()
