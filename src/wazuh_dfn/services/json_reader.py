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
            return self.fp.read()
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
                new_alerts = self.json_queue.add_data(data)
                if new_alerts:
                    alerts.extend(new_alerts)
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
