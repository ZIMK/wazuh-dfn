import logging
import os
import time
from typing import Dict, Iterator, List

from wazuh_dfn.services.file_queue import FileQueue
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
        self.file_queue = None
        self.json_queue = None
        self.last_check_time = 0
        self.check_interval = check_interval  # seconds

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __iter__(self) -> Iterator[List[Dict]]:
        return self

    def __next__(self) -> List[Dict]:
        """Get all available alerts from the queue up to the current file size"""
        if not self.is_active():
            raise StopIteration
        return self.next_alerts()

    def next_alerts(self) -> List[Dict]:
        alerts = []

        try:
            # Check file rotation periodically
            current_time = time.time()
            if current_time - self.last_check_time >= self.check_interval:
                self.last_check_time = current_time
                self.check_rotation()

            # Read data until we reach the target file size
            while True:
                data = self.file_queue.read(JSONQueue.READ_CHUNK_SIZE)
                if not data:
                    break

                # Process data and collect all alerts
                new_alerts = self.json_queue.add_data(data)
                if new_alerts:
                    alerts.extend(new_alerts)
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")

        return alerts

    def open(self):
        """Open the file for reading"""
        self.file_queue = FileQueue(self.file_path)
        self.json_queue = JSONQueue(self.alert_prefix)
        self.file_queue.open(self.tail)

    def is_active(self) -> bool:
        """Check if the reader is still active"""
        return bool(self.file_queue and self.file_queue.fp)

    def check_rotation(self) -> bool:
        """Check if file has been rotated"""
        try:
            current_stat = os.stat(self.file_path)
            if current_stat.st_ino != self.file_queue.f_status.st_ino:
                logger.info(f"File rotation detected. Reopening file {self.file_path}")
                return self.file_queue.open(False)
        except Exception as e:
            logger.warning(f"Failed to check file stats: {str(e)}")
        return False

    def close(self):
        """Close the reader"""
        if self.file_queue:
            self.file_queue.close()
        if self.json_queue:
            self.json_queue.reset()
