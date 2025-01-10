"""Observer service module for monitoring alert files."""

import logging
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Optional

from ..config import WazuhConfig
from ..validators import WazuhConfigValidator
from .file_json_reader import FileJsonReader

LOGGER = logging.getLogger(__name__)


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
        self.latest_queue_put: Optional[datetime] = None
        self.file_monitor: Optional[FileJsonReader] = None

    def start(self) -> None:
        """Start monitoring alert files."""
        LOGGER.info(f"Starting file monitoring for {self.file_path}")

        try:
            self.file_monitor = FileJsonReader(
                file_path=self.file_path,
                alert_queue=self.alert_queue,
                alert_prefix=self.config.json_alert_prefix,
            )

            while not self.shutdown_event.is_set():
                self.file_monitor.check_file()
                # Update latest queue put time from monitor
                self.latest_queue_put = self.file_monitor.latest_queue_put
                time.sleep(self.config.json_alert_file_poll_interval)

        except Exception as e:
            LOGGER.error(f"Error monitoring file: {str(e)}")
        finally:
            if self.file_monitor:
                self.file_monitor.close()
            LOGGER.info("Stopped file monitoring")

    def stop(self) -> None:
        """Stop the monitoring."""
        LOGGER.info("Stopping file monitoring")
