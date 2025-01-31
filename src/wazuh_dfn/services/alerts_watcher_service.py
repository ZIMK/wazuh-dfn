"""Observer service module for monitoring alert files."""

import logging
import threading
import time
from datetime import datetime
from typing import Optional

from wazuh_dfn.services.max_size_queue import MaxSizeQueue

from ..config import WazuhConfig
from ..validators import WazuhConfigValidator
from .file_monitor import FileMonitor

LOGGER = logging.getLogger(__name__)


class AlertsWatcherService:
    """Service for monitoring alert files."""

    def __init__(
        self,
        config: WazuhConfig,
        alert_queue: MaxSizeQueue,
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
        self.file_monitor: Optional[FileMonitor] = None

    def start(self) -> None:
        """Start monitoring alert files."""
        LOGGER.info(f"Starting file monitoring for {self.file_path}")
        try:
            self.file_monitor = FileMonitor(
                file_path=self.file_path,
                alert_queue=self.alert_queue,
                alert_prefix=self.config.json_alert_prefix,
                failed_alerts_path=self.config.failed_alerts_path,
                max_failed_files=self.config.max_failed_files,
                store_failed_alerts=self.config.store_failed_alerts,
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
