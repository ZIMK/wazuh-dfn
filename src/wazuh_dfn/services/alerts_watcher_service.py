"""Observer service module for monitoring alert files."""

import logging
import threading
import time
from .file_monitor import FileMonitor
from datetime import datetime
from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.services.max_size_queue import MaxSizeQueue

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
            config: WazuhConfig containing file monitoring settings
            alert_queue: Queue for storing parsed alerts
            shutdown_event: Event to signal shutdown
        """
        # Validation is handled by Pydantic automatically
        self.config = config
        self.alert_queue = alert_queue
        self.shutdown_event = shutdown_event
        self.file_path = config.json_alert_file
        self.latest_queue_put: datetime | None = None
        self.file_monitor: FileMonitor | None = None

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
            LOGGER.error(f"Error monitoring file: {e!s}")
        finally:
            if self.file_monitor:
                self.file_monitor.close()
            LOGGER.info("Stopped file monitoring")

    def stop(self) -> None:
        """Stop the monitoring."""
        LOGGER.info("Stopping file monitoring")
