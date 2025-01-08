"""Observer service module for monitoring alert files."""

import logging
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Optional

from ..config import WazuhConfig
from ..validators import WazuhConfigValidator
from .json_reader import JSONReader

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
        self.json_reader: Optional[JSONReader] = None

    def start(self) -> None:
        """Start monitoring alert files."""
        LOGGER.info(f"Starting file monitoring for {self.file_path}")

        try:
            with JSONReader(self.file_path, alert_prefix=self.config.json_alert_prefix, tail=True) as reader:
                self.json_reader = reader
                while not self.shutdown_event.is_set():
                    for alerts in reader:
                        if alerts:
                            for alert in alerts:
                                self.alert_queue.put(alert)
                                self.latest_queue_put = datetime.now()

                        time.sleep(self.config.json_alert_file_poll_interval)
        except Exception as e:
            LOGGER.error(f"Error reading file: {str(e)}")
        finally:
            LOGGER.info("Stopping file monitoring")

    def stop(self) -> None:
        """Stop the monitoring."""
        LOGGER.info("Stopping file monitoring")
