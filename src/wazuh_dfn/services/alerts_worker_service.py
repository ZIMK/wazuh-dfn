"""Alerts worker service module for processing alerts from the queue."""

import logging
import threading
import time
from queue import Empty, Queue
from typing import Optional

from ..config import MiscConfig
from ..validators import MiscConfigValidator
from .alerts_service import AlertsService

LOGGER = logging.getLogger(__name__)


class AlertsWorkerService:
    """Service for processing alerts from the queue.

    This class handles the worker pool that processes alerts from the queue.
    It follows the principle of least privilege by only accessing
    the configuration it needs.
    """

    def __init__(
        self,
        config: MiscConfig,
        alert_queue: Queue,
        alerts_service: AlertsService,
        shutdown_event: threading.Event,
    ) -> None:
        """Initialize AlertsWorkerService.

        Args:
            config: Miscellaneous configuration
            alert_queue: Queue to get alerts from
            alerts_service: Service for processing alerts
            shutdown_event: Event to signal shutdown

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        MiscConfigValidator.validate(config)
        self.config = config
        self.alert_queue = alert_queue
        self.alerts_service = alerts_service
        self.shutdown_event = shutdown_event
        self.workers: list[Optional[threading.Thread]] = []
        self._last_processed_time = time.time()

    @property
    def last_processed_time(self) -> float:
        """Get the timestamp of the last processed alert.

        Returns:
            float: Timestamp of last processed alert
        """
        return self._last_processed_time

    def start(self) -> None:
        """Start worker threads for processing alerts."""
        LOGGER.info(f"Starting {self.config.num_workers} alert worker threads")

        try:
            # Create and start worker threads
            for i in range(self.config.num_workers):
                worker = threading.Thread(
                    target=self._process_alerts,
                    name=f"AlertWorker-{i}",
                    daemon=True,
                )
                worker.start()
                self.workers.append(worker)

            # Keep running until shutdown
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(1)

        except Exception as e:
            LOGGER.error(f"Error in alerts worker service: {e}")
            raise

        finally:
            self._shutdown()

    def _process_alerts(self) -> None:
        """Process alerts from the queue."""
        while not self.shutdown_event.is_set():
            try:
                # Get alert with timeout to allow checking shutdown_event
                alert = self.alert_queue.get(timeout=1)
                try:
                    self.alerts_service.process_alert(alert)
                    self._last_processed_time = time.time()
                except Exception as e:
                    LOGGER.error(f"Error processing alert: {e}", exc_info=True)
                finally:
                    self.alert_queue.task_done()
            except Empty:
                continue

    def _shutdown(self) -> None:
        """Shutdown the alerts worker service."""
        LOGGER.info("Shutting down alerts worker service")

        # Wait for remaining items in queue
        if not self.alert_queue.empty():
            LOGGER.info("Waiting for remaining alerts to be processed")
            self.alert_queue.join()

        # Wait for all workers to finish
        for worker in self.workers:
            if worker and worker.is_alive():
                worker.join(timeout=1)

        LOGGER.info("Alerts worker service shutdown complete")
