"""Logging service module for managing logging and statistics."""

import logging
import threading
from queue import Queue

import psutil

from ..config import LogConfig
from ..validators import LogConfigValidator
from .alerts_watcher_service import AlertsWatcherService
from .alerts_worker_service import AlertsWorkerService
from .kafka_service import KafkaService

LOGGER = logging.getLogger(__name__)


class LoggingService:
    """Service for managing logging and statistics.

    This class handles logging configuration and periodic statistics logging.
    It follows the principle of least privilege by only accessing
    the configuration it needs.
    """

    def __init__(
        self,
        config: LogConfig,
        alert_queue: Queue,
        kafka_service: KafkaService,
        alerts_watcher_service: AlertsWatcherService,
        alerts_worker_service: AlertsWorkerService,
        shutdown_event: threading.Event,
    ) -> None:
        """Initialize LoggingService.

        Args:
            config: Logging configuration
            alert_queue: Queue for alerts
            kafka_service: Kafka service instance
            alerts_watcher_service: Observer service instance
            alerts_worker_service: Alerts worker service instance
            shutdown_event: Event to signal shutdown

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        # Validate configuration - will raise ConfigValidationError if invalid
        LogConfigValidator.validate(config)

        self.config = config
        self.alert_queue = alert_queue
        self.kafka_service = kafka_service
        self.alerts_watcher_service = alerts_watcher_service
        self.alerts_worker_service = alerts_worker_service
        self.shutdown_event = shutdown_event
        self.process = psutil.Process()

    def start(self) -> None:
        """Start periodic statistics logging and keep running until shutdown."""
        LOGGER.info("Starting logging service")

        try:
            # Keep running until shutdown
            while not self.shutdown_event.is_set():
                self._log_stats()
                self.shutdown_event.wait(self.config.interval)

            # Cleanup on shutdown
            self.stop()

        except Exception as e:
            LOGGER.error(f"Error in logging service: {e}")
            raise

    def stop(self) -> None:
        """Stop the logging service and cleanup resources."""
        LOGGER.info("Stopping logging service")
        # Log final stats before shutdown
        try:
            self._log_stats()
        except Exception as e:
            LOGGER.error(f"Error logging final stats: {e}")

    def _log_stats(self) -> None:
        """Log various statistics related to the alert processing system.

        This method logs the following details:
        - The number of objects currently in the alert queue.
        - The current memory usage of the process in percentage.
        - The current CPU usage averages (5 and 10 minutes).
        - The current open files of the process.
        - The status of the Kafka producer indicating if it is alive.
        - The number of alerts processed.
        - The latest queue put time from the observer.
        """
        try:
            # Log queue size
            queue_size = self.alert_queue.qsize()
            LOGGER.info(f"Number of objects in alert queue: {queue_size}")

            try:
                # Log memory usage
                memory_percent = self.process.memory_percent()
                LOGGER.info(f"Current memory usage: {memory_percent:.2f}%")
            except psutil.Error as e:
                LOGGER.error(f"Error getting memory usage: {str(e)}")

            # Log CPU usage averages
            try:
                cpu_times = psutil.cpu_percent()
                LOGGER.info(f"CPU usage (avg): {cpu_times:.2f}%")
            except Exception as e:
                LOGGER.debug(f"Error getting memory usage CPU average: {e}")

            try:
                # Log open files
                open_files = self.process.open_files()
                LOGGER.info(f"Current open files: {open_files}")
            except psutil.Error as e:
                LOGGER.error(f"Error getting open files: {str(e)}")

            # Log Kafka producer status
            if self.kafka_service.producer:
                LOGGER.info("Kafka producer is alive")
            else:
                LOGGER.warning("Kafka producer is not initialized")

            # Log alerts worker status
            if self.alerts_worker_service:
                LOGGER.info("Alerts worker service is running")
            else:
                LOGGER.warning("Alerts worker service is not initialized")

            # Log latest queue put time from observer
            if self.alerts_watcher_service:
                latest_queue_put = self.alerts_watcher_service.latest_queue_put
                if latest_queue_put:
                    LOGGER.info(f"Last alert queued at: {latest_queue_put.strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    LOGGER.info("No alerts queued yet")

        except Exception as e:
            LOGGER.error(f"Error collecting monitoring stats: {str(e)}")
