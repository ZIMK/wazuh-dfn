"""Logging service module for managing logging and statistics."""

import asyncio
import logging
from contextlib import suppress
from datetime import datetime

import psutil

from wazuh_dfn.config import LogConfig
from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue

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
        alert_queue: AsyncMaxSizeQueue,
        kafka_service: KafkaService,
        alerts_watcher_service: AlertsWatcherService,
        alerts_worker_service: AlertsWorkerService,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Initialize LoggingService.

        Args:
            config: Logging configuration settings
            alert_queue: Queue for monitoring size metrics
            kafka_service: Kafka service for monitoring performance
            alerts_watcher_service: Service watching alert files
            alerts_worker_service: Service processing alerts
            shutdown_event: Event to signal shutdown
        """
        # Validation is handled by Pydantic automatically
        self.config = config
        self.alert_queue = alert_queue
        self.kafka_service = kafka_service
        self.alerts_watcher_service = alerts_watcher_service
        self.alerts_worker_service = alerts_worker_service
        self.shutdown_event = shutdown_event
        self.process = psutil.Process()

    async def start(self) -> None:
        """Start periodic statistics logging and keep running until shutdown asynchronously.

        Periodically logs system statistics and service information until shutdown
        is signaled. Handles task cancellation and cleanup.
        """
        LOGGER.info("Starting logging service")
        task_name = asyncio.current_task().get_name() if asyncio.current_task() else "LoggingService"
        LOGGER.info(f"Logging service running as task: {task_name}")

        try:
            # Keep running until shutdown
            while not self.shutdown_event.is_set():
                await self._log_stats()
                with suppress(TimeoutError):
                    # Non-blocking wait that can be interrupted
                    await asyncio.wait_for(self.shutdown_event.wait(), timeout=self.config.interval)

            # Cleanup on shutdown
            await self.stop()

        except asyncio.CancelledError:
            LOGGER.info("Logging service task cancelled")
            await self.stop()
        except Exception as e:
            LOGGER.error(f"Error in logging service: {e}")
            raise

    async def stop(self) -> None:
        """Stop the logging service and cleanup resources asynchronously.

        Performs final statistics logging and gracefully shuts down the service.
        Called during service shutdown.
        """
        LOGGER.info("Stopping logging service")
        # Log final stats before shutdown
        try:
            await self._log_stats()
        except Exception as e:
            LOGGER.error(f"Error logging final stats: {e}")

    async def _log_stats(self) -> None:
        """Log various statistics related to the alert processing system asynchronously."""
        try:
            # Log queue size and capacity
            queue_size = self.alert_queue.qsize()
            queue_maxsize = self.alert_queue.maxsize
            fill_percentage = (queue_size / queue_maxsize) * 100 if queue_maxsize > 0 else 0

            # Add warning level based on fill percentage
            if fill_percentage > 90:
                LOGGER.error(f"CRITICAL: Queue is {fill_percentage:.1f}% full ({queue_size}/{queue_maxsize})!")
            elif fill_percentage > 70:
                LOGGER.warning(f"Queue is {fill_percentage:.1f}% full ({queue_size}/{queue_maxsize})!")
            else:
                LOGGER.info(f"Queue is {fill_percentage:.1f}% full ({queue_size}/{queue_maxsize})")

            # Get queue statistics from worker service
            try:
                queue_stats = await self.alerts_worker_service.queue_stats
                if queue_stats:
                    LOGGER.info(
                        f"Queue stats: {queue_stats['total_processed']} total alerts processed, "
                        f"max size reached: {queue_stats['max_queue_size']}, "
                        f"queue full warnings: {queue_stats['queue_full_count']}"
                    )
            except Exception as e:
                LOGGER.error(f"Error getting queue stats: {e}")

            # Log memory usage
            try:
                memory_percent = self.process.memory_percent()
                LOGGER.info(f"Current memory usage: {memory_percent:.2f}%")
            except psutil.Error as e:
                LOGGER.error(f"Error getting memory usage: {e!s}")

            # Log CPU usage averages
            try:
                cpu_times = psutil.cpu_percent()
                LOGGER.info(f"CPU usage (avg): {cpu_times:.2f}%")
            except Exception as e:
                LOGGER.debug(f"Error getting CPU average: {e}")

            # Log open files
            try:
                open_files = self.process.open_files()
                LOGGER.info(f"Current open files: {open_files}")
            except psutil.Error as e:
                LOGGER.error(f"Error getting open files: {e!s}")

            # Log Kafka producer status
            if hasattr(self.kafka_service, "producer") and self.kafka_service.producer:
                LOGGER.info("Kafka producer is alive")
            else:
                LOGGER.warning("Kafka producer is not initialized")

            # Log alerts worker status
            LOGGER.info("Alerts worker service is running")

            # Log FileMonitor statistics if available
            if hasattr(self.alerts_watcher_service, "file_monitor") and self.alerts_watcher_service.file_monitor:
                monitor_stats = await self.alerts_watcher_service.file_monitor.log_stats()
                alerts_per_sec, error_rate, interval_alerts, interval_errors, interval_replaced = monitor_stats

                LOGGER.info(
                    f"FileMonitor (current interval) - "
                    f"Alerts/sec: {alerts_per_sec:.2f}, "
                    f"Error rate: {error_rate:.2f}%, "
                    f"Processed alerts: {interval_alerts}, "
                    f"Replaced alerts: {interval_replaced}, "
                    f"Errors: {interval_errors}"
                )

            # Log the latest queue put time from the watcher service
            if (
                hasattr(self.alerts_watcher_service, "file_monitor")
                and self.alerts_watcher_service.file_monitor
                and self.alerts_watcher_service.file_monitor.latest_queue_put
            ):
                latest_put = self.alerts_watcher_service.file_monitor.latest_queue_put
                time_diff = datetime.now() - latest_put
                LOGGER.info(f"Latest queue put: {latest_put}, {time_diff.total_seconds():.2f} seconds ago")
            else:
                LOGGER.info("No alerts have been queued yet")

            # Log per-worker processing times
            try:
                worker_times = await self.alerts_worker_service.worker_processed_times
                for worker_name, timestamp in worker_times.items():
                    worker_last_processed = datetime.fromtimestamp(timestamp)
                    worker_diff = datetime.now() - worker_last_processed
                    worker_seconds_ago = worker_diff.total_seconds()

                    # Use warning levels for workers that haven't processed alerts recently
                    if worker_seconds_ago > 60:
                        LOGGER.warning(
                            f"Worker {worker_name} last processed: {worker_last_processed}, "
                            f"{worker_seconds_ago:.2f} seconds ago (STALLED)"
                        )
                    else:
                        LOGGER.info(
                            f"Worker {worker_name} last processed: {worker_last_processed}, "
                            f"{worker_seconds_ago:.2f} seconds ago"
                        )
            except Exception as e:
                LOGGER.error(f"Error logging worker times: {e}")

        except Exception as e:
            LOGGER.error(f"Error collecting monitoring stats: {e!s}", exc_info=True)
