"""Alerts worker service module for processing alerts from the queue."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import tempfile
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wazuh_dfn.config import MiscConfig
from wazuh_dfn.health.builders import WorkerLastProcessedBuilder, WorkerPerformanceBuilder
from wazuh_dfn.max_size_queue import AsyncMaxSizeQueue

if TYPE_CHECKING:
    from wazuh_dfn.health.event_service import HealthEventService
    from wazuh_dfn.health.models import QueueStatsData, WorkerLastProcessedData, WorkerPerformanceData

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
        alert_queue: AsyncMaxSizeQueue,
        alerts_service: AlertsService,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Initialize AlertsWorkerService.

        Args:
            config: Miscellaneous configuration settings
            alert_queue: Queue of alerts to process
            alerts_service: Service for alert processing
            shutdown_event: Event to signal shutdown
        """
        # Validation is handled by Pydantic automatically
        self.config = config
        self.alert_queue = alert_queue
        self.alerts_service = alerts_service
        self.shutdown_event = shutdown_event
        self.worker_tasks = []
        self._worker_processed_times = {}
        self._times_lock = asyncio.Lock()

        # Add counters for monitoring queue health - ensure timestamp is stored as int
        self._queue_stats = {
            "total_processed": 0,
            "last_queue_size": 0,
            "max_queue_size": 0,
            "config_max_queue_size": alert_queue.maxsize,
            "queue_full_count": 0,
            "last_queue_check": int(datetime.now().timestamp()),  # Convert to int
        }
        self._stats_lock = asyncio.Lock()

        # Track if we're in high throughput mode
        self._high_throughput_mode = False

        # Start queue monitoring task
        self._monitor_task = None

        # Reference to the logging service (will be set later)
        self._logging_service = None
        self._health_event_service: HealthEventService | None = None

    def set_logging_service(self, logging_service) -> None:
        """Set the logging service reference for performance logging.

        Args:
            logging_service: The logging service instance
        """
        self._logging_service = logging_service

    def set_health_event_service(self, health_event_service: HealthEventService) -> None:
        """Set the health event service for direct event pushing.

        Args:
            health_event_service: The health event service instance
        """
        self._health_event_service = health_event_service

    def get_health_status(self) -> bool:
        """Check if the service is healthy and operational.

        Returns:
            bool: True if service is healthy, False otherwise
        """
        return not self.shutdown_event.is_set()

    def get_worker_performance(self) -> WorkerPerformanceData:
        """Get current worker performance metrics.

        Returns:
            WorkerPerformanceData: Worker performance data
        """
        # Return basic performance data
        return {
            "alerts_processed": self._queue_stats.get("total_processed", 0),
            "rate": 0.0,
            "avg_processing": 0.0,
            "recent_avg": 0.0,
            "min_time": 0.0,
            "max_time": 0.0,
            "slow_alerts": 0,
            "extremely_slow_alerts": 0,
            "last_processing_time": 0.0,
            "last_alert_id": "",
            "timestamp": time.time(),
            "worker_count": self.config.num_workers,  # Add actual worker count
            "active_worker_count": len([task for task in self.worker_tasks if not task.done()]),  # Active workers
        }

    def get_worker_name(self) -> str:
        """Get the worker identifier.

        Returns:
            str: Unique worker name/ID
        """
        return "alerts_worker"

    def get_queue_stats(self) -> QueueStatsData:
        """Get current queue statistics.

        Returns:
            QueueStatsData: Queue statistics data
        """
        return {
            "total_processed": self._queue_stats.get("total_processed", 0),
            "max_queue_size": self._queue_stats.get("max_queue_size", 0),
            "config_max_queue_size": self._queue_stats.get("config_max_queue_size", 0),
            "queue_full_count": self._queue_stats.get("queue_full_count", 0),
            "last_queue_size": self.alert_queue.qsize(),
        }

    def get_queue_name(self) -> str:
        """Get the queue identifier.

        Returns:
            str: Queue name/identifier
        """
        return "alert_queue"

    def is_queue_healthy(self) -> bool:
        """Check if queue is operating within normal parameters.

        Returns:
            bool: True if queue is healthy, False if at risk
        """
        # Consider queue healthy if not full and service is running
        return not self.alert_queue.full() and self.get_health_status()

    def get_service_metrics(self) -> dict[str, Any]:
        """Get comprehensive service metrics.

        Returns:
            dict[str, Any]: Service metrics data
        """
        return {
            "health_status": self.get_health_status(),
            "worker_performance": self.get_worker_performance(),
            "queue_stats": self.get_queue_stats(),
            "is_processing": self.is_processing(),
        }

    def is_processing(self) -> bool:
        """Check if service is currently processing alerts.

        Returns:
            bool: True if actively processing
        """
        return self.get_health_status() and not self.alert_queue.empty()

    def get_last_error(self) -> str | None:
        """Get the last error message if any.

        Returns:
            str | None: Last error message or None
        """
        # Would need to implement error tracking
        return None

    @property
    async def worker_processed_times(self) -> dict[str, float]:
        """Get the timestamp of the last processed alert for each worker.

        Returns:
            dict[str, float]: Dictionary of worker names to timestamps
        """
        async with self._times_lock:
            # Return a copy to prevent external modification
            return self._worker_processed_times.copy()

    @property
    async def queue_stats(self) -> dict:
        """Get current queue statistics.

        Returns:
            dict: Current queue statistics
        """
        async with self._stats_lock:
            # Return a copy to prevent external modification
            return self._queue_stats.copy()

    async def start(self) -> None:
        """Start worker tasks for processing alerts asynchronously.

        Creates and manages a pool of worker tasks according to the configuration.
        Each worker processes alerts from the queue until shutdown is signaled.
        """
        LOGGER.info(f"Starting {self.config.num_workers} alert worker tasks")
        task_name = asyncio.current_task().get_name() if asyncio.current_task() else "AlertsWorkerService"
        LOGGER.info(f"Alerts worker service running as task: {task_name}")

        try:
            # Start queue monitoring task first
            self._monitor_task = asyncio.create_task(self._monitor_queue(), name="QueueMonitor")

            # Create and start worker tasks using task groups
            async with asyncio.TaskGroup() as tg:
                for i in range(self.config.num_workers):
                    worker_task = tg.create_task(self._process_alerts(), name=f"AlertWorker-{i}")
                    self.worker_tasks.append(worker_task)

                # Keep running until shutdown
                await self.shutdown_event.wait()

        except asyncio.CancelledError:
            LOGGER.info("Alert worker tasks cancelled")
        except Exception as e:
            LOGGER.error(f"Error in alerts worker service: {e}")
            raise
        finally:
            await self._shutdown()

    async def _monitor_queue(self) -> None:
        """Monitor queue health and adjust worker behavior accordingly."""
        LOGGER.info("Starting queue monitor task")

        while not self.shutdown_event.is_set():
            try:
                # Check queue size every 2 seconds
                await asyncio.sleep(2)

                current_size = self.alert_queue.qsize()
                max_size = self.alert_queue.maxsize
                fill_percentage = (current_size / max_size) * 100 if max_size > 0 else 0

                async with self._stats_lock:
                    self._queue_stats["last_queue_size"] = current_size
                    self._queue_stats["max_queue_size"] = max(self._queue_stats["max_queue_size"], current_size)

                    # Check if queue is at risk of overflowing (>80% full)
                    if fill_percentage > 80:
                        self._queue_stats["queue_full_count"] += 1

                        # Enable high-throughput mode if not already enabled
                        if not self._high_throughput_mode:
                            self._high_throughput_mode = True
                            LOGGER.warning(
                                f"Queue at {fill_percentage:.1f}%% capacity ({current_size}/{max_size}). "
                                f"Enabling high-throughput mode."
                            )
                    elif fill_percentage < 50 and self._high_throughput_mode:
                        # Disable high throughput mode when queue is less full
                        self._high_throughput_mode = False
                        LOGGER.info(f"Queue at {fill_percentage:.1f}%% capacity. Disabling high-throughput mode.")

                # Log warnings at different thresholds
                if fill_percentage > 90:
                    LOGGER.error(
                        f"CRITICAL: Queue nearly full: {fill_percentage:.1f}% ({current_size}/{max_size}). "
                        f"Events may be discarded!"
                    )
                elif fill_percentage > 80:
                    LOGGER.warning(
                        f"Queue filling up: {fill_percentage:.1f}% ({current_size}/{max_size}). "
                        f"Processing may fall behind."
                    )

            except asyncio.CancelledError:
                LOGGER.info("Queue monitor task cancelled")
                break
            except Exception as e:
                LOGGER.error(f"Error in queue monitor: {e}", exc_info=True)

    async def _process_alerts(self) -> None:  # noqa: PLR0912 NOSONAR
        """Process alerts from the queue asynchronously."""
        worker_name = asyncio.current_task().get_name() if asyncio.current_task() else "AlertWorker"
        LOGGER.info(f"Started alert processing worker: {worker_name}")

        # Initialize this worker's timestamp
        now = datetime.now().timestamp()
        async with self._times_lock:
            self._worker_processed_times[worker_name] = now

        # Track worker performance metrics
        alerts_processed = 0
        start_time = datetime.now()
        last_metrics_dump = start_time
        consecutive_empty = 0
        total_processing_time = 0

        # Initialize variables that might be referenced before assignment
        last_processing_time = 0
        last_alert_id = "none"

        # Add detailed timing metrics
        timing_stats = {
            "processing_times": [],  # Store recent processing times
            "slow_alerts": 0,  # Count of alerts taking > 2 seconds
            "extremely_slow_alerts": 0,  # Count of alerts taking > 5 seconds
            "max_time": 0,  # Maximum processing time
            "min_time": float("inf"),  # Minimum processing time
        }

        # Batch size for high-throughput mode
        batch_size = 5

        while not self.shutdown_event.is_set():
            try:
                # In high-throughput mode, try to process multiple alerts in a batch when queue is filling up
                is_high_throughput = self._high_throughput_mode

                if is_high_throughput:
                    # Process multiple alerts in a batch
                    new_alerts_processed, new_total_time, timing_results = await self._process_alert_batch(
                        worker_name, batch_size, alerts_processed, total_processing_time
                    )

                    # Update counters
                    alerts_processed = new_alerts_processed
                    total_processing_time = new_total_time

                    # Update timing stats
                    if timing_results:
                        for t in timing_results:
                            self._update_timing_stats(timing_stats, t)
                else:
                    # Process single alerts normally with detailed timing
                    timeout = 0.05 if consecutive_empty > 5 else 0.2

                    try:
                        # Get an alert from the queue
                        alert = await asyncio.wait_for(self.alert_queue.get(), timeout=timeout)
                        LOGGER.debug(f"Worker {worker_name} got alert {alert}")

                        consecutive_empty = 0  # Reset empty counter

                        # CRITICAL: Detailed timing breakdown for processing
                        try:
                            # Record overall processing time
                            process_start = datetime.now()

                            # Track internal timing of the process_alert method
                            alert_id = alert.get("id", "unknown")
                            LOGGER.debug(f"Worker {worker_name} starting to process alert {alert_id}")

                            # Process with timeouts to catch hangs
                            try:
                                # Use a timeout to prevent extremely long-running processes
                                # Default to 30 seconds max processing time per alert
                                await asyncio.wait_for(self.alerts_service.process_alert(alert), timeout=30.0)
                            except TimeoutError:
                                LOGGER.error(
                                    f"CRITICAL: Processing of alert {alert_id} timed out after 30 seconds! "
                                    f"This indicates a severe performance issue."
                                )
                                # Continue processing other alerts

                            process_end = datetime.now()
                            processing_time = (process_end - process_start).total_seconds()

                            # Update the last processed time for monitoring
                            now = datetime.now().timestamp()
                            async with self._times_lock:
                                self._worker_processed_times[worker_name] = now

                            # Update performance tracking
                            alerts_processed += 1
                            total_processing_time += processing_time

                            # Store the processing time and alert ID for metrics
                            last_processing_time = processing_time
                            last_alert_id = alert_id

                            # Update timing stats
                            self._update_timing_stats(timing_stats, processing_time)

                            # Update global stats
                            async with self._stats_lock:
                                self._queue_stats["total_processed"] += 1

                            # Log based on processing time thresholds
                            if processing_time > 10.0:
                                LOGGER.error(
                                    f"CRITICAL: Worker {worker_name} extremely slow alert processing: "
                                    f"{processing_time:.2f}s for alert {alert_id}. "
                                    f"This indicates a severe performance issue!"
                                )
                                # Dump slow alert for analysis
                                debug_path = await self._dump_alert(alert)
                                if debug_path:
                                    LOGGER.info(f"Dumped extremely slow alert to {debug_path}")
                            elif processing_time > 5.0:
                                LOGGER.warning(
                                    f"Worker {worker_name} very slow alert processing: {processing_time:.2f}s "
                                    f"for alert {alert_id}"
                                )
                            elif processing_time > 1.0:
                                LOGGER.warning(
                                    f"Worker {worker_name} slow alert processing: {processing_time:.2f}s "
                                    f"for alert {alert_id}"
                                )
                            else:
                                LOGGER.debug(
                                    f"Worker {worker_name} processed alert {alert_id} in {processing_time:.2f}s"
                                )

                        except Exception as e:
                            alert_id = alert.get("id", "unknown")
                            LOGGER.error(f"Error processing alert {alert_id}: {e}", exc_info=True)
                            debug_path = await self._dump_alert(alert)
                            if debug_path:
                                LOGGER.info(f"Dumped failed alert to {debug_path}")
                        finally:
                            # Mark the task as done
                            self.alert_queue.task_done()

                    except TimeoutError:
                        consecutive_empty += 1
                        # Very short sleep when queue is empty
                        if consecutive_empty > 10:
                            await asyncio.sleep(0.001)
                        continue

                # Log detailed performance metrics more frequently when things are slow
                now_time = datetime.now()
                log_interval = 15 if timing_stats["extremely_slow_alerts"] > 0 else 30

                if (now_time - last_metrics_dump).total_seconds() > log_interval:
                    elapsed = (now_time - start_time).total_seconds()
                    rate = alerts_processed / elapsed if elapsed > 0 else 0
                    avg_processing = total_processing_time / alerts_processed if alerts_processed > 0 else 0

                    # Calculate recent average from last 10 alerts or fewer
                    recent_times = timing_stats["processing_times"][-10:]
                    recent_avg = sum(recent_times) / len(recent_times) if recent_times else 0

                    # Send performance data to health event service (preferred) or logging service (fallback)
                    if self._health_event_service:
                        performance_data: WorkerPerformanceData = (
                            WorkerPerformanceBuilder.create()
                            .with_timestamp(now_time.timestamp())
                            .with_alerts_processed(alerts_processed)
                            .with_rate(rate)
                            .with_processing_times(
                                avg_processing, recent_avg, timing_stats["min_time"], timing_stats["max_time"]
                            )
                            .with_slow_alerts(timing_stats["slow_alerts"], timing_stats["extremely_slow_alerts"])
                            .with_last_alert(last_processing_time, last_alert_id)
                            .with_worker_counts(worker_count=1, active_worker_count=1)
                            .build()
                        )
                        await self._health_event_service.emit_worker_performance(worker_name, performance_data)
                    elif self._logging_service:
                        performance_data_dict = (
                            WorkerPerformanceBuilder.create()
                            .with_timestamp(now_time.timestamp())
                            .with_alerts_processed(alerts_processed)
                            .with_rate(rate)
                            .with_processing_times(
                                avg_processing, recent_avg, timing_stats["min_time"], timing_stats["max_time"]
                            )
                            .with_slow_alerts(timing_stats["slow_alerts"], timing_stats["extremely_slow_alerts"])
                            .with_last_alert(last_processing_time, last_alert_id)
                            .with_worker_counts(worker_count=1, active_worker_count=1)
                            .build()
                        )
                        await self._logging_service.record_worker_performance(worker_name, performance_data_dict)
                    else:
                        # Fallback if neither service is set
                        LOGGER.info(
                            f"Worker {worker_name} performance: {alerts_processed} alerts processed, "
                            f"rate: {rate:.2f} alerts/sec, avg processing: {avg_processing*1000:.2f}ms"
                        )

                    last_metrics_dump = now_time

            except asyncio.CancelledError:
                LOGGER.info(f"Worker {worker_name} task cancelled")
                break

            except Exception as e:
                LOGGER.error(f"Error in worker {worker_name}: {e}", exc_info=True)
                # Short wait on errors
                await asyncio.sleep(0.001)

        # Log final stats
        if alerts_processed > 0:
            elapsed = (datetime.now() - start_time).total_seconds()
            rate = alerts_processed / elapsed if elapsed > 0 else 0
            avg_processing = total_processing_time / alerts_processed
            LOGGER.info(
                f"Worker {worker_name} final stats: {alerts_processed} alerts processed, "
                f"rate: {rate:.2f} alerts/sec, avg processing: {avg_processing*1000:.2f}ms"
            )

        LOGGER.info(f"Stopping worker {worker_name}")

    def _update_timing_stats(self, stats: dict, processing_time: float) -> None:
        """Update timing statistics with a new processing time."""
        # Keep last 100 processing times for analysis
        stats["processing_times"].append(float(processing_time))  # Ensure it's explicitly a float
        if len(stats["processing_times"]) > 100:
            stats["processing_times"].pop(0)

        # Update min/max times - ensure they're always stored as floats
        stats["max_time"] = float(max(stats["max_time"], processing_time))
        stats["min_time"] = float(min(stats["min_time"], processing_time))

        # Count slow alerts
        if processing_time > 5.0:
            stats["extremely_slow_alerts"] += 1
        elif processing_time > 2.0:
            stats["slow_alerts"] += 1

    async def _process_alert_batch(
        self, worker_name: str, batch_size: int, alerts_processed: int, total_processing_time: float
    ) -> tuple[int, float, list[float]]:
        """Process multiple alerts in a batch when queue is filling up.

        Returns:
            tuple: (alerts_processed, total_processing_time, processing_times)
        """
        batch = []
        timing_results = []
        _last_alert_id = "batch-none"  # Initialize with default value

        # Try to get up to batch_size alerts without blocking
        for _ in range(batch_size):
            try:
                if not self.alert_queue.empty():
                    alert = self.alert_queue.get_nowait()
                    batch.append(alert)
            except asyncio.QueueEmpty:
                break

        if not batch:
            # No alerts to process, return unchanged values
            await asyncio.sleep(0.001)  # Brief pause to prevent CPU spinning
            return alerts_processed, total_processing_time, timing_results

        # Process the batch
        try:
            batch_start_time = datetime.now()

            # Process each alert in sequence with detailed timing
            for alert in batch:
                try:
                    alert_id = alert.get("id", "unknown")
                    _last_alert_id = alert_id  # Keep track of the last processed alert ID
                    LOGGER.debug(f"Worker {worker_name} processing batch alert {alert_id}")

                    process_start = datetime.now()
                    try:
                        # Use timeout to prevent hanging
                        await asyncio.wait_for(self.alerts_service.process_alert(alert), timeout=30.0)
                    except TimeoutError:
                        LOGGER.error(f"CRITICAL: Processing of batch alert {alert_id} timed out after 30 seconds!")

                    process_end = datetime.now()
                    processing_time = (process_end - process_start).total_seconds()

                    # Update last processed information for metrics
                    if self._health_event_service:
                        # Store the last alert processing info
                        last_processing_info: WorkerLastProcessedData = (
                            WorkerLastProcessedBuilder.create()
                            .with_processing_time(processing_time)
                            .with_alert_id(alert_id)
                            .build()
                        )
                        await self._health_event_service.emit_worker_last_processed(worker_name, last_processing_info)
                    elif self._logging_service:
                        # Store the last alert processing info
                        last_processing_info = (
                            WorkerLastProcessedBuilder.create()
                            .with_processing_time(processing_time)
                            .with_alert_id(alert_id)
                            .build()
                        )
                        await self._logging_service.update_worker_last_processed(worker_name, last_processing_info)

                    # Track times
                    total_processing_time += processing_time
                    timing_results.append(processing_time)
                    alerts_processed += 1

                    # Log slow processing
                    if processing_time > 5.0:
                        LOGGER.warning(
                            f"Worker {worker_name} very slow batch alert processing: {processing_time:.2f}s "
                            f"for alert {alert_id}"
                        )

                    # Update global stats
                    async with self._stats_lock:
                        self._queue_stats["total_processed"] += 1

                except Exception as e:
                    alert_id = alert.get("id", "unknown")
                    LOGGER.error(f"Error processing batch alert {alert_id}: {e}", exc_info=True)
                finally:
                    # Mark as done regardless of success or failure
                    self.alert_queue.task_done()

            # Update the last processed time once for the batch
            now = datetime.now().timestamp()
            async with self._times_lock:
                self._worker_processed_times[worker_name] = now

            # Log batch performance
            batch_time = (datetime.now() - batch_start_time).total_seconds()
            LOGGER.info(
                f"Worker {worker_name} processed batch of {len(batch)} alerts in {batch_time:.3f}s "
                f"({batch_time/len(batch):.3f}s per alert)"
            )

        except Exception as e:
            LOGGER.error(f"Error processing alert batch: {e}", exc_info=True)

        return alerts_processed, total_processing_time, timing_results

    async def _dump_alert(self, alert: dict[str, Any]) -> str | None:
        """Dump alert to file for debugging asynchronously.

        Creates a temporary file containing the JSON representation of the
        alert that failed processing, for later analysis.

        Args:
            alert: The alert data to dump
        Returns:
            str | None: Path to the dump file or None if failed
        """
        try:
            alert_id = alert.get("id", "unknown")
            random_suffix = str(secrets.randbelow(999999) + 100000)
            alert_suffix = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random_suffix}"
            # Create a temp file with pathlib
            temp_path = Path(tempfile.gettempdir()) / f"dfn-alert-{alert_id}_{alert_suffix}.json"
            # Use async file operations
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._write_file(temp_path, json.dumps(alert, indent=2)))
            return str(temp_path)

        except Exception as e:
            LOGGER.error(f"Error writing alert to tmp file: {e!s}")
            return None

    async def _write_file(self, path: Path, content: str) -> None:
        """Write content to file asynchronously.

        Uses asyncio's run_in_executor to perform file I/O operations
        without blocking the event loop.

        Args:
            path: The path to write to
            content: The content to write
        """
        # Use a thread for file I/O since aiofiles might not be available in all environments
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, path.write_text, content)

    async def _shutdown(self) -> None:
        """Shutdown the alerts worker service asynchronously.

        Ensures graceful shutdown by:
        1. Waiting for remaining items in the queue to be processed
        2. Cancelling and awaiting all worker tasks

        This method is called during service shutdown to ensure clean termination.
        """
        LOGGER.info("Shutting down alerts worker service")
        # Cancel the queue monitor first
        if self._monitor_task and not self._monitor_task.done():
            LOGGER.info("Cancelling queue monitor task")
            self._monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._monitor_task

        # Wait for all workers to finish
        for worker_task in self.worker_tasks:
            LOGGER.info(f"Waiting for worker task {worker_task.get_name()} to finish. done: {worker_task.done()}")
            if not worker_task.done():
                LOGGER.info(f"Cancelling worker task {worker_task.get_name()}")
                worker_task.cancel()
                with suppress(asyncio.CancelledError):
                    await worker_task

        LOGGER.info("Alerts worker service shutdown complete")
