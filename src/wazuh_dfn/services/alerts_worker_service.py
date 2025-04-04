"""Alerts worker service module for processing alerts from the queue."""

import asyncio
import json
import logging
import secrets
import tempfile
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any, List

from wazuh_dfn.config import MiscConfig
from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue

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

        # Add counters for monitoring queue health
        self._queue_stats = {
            "total_processed": 0,
            "last_queue_size": 0,
            "max_queue_size": 0,
            "queue_full_count": 0,
            "last_queue_check": datetime.now().timestamp(),
        }
        self._stats_lock = asyncio.Lock()

        # Track if we're in high throughput mode
        self._high_throughput_mode = False

        # Start queue monitoring task
        self._monitor_task = None

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
                                f"Queue at {fill_percentage:.1f}% capacity ({current_size}/{max_size}). "
                                f"Enabling high-throughput mode."
                            )
                    elif fill_percentage < 50 and self._high_throughput_mode:
                        # Disable high throughput mode when queue is less full
                        self._high_throughput_mode = False
                        LOGGER.info(f"Queue at {fill_percentage:.1f}% capacity. Disabling high-throughput mode.")

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

    async def _process_alerts(self) -> None:
        """Process alerts from the queue asynchronously.

        Continuously retrieves alerts from the queue and processes them
        through the alerts_service until shutdown is signaled.
        Handles errors and timeouts gracefully.
        """
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

        # Batch size for high-throughput mode
        batch_size = 5

        while not self.shutdown_event.is_set():
            try:
                # In high-throughput mode, try to process multiple alerts in a batch when queue is filling up
                is_high_throughput = self._high_throughput_mode

                if is_high_throughput:
                    # Process multiple alerts in a batch
                    await self._process_alert_batch(worker_name, batch_size, alerts_processed, total_processing_time)
                else:
                    # Process single alerts normally
                    # Use shorter timeout if queue has been consistently empty
                    timeout = 0.05 if consecutive_empty > 5 else 0.2

                    try:
                        # Get an alert from the queue
                        alert = await asyncio.wait_for(self.alert_queue.get(), timeout=timeout)
                        consecutive_empty = 0  # Reset empty counter

                        try:
                            # Process the alert with detailed timing
                            process_start = datetime.now()
                            await self.alerts_service.process_alert(alert)
                            process_end = datetime.now()

                            # Update timestamp with minimal locking
                            now = datetime.now().timestamp()
                            async with self._times_lock:
                                self._worker_processed_times[worker_name] = now

                            # Performance tracking
                            alerts_processed += 1
                            processing_time = (process_end - process_start).total_seconds()
                            total_processing_time += processing_time

                            # Update global stats
                            async with self._stats_lock:
                                self._queue_stats["total_processed"] += 1

                            if processing_time > 0.5:
                                LOGGER.warning(
                                    f"Worker {worker_name} slow alert processing: {processing_time:.2f}s "
                                    f"for alert {alert.get('id', 'unknown')}"
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

                # Periodically log performance metrics (every 30 seconds)
                now_time = datetime.now()
                if (now_time - last_metrics_dump).total_seconds() > 30:
                    elapsed = (now_time - start_time).total_seconds()
                    rate = alerts_processed / elapsed if elapsed > 0 else 0
                    avg_processing = total_processing_time / alerts_processed if alerts_processed > 0 else 0

                    LOGGER.info(
                        f"Worker {worker_name} performance: {alerts_processed} alerts processed, "
                        f"rate: {rate:.2f} alerts/sec, avg processing: {avg_processing*1000:.2f}ms, "
                        f"total runtime: {elapsed:.1f}s"
                    )

                    # Check if this worker is significantly slower than expected
                    if alerts_processed > 10 and rate < 0.5:
                        LOGGER.warning(
                            f"Worker {worker_name} is processing alerts slower than expected ({rate:.2f}/sec). "
                            f"Average processing time: {avg_processing*1000:.2f}ms"
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

    async def _process_alert_batch(
        self, worker_name: str, batch_size: int, alerts_processed: int, total_processing_time: float
    ) -> tuple[int, float]:
        """Process multiple alerts in a batch when queue is filling up.

        Args:
            worker_name: Name of the worker processing the batch
            batch_size: Maximum number of alerts to process in this batch
            alerts_processed: Current count of processed alerts to update
            total_processing_time: Current total processing time to update

        Returns:
            tuple: Updated (alerts_processed, total_processing_time)
        """
        batch = []
        batch_start = datetime.now()

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
            return alerts_processed, total_processing_time

        # Process the batch
        try:
            batch_start_time = datetime.now()

            # Process each alert in sequence
            for alert in batch:
                try:
                    process_start = datetime.now()
                    await self.alerts_service.process_alert(alert)
                    process_end = datetime.now()

                    # Track processing time for individual alert
                    processing_time = (process_end - process_start).total_seconds()
                    total_processing_time += processing_time
                    alerts_processed += 1

                    # Update global stats
                    async with self._stats_lock:
                        self._queue_stats["total_processed"] += 1

                except Exception as e:
                    alert_id = alert.get("id", "unknown")
                    LOGGER.error(f"Error processing alert {alert_id} in batch: {e}", exc_info=True)
                finally:
                    # Mark as done regardless of success or failure
                    self.alert_queue.task_done()

            # Update the last processed time once for the batch
            now = datetime.now().timestamp()
            async with self._times_lock:
                self._worker_processed_times[worker_name] = now

            # Log batch performance
            batch_time = (datetime.now() - batch_start_time).total_seconds()
            LOGGER.debug(
                f"Worker {worker_name} processed batch of {len(batch)} alerts in {batch_time:.3f}s "
                f"({batch_time/len(batch):.3f}s per alert)"
            )

        except Exception as e:
            LOGGER.error(f"Error processing alert batch: {e}", exc_info=True)

        return alerts_processed, total_processing_time

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
            self._monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._monitor_task

        # Wait for all workers to finish
        for worker_task in self.worker_tasks:
            if not worker_task.done():
                worker_task.cancel()
                with suppress(asyncio.CancelledError):
                    await worker_task

        LOGGER.info("Alerts worker service shutdown complete")
