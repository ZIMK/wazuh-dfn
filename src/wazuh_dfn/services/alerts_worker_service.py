"""Alerts worker service module for processing alerts from the queue."""

import asyncio
import json
import logging
import secrets
import tempfile
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any

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
        self._last_processed_time = datetime.now().timestamp()

    @property
    def last_processed_time(self) -> float:
        """Get the timestamp of the last processed alert.

        Returns:
            float: Timestamp of last processed alert
        """
        return self._last_processed_time

    async def start(self) -> None:
        """Start worker tasks for processing alerts asynchronously.

        Creates and manages a pool of worker tasks according to the configuration.
        Each worker processes alerts from the queue until shutdown is signaled.
        """
        LOGGER.info(f"Starting {self.config.num_workers} alert worker tasks")
        task_name = asyncio.current_task().get_name() if asyncio.current_task() else "AlertsWorkerService"
        LOGGER.info(f"Alerts worker service running as task: {task_name}")

        try:
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

    async def _process_alerts(self) -> None:
        """Process alerts from the queue asynchronously.

        Continuously retrieves alerts from the queue and processes them
        through the alerts_service until shutdown is signaled.
        Handles errors and timeouts gracefully.
        """
        worker_name = asyncio.current_task().get_name() if asyncio.current_task() else "AlertWorker"
        LOGGER.info(f"Started alert processing worker: {worker_name}")

        while not self.shutdown_event.is_set():
            try:
                # Get alert with timeout
                try:
                    alert = await asyncio.wait_for(self.alert_queue.get(), timeout=1.0)

                    try:
                        # Process the alert
                        await self.alerts_service.process_alert(alert)
                        self._last_processed_time = datetime.now().timestamp()
                    except Exception as e:
                        alert_id = alert.get("id", "unknown")
                        LOGGER.error(f"Error processing alert {alert_id}: {e}", exc_info=True)

                        # Dump failed alert for debugging
                        debug_path = await self._dump_alert(alert)
                        if debug_path:
                            LOGGER.info(f"Dumped failed alert to {debug_path}")
                    finally:
                        # Mark the task as done
                        self.alert_queue.task_done()

                except TimeoutError:
                    # This is expected - just retry
                    continue

            except asyncio.CancelledError:
                # Exit gracefully on cancellation
                LOGGER.info(f"Worker {worker_name} task cancelled")
                break

            except Exception as e:
                LOGGER.error(f"Error in worker {worker_name}: {e}", exc_info=True)
                # Wait a bit before retrying on unexpected errors
                await asyncio.sleep(0.1)

        LOGGER.info(f"Stopping worker {worker_name}")

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

        # Wait for remaining items in queue
        if not self.alert_queue.empty():
            LOGGER.info("Waiting for remaining alerts to be processed")
            await self.alert_queue.join()

        # Wait for all workers to finish
        for worker_task in self.worker_tasks:
            if not worker_task.done():
                worker_task.cancel()
                with suppress(asyncio.CancelledError):
                    await worker_task

        LOGGER.info("Alerts worker service shutdown complete")
