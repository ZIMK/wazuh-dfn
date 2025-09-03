"""Observer service module for monitoring alert files."""

import asyncio
import logging
from datetime import datetime
from typing import Any

from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.max_size_queue import AsyncMaxSizeQueue

from .file_monitor import FileMonitor
from .wazuh_service import WazuhService

LOGGER = logging.getLogger(__name__)


class AlertsWatcherService:
    """Service for monitoring alert files."""

    def __init__(
        self,
        config: WazuhConfig,
        alert_queue: AsyncMaxSizeQueue,
        wazuh_service: WazuhService,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Initialize AlertsWatcherService.

        Args:
            config: WazuhConfig containing file monitoring settings
            alert_queue: Queue for storing parsed alerts
            wazuh_service: Service for checking Wazuh connection status
            shutdown_event: Event to signal shutdown
        """
        # Validation is handled by Pydantic automatically
        self.config = config
        self.alert_queue = alert_queue
        self.wazuh_service = wazuh_service
        self.shutdown_event = shutdown_event
        self.file_path = config.json_alert_file
        self.latest_queue_put: datetime | None = None
        self.file_monitor: FileMonitor | None = None

        # Back-pressure statistics
        self._back_pressure_active = False
        self._skipped_checks = 0
        self._last_connection_check = datetime.now()

        # File monitoring metrics
        self._total_file_checks = 0
        self._successful_file_checks = 0
        self._failed_file_checks = 0

    async def start(self) -> None:
        """Start monitoring alert files asynchronously."""
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

            await self.file_monitor.open()  # Ensure we explicitly open the file monitor

            while not self.shutdown_event.is_set():
                try:
                    # Check Wazuh connection status for back-pressure mechanism
                    is_connected = self.wazuh_service.is_connected

                    if not is_connected:
                        # Wazuh is disconnected - activate back-pressure
                        if not self._back_pressure_active:
                            LOGGER.warning(
                                "Wazuh connection lost. Activating back-pressure: "
                                "pausing file monitoring to prevent queue overflow."
                            )
                            self._back_pressure_active = True

                        self._skipped_checks += 1

                        # Log status every 10 skipped checks (roughly every 10 seconds with default poll interval)
                        if self._skipped_checks % 10 == 0:
                            LOGGER.info(
                                f"Back-pressure active: Wazuh still disconnected. "
                                f"Skipped {self._skipped_checks} file checks to prevent queue overflow."
                            )
                    else:
                        # Wazuh is connected - deactivate back-pressure if needed
                        if self._back_pressure_active:
                            LOGGER.info(
                                f"Wazuh connection restored. Deactivating back-pressure. "
                                f"Skipped {self._skipped_checks} file checks during outage."
                            )
                            self._back_pressure_active = False
                            self._skipped_checks = 0

                        # Normal file monitoring when connected
                        await self.file_monitor.check_file()
                        # Update latest queue put time from monitor
                        self.latest_queue_put = self.file_monitor.latest_queue_put

                except Exception as e:
                    LOGGER.error(f"Error during file check: {e!s}")
                    # Continue the loop instead of breaking on transient errors

                await asyncio.sleep(self.config.json_alert_file_poll_interval)

        except Exception as e:
            LOGGER.error(f"Critical error monitoring file: {e!s}")
        finally:
            if self.file_monitor:
                await self.file_monitor.close()
            LOGGER.info("Stopped file monitoring")

    async def stop(self) -> None:
        """Stop the monitoring asynchronously."""
        LOGGER.info("Stopping file monitoring")
        if self.file_monitor:
            await self.file_monitor.close()

    # HealthMetricsProvider protocol implementation
    def get_health_status(self) -> bool:
        """Get the health status of the AlertsWatcher service.

        Returns:
            bool: True if monitoring and not in back-pressure, False otherwise
        """
        return self.file_monitor is not None and not self._back_pressure_active

    def get_service_metrics(self) -> dict[str, Any]:
        """Get comprehensive service metrics for health monitoring.

        Returns:
            dict: Service metrics including file monitoring status and performance data
        """
        # Calculate operations based on file monitoring activity
        total_checks = max(self._total_file_checks, self._skipped_checks)
        failed_checks = self._failed_file_checks + self._skipped_checks
        successful_checks = max(0, total_checks - failed_checks)

        # Get file monitor metrics if available
        file_monitor_metrics = {}
        if self.file_monitor:
            file_monitor_metrics = {
                "file_monitor_latest_queue_put": (
                    self.file_monitor.latest_queue_put.isoformat() if self.file_monitor.latest_queue_put else None
                ),
                "file_monitor_current_inode": getattr(self.file_monitor, "current_inode", None),
                "file_monitor_buffer_size": len(getattr(self.file_monitor, "buffer", [])),
                "file_monitor_active": True,
            }
        else:
            file_monitor_metrics = {
                "file_monitor_latest_queue_put": None,
                "file_monitor_current_inode": None,
                "file_monitor_buffer_size": 0,
                "file_monitor_active": False,
            }

        return {
            "service_type": "file_monitor",
            "is_connected": self.file_monitor is not None,
            "connection_latency": 0.001,  # File system access time
            "total_operations": total_checks,
            "successful_operations": successful_checks,
            "failed_operations": failed_checks,
            "avg_response_time": self.config.json_alert_file_poll_interval,  # Poll interval as response time
            "max_response_time": self.config.json_alert_file_poll_interval * 2,  # Estimate worst case
            "slow_operations_count": self._skipped_checks,
            # AlertsWatcher-specific metrics
            "file_path": str(self.file_path),
            "back_pressure_active": self._back_pressure_active,
            "skipped_checks": self._skipped_checks,
            "latest_queue_put": self.latest_queue_put.isoformat() if self.latest_queue_put else None,
            "poll_interval": self.config.json_alert_file_poll_interval,
            "wazuh_connected": self.wazuh_service.is_connected if self.wazuh_service else False,
            # File monitor sub-component metrics
            **file_monitor_metrics,
        }

    def get_last_error(self) -> str | None:
        """Get the last error message if any.

        Returns:
            str | None: Last error message or None
        """
        # Would need to implement error tracking
        return None
