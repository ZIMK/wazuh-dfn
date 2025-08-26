"""HealthEventService - Lightweight service for real-time performance event pushing.

This service implements the planned hybrid push/pull architecture:
- Services push performance events here in real-time
- HealthService polls from the queue to consume events
- Immediate alerting for extremely slow operations

Note: Simplified queue-only approach since HealthService is the sole consumer.
Removed subscriber pattern as it was redundant with queue polling.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

from wazuh_dfn.config import HealthConfig
from wazuh_dfn.max_size_queue import AsyncMaxSizeQueue

from .models import (
    HealthEvent,
    KafkaPerformanceEvent,
    QueueStatsData,
    WorkerLastProcessedData,
    WorkerLastProcessedEvent,
    WorkerPerformanceData,
    WorkerPerformanceEvent,
)

if TYPE_CHECKING:
    from wazuh_dfn.health.models import KafkaPerformanceData


# Logging
LOGGER = logging.getLogger(__name__)


class HealthEventService:
    """Lightweight service for real-time performance event pushing.

    This service implements the planned hybrid push/pull architecture:
    - Services push performance events here in real-time
    - HealthService polls from the queue to consume events
    - Immediate alerting for extremely slow operations

    Note: Simplified queue-only approach since HealthService is the sole consumer.
    Removed subscriber pattern as it was redundant with queue polling.
    """

    def __init__(self, config: HealthConfig, shutdown_event: asyncio.Event) -> None:
        """Initialize HealthEventService.

        Args:
            config: Health configuration for thresholds (required)
            shutdown_event: Event to signal shutdown
        """
        self._event_queue = AsyncMaxSizeQueue(maxsize=config.event_queue_size)
        self._config = config
        self._shutdown_event = shutdown_event

        # Use configurable thresholds from config
        self._extremely_slow_threshold = config.kafka_extremely_slow_threshold
        self._worker_stall_threshold = config.worker_stall_threshold

        # Add counters for monitoring queue health - ensure timestamp is stored as int
        self._queue_stats = {
            "total_processed": 0,
            "last_queue_size": 0,
            "max_queue_size": 0,
            "config_max_queue_size": self._event_queue.maxsize,
            "queue_full_count": 0,
            "last_queue_check": int(datetime.now().timestamp()),
        }
        self._stats_lock = asyncio.Lock()

        # Track last error for health monitoring
        self._last_error: str | None = None

    @property
    def event_queue(self) -> AsyncMaxSizeQueue:
        """Access to the event queue for testing and health service polling."""
        return self._event_queue

    async def push_worker_performance(self, worker_name: str, performance_data: WorkerPerformanceData) -> None:
        """Real-time push from AlertsWorkerService (replaces record_worker_performance).

        Type-safe: Uses WorkerPerformanceData instead of unsafe dict[str, Any]

        Args:
            worker_name: Name of the worker
            performance_data: Type-safe worker performance data
        """
        timestamp = time.time()
        event: WorkerPerformanceEvent = {
            "event_type": "worker_performance",
            "timestamp": timestamp,
            "worker_name": worker_name,
            "data": performance_data,
        }

        # Add to queue for polling by HealthService
        try:
            await self._event_queue.put(event)

            # Update queue statistics
            async with self._stats_lock:
                self._queue_stats["total_processed"] += 1
                current_size = self._event_queue.qsize()
                self._queue_stats["last_queue_size"] = current_size
                self._queue_stats["max_queue_size"] = max(self._queue_stats["max_queue_size"], current_size)

                # Check if queue is getting full
                if self._event_queue.full():
                    self._queue_stats["queue_full_count"] += 1

        except Exception as e:
            self._last_error = f"Failed to push worker performance event: {e}"
            LOGGER.error(self._last_error)
            raise

        # Immediate alerting for extremely slow operations (preserve current behavior)
        # Type-safe access: performance_data["extremely_slow_alerts"] instead of .get()
        if (
            performance_data["extremely_slow_alerts"] > 0
            and performance_data["last_processing_time"] > self._extremely_slow_threshold
        ):
            self._emit_immediate_alert(event)

    async def push_worker_last_processed(self, worker_name: str, info: WorkerLastProcessedData) -> None:
        """Real-time push from AlertsWorkerService (replaces update_worker_last_processed).

        Type-safe: Uses WorkerLastProcessedData instead of unsafe dict[str, Any]

        Args:
            worker_name: Name of the worker
            info: Type-safe worker processing information
        """
        timestamp = time.time()
        event: WorkerLastProcessedEvent = {
            "event_type": "worker_last_processed",
            "timestamp": timestamp,
            "worker_name": worker_name,
            "data": info,
        }

        # Add to queue for polling by HealthService
        try:
            await self._event_queue.put(event)

            # Update queue statistics
            async with self._stats_lock:
                self._queue_stats["total_processed"] += 1
                current_size = self._event_queue.qsize()
                self._queue_stats["last_queue_size"] = current_size
                self._queue_stats["max_queue_size"] = max(self._queue_stats["max_queue_size"], current_size)

                # Check if queue is getting full
                if self._event_queue.full():
                    self._queue_stats["queue_full_count"] += 1

        except Exception as e:
            self._last_error = f"Failed to push worker last processed event: {e}"
            LOGGER.error(self._last_error)
            raise

    async def push_kafka_performance(self, operation_data: KafkaPerformanceData) -> None:
        """Real-time push from KafkaService (replaces record_kafka_performance).

        Type-safe: Uses KafkaPerformanceData TypedDict

        Args:
            operation_data: Kafka performance data
        """
        timestamp = time.time()
        event: KafkaPerformanceEvent = {
            "event_type": "kafka_performance",
            "timestamp": timestamp,
            "data": operation_data,
        }

        # Add to queue for polling by HealthService
        try:
            await self._event_queue.put(event)

            # Update queue statistics
            async with self._stats_lock:
                self._queue_stats["total_processed"] += 1
                current_size = self._event_queue.qsize()
                self._queue_stats["last_queue_size"] = current_size
                self._queue_stats["max_queue_size"] = max(self._queue_stats["max_queue_size"], current_size)

                # Check if queue is getting full
                if self._event_queue.full():
                    self._queue_stats["queue_full_count"] += 1

        except Exception as e:
            self._last_error = f"Failed to push kafka performance event: {e}"
            LOGGER.error(self._last_error)
            raise

        # Immediate alerting for extremely slow operations (preserve current behavior)
        # Safe access: Use .get() since TypedDict has total=False
        total_time = operation_data.get("total_time", 0.0)
        if total_time > self._extremely_slow_threshold:
            self._emit_immediate_alert(event)

    def _emit_immediate_alert(self, event: HealthEvent) -> None:
        """Emit immediate alert for extremely slow operations.

        Args:
            event: Health event that triggered the alert
        """
        LOGGER.warning(
            f"IMMEDIATE ALERT: Extremely slow operation detected - "
            f"Event: {event['event_type']}, Timestamp: {event['timestamp']}"
        )

    def get_event_queue_size(self) -> int:
        """Get current size of event queue.

        Returns:
            int: Number of events in queue
        """
        return self._event_queue.qsize()

    async def get_next_event(self) -> HealthEvent | None:
        """Get the next event from the queue (for HealthService to consume).

        Returns:
            HealthEvent | None: Next event or None if queue is empty
        """
        try:
            event = await asyncio.wait_for(self._event_queue.get(), timeout=0.1)

            # Update queue statistics on consumption
            async with self._stats_lock:
                self._queue_stats["last_queue_size"] = self._event_queue.qsize()
                self._queue_stats["last_queue_check"] = int(time.time())

            # Clear any previous errors on successful operation
            self._last_error = None
            return event

        except TimeoutError:
            return None
        except Exception as e:
            self._last_error = f"Failed to get next event: {e}"
            LOGGER.error(self._last_error)
            return None

    # QueueMetricsProvider protocol implementation
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
            "last_queue_size": self._event_queue.qsize(),
        }

    def get_queue_name(self) -> str:
        """Get the queue identifier.

        Returns:
            str: Queue name/identifier
        """
        return "health_event_queue"

    def is_queue_healthy(self) -> bool:
        """Check if queue is operating within normal parameters.

        Returns:
            bool: True if queue is healthy, False if at risk
        """
        # Consider queue healthy if not full and service is running
        return not self._event_queue.full() and self.get_health_status()

    # HealthMetricsProvider protocol implementation
    def get_health_status(self) -> bool:
        """Check if the service is healthy and operational.

        Returns:
            bool: True if service is healthy, False otherwise
        """
        return not self._shutdown_event.is_set()

    def get_service_metrics(self) -> dict[str, Any]:
        """Get comprehensive service metrics.

        Returns:
            dict[str, Any]: Service metrics data
        """
        return {
            "health_status": self.get_health_status(),
            "queue_stats": self.get_queue_stats(),
            "queue_name": self.get_queue_name(),
            "is_queue_healthy": self.is_queue_healthy(),
            "event_queue_size": self.get_event_queue_size(),
            "last_error": self.get_last_error(),
        }

    def get_last_error(self) -> str | None:
        """Get the last error message if any.

        Returns:
            str | None: Last error message or None
        """
        return self._last_error
