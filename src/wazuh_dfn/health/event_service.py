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
from typing import TYPE_CHECKING

from wazuh_dfn.config import HealthConfig
from wazuh_dfn.max_size_queue import AsyncMaxSizeQueue

from .models import (
    HealthEvent,
    KafkaPerformanceEvent,
    WorkerLastProcessedData,
    WorkerLastProcessedEvent,
    WorkerPerformanceData,
    WorkerPerformanceEvent,
)

if TYPE_CHECKING:
    from wazuh_dfn.health.models import KafkaPerformanceData


class HealthEventService:
    """Lightweight service for real-time performance event pushing.

    This service implements the planned hybrid push/pull architecture:
    - Services push performance events here in real-time
    - HealthService polls from the queue to consume events
    - Immediate alerting for extremely slow operations

    Note: Simplified queue-only approach since HealthService is the sole consumer.
    Removed subscriber pattern as it was redundant with queue polling.
    """

    def __init__(self, config: HealthConfig) -> None:
        """Initialize HealthEventService.

        Args:
            config: Health configuration for thresholds (required)
        """
        self.logger = logging.getLogger(f"{__name__}.HealthEventService")
        self._event_queue = AsyncMaxSizeQueue(maxsize=config.event_queue_size)
        self._config = config
        self._shutdown_event = asyncio.Event()

        # Use configurable thresholds from config
        self._extremely_slow_threshold = config.kafka_extremely_slow_threshold
        self._worker_stall_threshold = config.worker_stall_threshold

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
        await self._event_queue.put(event)

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
        await self._event_queue.put(event)

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
        await self._event_queue.put(event)

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
        self.logger.warning(
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
            return await asyncio.wait_for(self._event_queue.get(), timeout=0.1)
        except TimeoutError:
            return None
