"""Protocol definitions for health metrics providers.

This module defines the interfaces that services must implement to integrate
with the health monitoring system. Uses Python's Protocol for structural
typing and clear contracts.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Protocol, TypedDict, runtime_checkable

from .models import (
    FileMonitorStatsData,
    HealthEvent,
    KafkaInternalStatsData,
    KafkaPerformanceEvent,
    QueueStatsData,
    WorkerLastProcessedEvent,
    WorkerPerformanceData,
    WorkerPerformanceEvent,
    WorkerProcessedTimesData,
)

LOGGER = logging.getLogger(__name__)


# Error handling structures
class HealthError(TypedDict):
    """Standard error response format for health metrics."""

    error_type: str
    message: str
    timestamp: float
    service_name: str


class HealthResponse(TypedDict):
    """Standard response format for health operations."""

    success: bool
    data: Any | None
    error: HealthError | None


@runtime_checkable
class HealthMetricsProvider(Protocol):
    """Protocol for services that provide health metrics.

    Services implementing this protocol can be automatically discovered
    and integrated into the health monitoring system through duck typing.

    The @runtime_checkable decorator allows isinstance() checks for
    protocol compliance at runtime.
    """

    def get_health_status(self) -> bool:
        """Check if the service is healthy and operational.

        Returns:
            bool: True if service is healthy, False otherwise
        """
        ...

    def get_service_metrics(self) -> dict[str, Any]:
        """Get service-specific metrics as a dictionary.

        Returns:
            dict[str, Any]: Service metrics in key-value format
        """
        ...

    def get_last_error(self) -> str | None:
        """Get the last error message if any.

        Returns:
            str | None: Last error message or None if no error
        """
        ...


@runtime_checkable
class HealthEventSubscriber(Protocol):
    """Protocol for services that subscribe to health events.

    The HealthService implements this protocol to receive real-time
    health events from the HealthEventService.
    """

    async def on_worker_performance_event(self, event: WorkerPerformanceEvent) -> None:
        """Handle a worker performance event.

        Args:
            event: Worker performance event data
        """
        ...

    async def on_worker_last_processed_event(self, event: WorkerLastProcessedEvent) -> None:
        """Handle a worker last processed event.

        Args:
            event: Worker last processed event data
        """
        ...

    async def on_kafka_performance_event(self, event: KafkaPerformanceEvent) -> None:
        """Handle a Kafka performance event.

        Args:
            event: Kafka performance event data
        """
        ...


@runtime_checkable
class WorkerMetricsProvider(HealthMetricsProvider, Protocol):
    """Protocol for worker services providing performance metrics.

    Extends HealthMetricsProvider with worker-specific functionality.
    """

    def get_worker_performance(self) -> WorkerPerformanceData:
        """Get current worker performance data.

        Returns:
            WorkerPerformanceData: Type-safe worker performance metrics
        """
        ...

    def get_worker_name(self) -> str:
        """Get the worker identifier.

        Returns:
            str: Unique worker name/ID
        """
        ...

    def is_processing(self) -> bool:
        """Check if worker is currently processing alerts.

        Returns:
            bool: True if actively processing, False if idle
        """
        ...


@runtime_checkable
class QueueMetricsProvider(HealthMetricsProvider, Protocol):
    """Protocol for queue services providing capacity and throughput metrics."""

    def get_queue_stats(self) -> QueueStatsData:
        """Get current queue statistics.

        Returns:
            QueueStatsData: Type-safe queue metrics
        """
        ...

    def get_queue_name(self) -> str:
        """Get the queue identifier.

        Returns:
            str: Queue name/identifier
        """
        ...

    def is_queue_healthy(self) -> bool:
        """Check if queue is operating within normal parameters.

        Returns:
            bool: True if queue is healthy, False if at risk
        """
        ...


@runtime_checkable
class KafkaMetricsProvider(HealthMetricsProvider, Protocol):
    """Protocol for Kafka service providing connection and performance metrics."""

    def get_kafka_stats(self) -> KafkaInternalStatsData:
        """Get internal Kafka performance statistics.

        Returns:
            KafkaInternalStatsData: Type-safe Kafka metrics
        """
        ...

    def is_connected(self) -> bool:
        """Check if Kafka connection is active.

        Returns:
            bool: True if connected, False otherwise
        """
        ...

    def get_connection_info(self) -> dict[str, Any]:
        """Get Kafka connection information.

        Returns:
            dict[str, Any]: Connection details (topic, bootstrap servers, etc.)
        """
        ...


@runtime_checkable
class FileMonitorMetricsProvider(HealthMetricsProvider, Protocol):
    """Protocol for file monitor services providing file processing metrics."""

    def get_file_monitor_stats(self) -> FileMonitorStatsData:
        """Get current file monitor statistics.

        Returns:
            FileMonitorStatsData: Type-safe file monitor metrics (replaces log_stats tuple)
        """
        ...

    def get_monitored_files_count(self) -> int:
        """Get the number of files currently being monitored.

        Returns:
            int: Number of monitored files
        """
        ...

    def is_monitoring_active(self) -> bool:
        """Check if file monitoring is active.

        Returns:
            bool: True if actively monitoring files, False otherwise
        """
        ...


@runtime_checkable
class EventPublisher(Protocol):
    """Protocol for services that can publish health events.

    Allows decoupled event publishing for health monitoring.
    """

    def publish_health_event(self, event: HealthEvent) -> bool:
        """Publish a health event.

        Args:
            event: Health event data to publish

        Returns:
            bool: True if published successfully, False otherwise
        """
        ...

    def is_publisher_available(self) -> bool:
        """Check if event publisher is available.

        Returns:
            bool: True if can publish events, False otherwise
        """
        ...


class BaseHealthMetricsProvider(ABC):
    """Abstract base class providing common health metrics functionality.

    Services can inherit from this class instead of implementing the protocol
    directly if they prefer inheritance over duck typing.
    """

    def __init__(self, service_name: str) -> None:
        """Initialize base provider.

        Args:
            service_name: Unique service identifier
        """
        self.service_name = service_name
        self._last_error: str | None = None
        self._is_healthy = True

    @abstractmethod
    def get_service_metrics(self) -> dict[str, Any]:
        """Get service-specific metrics. Must be implemented by subclasses."""
        ...

    def get_health_status(self) -> bool:
        """Default health status implementation."""
        return self._is_healthy

    def get_last_error(self) -> str | None:
        """Get the last recorded error."""
        return self._last_error

    def _set_error(self, error_msg: str) -> None:
        """Record an error and mark service as unhealthy.

        Args:
            error_msg: Error message to record
        """
        self._last_error = error_msg
        self._is_healthy = False

    def _clear_error(self) -> None:
        """Clear error state and mark service as healthy."""
        self._last_error = None
        self._is_healthy = True


class WorkerStatsCollector:
    """Utility class for collecting worker statistics from multiple providers.

    Aggregates data from multiple WorkerMetricsProvider instances to build
    comprehensive worker health overview.
    """

    def __init__(self) -> None:
        """Initialize collector."""
        self._providers: list[WorkerMetricsProvider] = []

    def register_provider(self, provider: WorkerMetricsProvider) -> None:
        """Register a worker metrics provider.

        Args:
            provider: Worker metrics provider to register
        """
        if isinstance(provider, WorkerMetricsProvider):
            self._providers.append(provider)
        else:
            raise TypeError("Provider must implement WorkerMetricsProvider protocol")

    def get_all_worker_performance(self) -> list[tuple[str, WorkerPerformanceData]]:
        """Collect performance data from all registered providers.

        Returns:
            list[tuple[str, WorkerPerformanceData]]: List of (worker_name, performance_data) tuples
        """
        results = []
        for provider in self._providers:
            try:
                worker_name = provider.get_worker_name()
                performance = provider.get_worker_performance()
                results.append((worker_name, performance))
            except Exception as e:
                # Log error but continue with other providers
                LOGGER.error(f"Error collecting from worker {getattr(provider, 'service_name', 'unknown')}: {e}")
        return results

    def get_healthy_worker_count(self) -> int:
        """Count healthy workers.

        Returns:
            int: Number of healthy workers
        """
        return sum(1 for provider in self._providers if provider.get_health_status())

    def get_processed_times(self) -> WorkerProcessedTimesData:
        """Collect last processed times from all workers.

        Returns:
            WorkerProcessedTimesData: Mapping of worker names to last processed times
        """
        worker_times = {}
        for provider in self._providers:
            try:
                worker_name = provider.get_worker_name()
                performance = provider.get_worker_performance()
                worker_times[worker_name] = performance["timestamp"]
            except Exception as e:
                LOGGER.error(f"Error getting processed time from {getattr(provider, 'service_name', 'unknown')}: {e}")

        return WorkerProcessedTimesData(worker_times=worker_times)


class QueueStatsCollector:
    """Utility class for collecting queue statistics from multiple providers."""

    def __init__(self) -> None:
        """Initialize collector."""
        self._providers: list[QueueMetricsProvider] = []

    def register_provider(self, provider: QueueMetricsProvider) -> None:
        """Register a queue metrics provider.

        Args:
            provider: Queue metrics provider to register
        """
        if isinstance(provider, QueueMetricsProvider):
            self._providers.append(provider)
        else:
            raise TypeError("Provider must implement QueueMetricsProvider protocol")

    def get_all_queue_stats(self) -> list[tuple[str, QueueStatsData]]:
        """Collect statistics from all registered queue providers.

        Returns:
            list[tuple[str, QueueStatsData]]: List of (queue_name, stats) tuples
        """
        results = []
        for provider in self._providers:
            try:
                queue_name = provider.get_queue_name()
                stats = provider.get_queue_stats()
                results.append((queue_name, stats))
            except Exception as e:
                LOGGER.error(f"Error collecting from queue {getattr(provider, 'service_name', 'unknown')}: {e}")
        return results

    def get_total_capacity_utilization(self) -> float:
        """Calculate average capacity utilization across all queues.

        Returns:
            float: Average utilization (0.0-1.0)
        """
        utilizations = []
        for provider in self._providers:
            try:
                stats = provider.get_queue_stats()
                if stats["max_queue_size"] > 0:
                    utilization = stats["last_queue_size"] / stats["max_queue_size"]
                    utilizations.append(min(1.0, utilization))
            except Exception as e:
                # Log the exception before continuing to aid in debugging
                logging.getLogger(__name__).debug(f"Failed to get queue stats from provider: {e}")
                continue

        return sum(utilizations) / len(utilizations) if utilizations else 0.0


@runtime_checkable
class APIHealthProvider(Protocol):
    """Protocol for health providers that can serve API requests.

    This protocol defines the interface that health providers must implement
    to be compatible with the Health API Server. Both the real HealthService
    and test mock providers should implement these methods.
    """

    def get_health_status(self) -> dict[str, Any]:
        """Get basic health status information.

        Returns:
            dict: Basic health status with at least 'status' and 'timestamp' keys
        """
        ...

    def get_detailed_health_status(self) -> dict[str, Any]:
        """Get detailed health status information.

        Returns:
            dict: Detailed health information including system, workers, queues, services
        """
        ...

    def get_health_metrics(self) -> Any:
        """Get health metrics for Prometheus export.

        Returns:
            HealthMetrics object or compatible data structure
        """
        ...

    def get_worker_status(self) -> dict[str, Any]:
        """Get worker status information.

        Returns:
            dict: Worker status with 'workers' and 'summary' keys
        """
        ...

    def get_queue_status(self) -> dict[str, Any]:
        """Get queue status information.

        Returns:
            dict: Queue status with 'queues' and 'summary' keys
        """
        ...

    def get_system_status(self) -> dict[str, Any]:
        """Get system status information.

        Returns:
            dict: System status with 'system' and 'timestamp' keys
        """
        ...
