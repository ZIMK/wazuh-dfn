"""Health monitoring package for wazuh-dfn.

Provides comprehensive health monitoring capabilities with:
- Type-safe data structures replacing unsafe dict[str, Any]
- Fluent builder classes for data construction
- Pydantic v2 models with validation and serialization
- REST API support for external monitoring
"""

from __future__ import annotations

__author__ = "Sebastian Wolf (https://github.com/ZIMK/wazuh-dfn)"
__maintainer__ = "Sebastian Wolf"

# Import main health components for easy access
from .api_server import (
    APIConfiguration,
    HealthAPIServer,
    create_health_api_server,
)
from .builders import (
    KafkaPerformanceBuilder,
    QueueStatsBuilder,
    WorkerPerformanceBuilder,
)
from .event_service import (
    HealthEventService,
)
from .models import (
    BaseHealthModel,
    HealthEvent,
    HealthMetrics,
    KafkaInternalStatsData,
    KafkaPerformanceEvent,
    QueueHealth,
    QueueStatsData,
    ServiceHealth,
    SystemHealth,
    WorkerHealth,
    WorkerLastProcessedData,
    WorkerLastProcessedEvent,
    WorkerPerformanceData,
    WorkerPerformanceEvent,
    WorkerProcessedTimesData,
)
from .protocols import (
    BaseHealthMetricsProvider,
    EventPublisher,
    HealthMetricsProvider,
    KafkaMetricsProvider,
    QueueMetricsProvider,
    QueueStatsCollector,
    WorkerMetricsProvider,
    WorkerStatsCollector,
)

__all__ = [
    "APIConfiguration",
    "BaseHealthMetricsProvider",
    "BaseHealthModel",
    "EventPublisher",
    "HealthAPIServer",
    "HealthEvent",
    "HealthEventService",
    "HealthMetrics",
    "HealthMetricsProvider",
    "KafkaInternalStatsData",
    "KafkaMetricsProvider",
    "KafkaPerformanceBuilder",
    "KafkaPerformanceEvent",
    "QueueHealth",
    "QueueMetricsProvider",
    "QueueStatsBuilder",
    "QueueStatsCollector",
    "QueueStatsData",
    "ServiceHealth",
    "SystemHealth",
    "WorkerHealth",
    "WorkerLastProcessedData",
    "WorkerLastProcessedEvent",
    "WorkerMetricsProvider",
    "WorkerPerformanceBuilder",
    "WorkerPerformanceData",
    "WorkerPerformanceEvent",
    "WorkerProcessedTimesData",
    "WorkerStatsCollector",
    "create_health_api_server",
]
