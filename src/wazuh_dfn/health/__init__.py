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
# Note: HealthAPIServer requires optional aiohttp dependency
try:
    from .api import HealthAPIServer, AIOHTTP_AVAILABLE  # noqa: F401

    _AIOHTTP_AVAILABLE = AIOHTTP_AVAILABLE
except ImportError:
    _AIOHTTP_AVAILABLE = False

# Import APIConfig from main config for backward compatibility
import contextlib

with contextlib.suppress(ImportError):
    from wazuh_dfn.config import APIConfig  # noqa: F401

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
    "BaseHealthMetricsProvider",
    "BaseHealthModel",
    "EventPublisher",
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
]

# Add API components if aiohttp is available
if _AIOHTTP_AVAILABLE:
    __all__.extend(["APIConfig", "HealthAPIServer"])
