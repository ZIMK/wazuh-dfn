"""Tests for wazuh_dfn.health.protocols module."""

from datetime import datetime
from typing import Any

import pytest

from wazuh_dfn.health.models import (
    HealthStatus,
    KafkaInternalStatsData,
    QueueStatsData,
    WorkerPerformanceData,
)
from wazuh_dfn.health.protocols import (
    BaseHealthMetricsProvider,
    HealthError,
    HealthMetricsProvider,
    HealthResponse,
    KafkaMetricsProvider,
    QueueMetricsProvider,
    QueueStatsCollector,
    WorkerMetricsProvider,
    WorkerStatsCollector,
)


def test_health_error_structure():
    """Test HealthError TypedDict structure."""
    error: HealthError = {
        "error_type": "connection_error",
        "message": "Failed to connect to service",
        "timestamp": 1234567890.0,
        "service_name": "test_service",
    }

    assert error["error_type"] == "connection_error"
    assert error["message"] == "Failed to connect to service"
    assert error["timestamp"] == 1234567890.0
    assert error["service_name"] == "test_service"


def test_health_response_success():
    """Test HealthResponse TypedDict for success case."""
    response: HealthResponse = {"success": True, "data": {"status": HealthStatus.HEALTHY}, "error": None}

    assert response["success"] is True
    assert response["data"] == {"status": HealthStatus.HEALTHY}
    assert response["error"] is None


def test_health_response_error():
    """Test HealthResponse TypedDict for error case."""
    error: HealthError = {
        "error_type": "validation_error",
        "message": "Invalid input data",
        "timestamp": 1234567890.0,
        "service_name": "test_service",
    }

    response: HealthResponse = {"success": False, "data": None, "error": error}

    assert response["success"] is False
    assert response["data"] is None
    assert response["error"] == error


class MockHealthMetricsProvider:
    """Mock implementation of HealthMetricsProvider protocol."""

    def __init__(self, healthy: bool = True, error: str | None = None):
        self.healthy = healthy
        self.error = error
        self.metrics = {"test_metric": 42}

    def get_health_status(self) -> bool:
        return self.healthy

    def get_service_metrics(self) -> dict[str, Any]:
        return self.metrics

    def get_last_error(self) -> str | None:
        return self.error


class MockWorkerMetricsProvider(MockHealthMetricsProvider):
    """Mock implementation of WorkerMetricsProvider protocol."""

    def __init__(self, worker_name: str = "test_worker", **kwargs):
        super().__init__(**kwargs)
        self.worker_name = worker_name
        self.performance_data: WorkerPerformanceData = {
            "timestamp": datetime.now().timestamp(),
            "alerts_processed": 100,
            "rate": 10.0,
            "avg_processing": 0.1,
            "recent_avg": 0.08,
            "min_time": 0.05,
            "max_time": 0.5,
            "slow_alerts": 2,
            "extremely_slow_alerts": 0,
            "last_processing_time": datetime.now().timestamp(),
            "last_alert_id": "test-alert-123",
            "worker_count": 4,
            "active_worker_count": 3,
        }
        self.processing = True

    def get_worker_performance(self) -> WorkerPerformanceData:
        return self.performance_data

    def get_worker_name(self) -> str:
        return self.worker_name

    def is_processing(self) -> bool:
        return self.processing


class MockQueueMetricsProvider(MockHealthMetricsProvider):
    """Mock implementation of QueueMetricsProvider protocol."""

    def __init__(self, queue_name: str = "test_queue", **kwargs):
        super().__init__(**kwargs)
        self.queue_name = queue_name
        self.queue_stats: QueueStatsData = {
            "total_processed": 500,
            "max_queue_size": 100,
            "config_max_queue_size": 1000,
            "queue_full_count": 1,
            "last_queue_size": 10,
        }

    def get_queue_stats(self) -> QueueStatsData:
        return self.queue_stats

    def get_queue_name(self) -> str:
        return self.queue_name

    def is_queue_healthy(self) -> bool:
        return self.healthy


class MockKafkaMetricsProvider(MockHealthMetricsProvider):
    """Mock implementation of KafkaMetricsProvider protocol."""

    def __init__(self, connected: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.connected = connected
        self.kafka_stats: KafkaInternalStatsData = {
            "slow_operations": 10,
            "total_operations": 1000,
            "last_slow_operation_time": 0.03,
            "max_operation_time": 0.2,
            "recent_stage_times": [
                {"prep": 0.01, "encode": 0.02, "send": 0.15, "connect": 0.02},
                {"prep": 0.015, "encode": 0.025, "send": 0.18, "connect": 0.015},
            ],
        }
        self.connection_info = {"bootstrap_servers": ["localhost:9092"], "topic": "test_topic"}

    def get_kafka_stats(self) -> KafkaInternalStatsData:
        return self.kafka_stats

    def is_connected(self) -> bool:
        return self.connected

    def get_connection_info(self) -> dict[str, Any]:
        return self.connection_info


def test_health_metrics_provider_protocol_compliance():
    """Test that mock implements HealthMetricsProvider protocol."""
    provider = MockHealthMetricsProvider()

    # Runtime checkable protocol
    assert isinstance(provider, HealthMetricsProvider)

    # Test protocol methods
    assert provider.get_health_status() is True
    assert provider.get_service_metrics() == {"test_metric": 42}
    assert provider.get_last_error() is None


def test_worker_metrics_provider_protocol_compliance():
    """Test that mock implements WorkerMetricsProvider protocol."""
    provider = MockWorkerMetricsProvider("worker-1")

    # Runtime checkable protocol
    assert isinstance(provider, WorkerMetricsProvider)
    assert isinstance(provider, HealthMetricsProvider)  # Inheritance

    # Test protocol methods
    assert provider.get_worker_name() == "worker-1"
    assert provider.is_processing() is True
    performance = provider.get_worker_performance()

    # Performance should be a TypedDict (dict with type annotations)
    assert isinstance(performance, dict)
    assert performance["alerts_processed"] == 100
    assert "timestamp" in performance


def test_queue_metrics_provider_protocol_compliance():
    """Test that mock implements QueueMetricsProvider protocol."""
    provider = MockQueueMetricsProvider("queue-1")

    # Runtime checkable protocol
    assert isinstance(provider, QueueMetricsProvider)
    assert isinstance(provider, HealthMetricsProvider)  # Inheritance

    # Test protocol methods
    assert provider.get_queue_name() == "queue-1"
    assert provider.is_queue_healthy() is True
    stats = provider.get_queue_stats()

    # Stats should be a TypedDict (dict with type annotations)
    assert isinstance(stats, dict)
    assert stats["total_processed"] == 500
    assert stats["last_queue_size"] == 10


def test_kafka_metrics_provider_protocol_compliance():
    """Test that mock implements KafkaMetricsProvider protocol."""
    provider = MockKafkaMetricsProvider()

    # Runtime checkable protocol
    assert isinstance(provider, KafkaMetricsProvider)
    assert isinstance(provider, HealthMetricsProvider)  # Inheritance

    # Test protocol methods
    assert provider.is_connected() is True
    stats = provider.get_kafka_stats()

    # Stats should be a TypedDict (dict with type annotations)
    assert isinstance(stats, dict)
    assert stats["total_operations"] == 1000
    connection_info = provider.get_connection_info()
    assert "bootstrap_servers" in connection_info


def test_base_provider_initialization():
    """Test BaseHealthMetricsProvider initialization."""

    class ConcreteProvider(BaseHealthMetricsProvider):
        def get_service_metrics(self) -> dict[str, Any]:
            return {"test": "data"}

    provider = ConcreteProvider("test_service")

    assert provider.service_name == "test_service"
    assert provider.get_health_status() is True
    assert provider.get_last_error() is None


def test_base_provider_error_handling():
    """Test error handling in BaseHealthMetricsProvider."""

    class ConcreteProvider(BaseHealthMetricsProvider):
        def get_service_metrics(self) -> dict[str, Any]:
            return {"test": "data"}

    provider = ConcreteProvider("test_service")

    # Test error setting
    provider._set_error("Test error")
    assert provider.get_health_status() is False
    assert provider.get_last_error() == "Test error"

    # Test error clearing
    provider._clear_error()
    assert provider.get_health_status() is True
    assert provider.get_last_error() is None


def test_base_provider_abstract_method():
    """Test that BaseHealthMetricsProvider enforces abstract method."""
    with pytest.raises(TypeError):
        # Cannot instantiate abstract class
        BaseHealthMetricsProvider("test")  # type: ignore[]


def test_worker_stats_collector():
    """Test WorkerStatsCollector functionality."""
    collector = WorkerStatsCollector()

    # Test registration
    provider1 = MockWorkerMetricsProvider("worker-1")
    provider2 = MockWorkerMetricsProvider("worker-2")

    collector.register_provider(provider1)
    collector.register_provider(provider2)

    # Test provider collection
    assert len(collector._providers) == 2
    assert provider1 in collector._providers
    assert provider2 in collector._providers

    # Test statistics collection
    all_performance = collector.get_all_worker_performance()
    assert len(all_performance) == 2
    worker_names = [name for name, _ in all_performance]
    assert "worker-1" in worker_names
    assert "worker-2" in worker_names


def test_worker_stats_collector_type_validation():
    """Test WorkerStatsCollector type validation."""
    collector = WorkerStatsCollector()

    # Test invalid provider registration
    with pytest.raises(TypeError):
        collector.register_provider("not_a_provider")  # type: ignore[]


def test_queue_stats_collector():
    """Test QueueStatsCollector functionality."""
    collector = QueueStatsCollector()

    # Test registration
    provider1 = MockQueueMetricsProvider("queue-1")
    provider2 = MockQueueMetricsProvider("queue-2")

    collector.register_provider(provider1)
    collector.register_provider(provider2)

    # Test provider collection
    assert len(collector._providers) == 2
    assert provider1 in collector._providers
    assert provider2 in collector._providers

    # Test statistics collection
    all_stats = collector.get_all_queue_stats()
    assert len(all_stats) == 2
    queue_names = [name for name, _ in all_stats]
    assert "queue-1" in queue_names
    assert "queue-2" in queue_names


def test_queue_stats_collector_type_validation():
    """Test QueueStatsCollector type validation."""
    collector = QueueStatsCollector()

    # Test invalid provider registration
    with pytest.raises(TypeError):
        collector.register_provider("not_a_provider")  # type: ignore[]


def test_protocol_inheritance_hierarchy():
    """Test that specialized protocols inherit from base HealthMetricsProvider."""
    worker_provider = MockWorkerMetricsProvider()
    queue_provider = MockQueueMetricsProvider()
    kafka_provider = MockKafkaMetricsProvider()

    # All specialized providers should implement base protocol
    assert isinstance(worker_provider, HealthMetricsProvider)
    assert isinstance(queue_provider, HealthMetricsProvider)
    assert isinstance(kafka_provider, HealthMetricsProvider)

    # Test specialized protocol compliance
    assert isinstance(worker_provider, WorkerMetricsProvider)
    assert isinstance(queue_provider, QueueMetricsProvider)
    assert isinstance(kafka_provider, KafkaMetricsProvider)


def test_protocol_duck_typing():
    """Test that objects with correct methods pass protocol checks."""

    # Object with correct interface but no explicit protocol implementation
    class DuckTypedProvider:
        def get_health_status(self) -> bool:
            return True

        def get_service_metrics(self) -> dict[str, Any]:
            return {"metric": "value"}

        def get_last_error(self) -> str | None:
            return None

    duck_provider = DuckTypedProvider()

    # Should pass protocol check due to structural typing
    assert isinstance(duck_provider, HealthMetricsProvider)
