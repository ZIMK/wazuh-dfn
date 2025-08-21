"""Tests for wazuh_dfn.service_container module."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from wazuh_dfn.health.protocols import (
    HealthMetricsProvider,
    KafkaMetricsProvider,
    QueueMetricsProvider,
    WorkerMetricsProvider,
)
from wazuh_dfn.service_container import ServiceContainer


@pytest.fixture
def container():
    """Create a ServiceContainer instance for testing."""
    return ServiceContainer()


@pytest.fixture
def mock_service():
    """Create a mock service for testing."""
    service = MagicMock()
    service.start = AsyncMock()
    service.stop = AsyncMock()
    return service


@pytest.fixture
def mock_worker_provider():
    """Create a mock worker metrics provider."""
    provider = MagicMock(spec=WorkerMetricsProvider)
    provider.get_health_status = MagicMock(return_value={"status": "healthy"})
    return provider


@pytest.fixture
def mock_queue_provider():
    """Create a mock queue metrics provider."""
    provider = MagicMock(spec=QueueMetricsProvider)
    provider.get_health_status = MagicMock(return_value={"status": "healthy"})
    return provider


@pytest.fixture
def mock_kafka_provider():
    """Create a mock Kafka metrics provider."""
    provider = MagicMock(spec=KafkaMetricsProvider)
    provider.get_health_status = MagicMock(return_value={"status": "healthy"})
    return provider


@pytest.fixture
def mock_health_provider():
    """Create a mock health metrics provider."""
    provider = MagicMock(spec=HealthMetricsProvider)
    provider.get_health_status = MagicMock(return_value={"status": "healthy"})
    return provider


def test_container_initialization(container):
    """Test ServiceContainer initialization."""
    assert container._services == {}
    assert container._service_factories == {}
    assert container._worker_providers == {}
    assert container._queue_providers == {}
    assert container._kafka_providers == {}
    assert container._health_providers == {}


def test_register_service(container, mock_service):
    """Test service registration."""
    container.register_service("test_service", mock_service)
    assert "test_service" in container._services
    assert container._services["test_service"] is mock_service


def test_register_service_factory(container, mock_service):
    """Test service factory registration."""

    def factory():
        return mock_service

    container.register_service_factory("test_service", factory)
    assert "test_service" in container._service_factories
    assert container._service_factories["test_service"] is factory


def test_get_service_direct(container, mock_service):
    """Test getting a directly registered service."""
    container.register_service("test_service", mock_service)
    result = container.get_service("test_service")
    assert result is mock_service


def test_get_service_with_type_check(container, mock_service):
    """Test getting service with type checking."""
    container.register_service("test_service", mock_service)
    result = container.get_service("test_service", MagicMock)
    assert result is mock_service


def test_get_service_wrong_type(container):
    """Test getting service with wrong type returns None."""
    container.register_service("test_service", "not_a_mock")
    result = container.get_service("test_service", MagicMock)
    assert result is None


def test_get_service_from_factory(container, mock_service):
    """Test getting service from factory."""

    def factory():
        return mock_service

    container.register_service_factory("test_service", factory)
    result = container.get_service("test_service")
    assert result is mock_service
    # Service should be cached after creation
    assert "test_service" in container._services


def test_get_service_factory_error(container):
    """Test factory error handling."""

    def failing_factory():
        raise RuntimeError("Factory failed")

    container.register_service_factory("test_service", failing_factory)
    result = container.get_service("test_service")
    assert result is None


def test_get_service_not_found(container):
    """Test getting non-existent service returns None."""
    result = container.get_service("nonexistent")
    assert result is None


def test_register_worker_provider(container, mock_worker_provider):
    """Test worker provider registration."""
    container.register_worker_provider("test_worker", mock_worker_provider)
    assert "test_worker" in container._worker_providers
    assert container._worker_providers["test_worker"] is mock_worker_provider


def test_register_queue_provider(container, mock_queue_provider):
    """Test queue provider registration."""
    container.register_queue_provider("test_queue", mock_queue_provider)
    assert "test_queue" in container._queue_providers
    assert container._queue_providers["test_queue"] is mock_queue_provider


def test_register_kafka_provider(container, mock_kafka_provider):
    """Test Kafka provider registration."""
    container.register_kafka_provider("test_kafka", mock_kafka_provider)
    assert "test_kafka" in container._kafka_providers
    assert container._kafka_providers["test_kafka"] is mock_kafka_provider


def test_register_health_provider(container, mock_health_provider):
    """Test health provider registration."""
    container.register_health_provider("test_health", mock_health_provider)
    assert "test_health" in container._health_providers
    assert container._health_providers["test_health"] is mock_health_provider


def test_get_worker_providers(container, mock_worker_provider):
    """Test getting worker providers."""
    container.register_worker_provider("test_worker", mock_worker_provider)
    providers = container.get_worker_providers()
    assert "test_worker" in providers
    assert providers["test_worker"] is mock_worker_provider
    # Should return a copy, not the original dict
    assert providers is not container._worker_providers


def test_get_queue_providers(container, mock_queue_provider):
    """Test getting queue providers."""
    container.register_queue_provider("test_queue", mock_queue_provider)
    providers = container.get_queue_providers()
    assert "test_queue" in providers
    assert providers["test_queue"] is mock_queue_provider
    assert providers is not container._queue_providers


def test_get_kafka_providers(container, mock_kafka_provider):
    """Test getting Kafka providers."""
    container.register_kafka_provider("test_kafka", mock_kafka_provider)
    providers = container.get_kafka_providers()
    assert "test_kafka" in providers
    assert providers["test_kafka"] is mock_kafka_provider
    assert providers is not container._kafka_providers


def test_get_health_providers(container, mock_health_provider):
    """Test getting health providers."""
    container.register_health_provider("test_health", mock_health_provider)
    providers = container.get_health_providers()
    assert "test_health" in providers
    assert providers["test_health"] is mock_health_provider
    assert providers is not container._health_providers


def test_get_all_providers(
    container, mock_worker_provider, mock_queue_provider, mock_kafka_provider, mock_health_provider
):
    """Test getting all providers combined."""
    # Make providers implement HealthMetricsProvider
    for provider in [mock_worker_provider, mock_queue_provider, mock_kafka_provider]:
        provider.__class__ = type(provider.__class__.__name__, (provider.__class__, HealthMetricsProvider), {})

    container.register_worker_provider("worker1", mock_worker_provider)
    container.register_queue_provider("queue1", mock_queue_provider)
    container.register_kafka_provider("kafka1", mock_kafka_provider)
    container.register_health_provider("health1", mock_health_provider)

    all_providers = container.get_all_providers()

    assert "worker_worker1" in all_providers
    assert "queue_queue1" in all_providers
    assert "kafka_kafka1" in all_providers
    assert "health1" in all_providers


def test_list_services(container, mock_service):
    """Test listing all services."""

    def factory():
        return mock_service

    container.register_service("service1", mock_service)
    container.register_service_factory("service2", factory)

    services = container.list_services()
    assert "service1" in services
    assert "service2" in services
    assert services == sorted(services)  # Should be sorted


def test_clear(container, mock_service, mock_worker_provider):
    """Test clearing the container."""
    container.register_service("test_service", mock_service)
    container.register_worker_provider("test_worker", mock_worker_provider)

    container.clear()

    assert container._services == {}
    assert container._service_factories == {}
    assert container._worker_providers == {}
    assert container._queue_providers == {}
    assert container._kafka_providers == {}
    assert container._health_providers == {}


@pytest.mark.asyncio
async def test_start_all_services(container):
    """Test starting all services in proper order."""
    # Create mock services
    health_event_service = MagicMock()
    health_event_service.start = AsyncMock()

    health_service = MagicMock()
    health_service.start = AsyncMock()

    other_service = MagicMock()
    other_service.start = AsyncMock()

    # Register services
    container.register_service("health_event", health_event_service)
    container.register_service("health", health_service)
    container.register_service("other", other_service)

    await container.start_all_services()

    # Verify all services were started
    health_event_service.start.assert_called_once()
    health_service.start.assert_called_once()
    other_service.start.assert_called_once()


@pytest.mark.asyncio
async def test_start_all_services_with_error(container):
    """Test start_all_services handles errors properly."""
    failing_service = MagicMock()
    failing_service.start = AsyncMock(side_effect=RuntimeError("Start failed"))

    container.register_service("failing", failing_service)

    with pytest.raises(RuntimeError, match="Start failed"):
        await container.start_all_services()


@pytest.mark.asyncio
async def test_stop_all_services(container):
    """Test stopping all services."""
    service1 = MagicMock()
    service1.stop = AsyncMock()

    service2 = MagicMock()
    service2.stop = AsyncMock()

    container.register_service("service1", service1)
    container.register_service("service2", service2)

    await container.stop_all_services()

    service1.stop.assert_called_once()
    service2.stop.assert_called_once()


@pytest.mark.asyncio
async def test_stop_all_services_continues_on_error(container):
    """Test stop_all_services continues even when a service fails to stop."""
    failing_service = MagicMock()
    failing_service.stop = AsyncMock(side_effect=RuntimeError("Stop failed"))

    working_service = MagicMock()
    working_service.stop = AsyncMock()

    container.register_service("failing", failing_service)
    container.register_service("working", working_service)

    # Should not raise exception
    await container.stop_all_services()

    failing_service.stop.assert_called_once()
    working_service.stop.assert_called_once()


@pytest.mark.asyncio
async def test_services_without_start_stop_methods(container):
    """Test that services without start/stop methods are handled gracefully."""

    # Create a simple object without start/stop methods (not a MagicMock)
    class SimpleService:
        pass

    simple_service = SimpleService()

    container.register_service("simple", simple_service)

    # Should not raise exceptions
    await container.start_all_services()
    await container.stop_all_services()
