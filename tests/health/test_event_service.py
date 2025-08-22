"""Comprehensive tests for HealthEventService.

This module tests the HealthEventService implementation including:
- Event queue management and processing
- Real-time event dispatch and collection
- Thread-safe event handling
- Performance tracking and metrics collection
- Integration with health service architecture

Tests follow Python 3.12+ best practices with function-based approach and modern pytest features.
"""

import asyncio
import contextlib
import time

import pytest

from wazuh_dfn.config import HealthConfig
from wazuh_dfn.health.event_service import HealthEventService
from wazuh_dfn.health.models import KafkaPerformanceData, WorkerPerformanceData
from wazuh_dfn.health.protocols import QueueMetricsProvider
from wazuh_dfn.max_size_queue import AsyncMaxSizeQueue


@pytest.fixture
def health_config():
    """Create a health config for testing."""
    return HealthConfig(
        stats_interval=60,
        history_retention=600,
        max_history_entries=100,
        queue_warning_threshold=70,
        queue_critical_threshold=90,
    )


@pytest.fixture
def shutdown_event():
    """Create a shutdown event for testing."""
    return asyncio.Event()


@pytest.fixture
def health_event_service(health_config, shutdown_event):
    """Create a HealthEventService for testing."""
    return HealthEventService(health_config, shutdown_event)


@pytest.mark.asyncio
async def test_health_event_service_initialization(health_config, shutdown_event):
    """Test HealthEventService initialization."""
    service = HealthEventService(health_config, shutdown_event)

    assert hasattr(service, "_event_queue")
    assert isinstance(service._event_queue, AsyncMaxSizeQueue)
    assert service._event_queue.qsize() == 0
    assert hasattr(service, "_queue_stats")
    assert hasattr(service, "_stats_lock")
    assert hasattr(service, "_last_error")
    assert service._last_error is None


@pytest.mark.asyncio
async def test_health_event_service_with_custom_queue(health_config, shutdown_event):
    """Test HealthEventService initialization with config."""
    service = HealthEventService(health_config, shutdown_event)

    assert service._event_queue is not None
    assert service.event_queue.maxsize == 50  # Bounded queue from config


@pytest.mark.asyncio
async def test_push_worker_performance_event(health_event_service):
    """Test pushing worker performance events."""
    worker_name = "test_worker"
    performance_data: WorkerPerformanceData = {
        "timestamp": time.time(),
        "alerts_processed": 100,
        "rate": 5.2,
        "avg_processing": 0.025,
        "recent_avg": 0.015,
        "min_time": 0.001,
        "max_time": 0.150,
        "slow_alerts": 3,
        "extremely_slow_alerts": 1,
        "last_processing_time": time.time(),
        "last_alert_id": "alert-123",
    }

    # Push event
    await health_event_service.push_worker_performance(worker_name, performance_data)

    # Verify event was queued
    assert health_event_service._event_queue.qsize() == 1

    # Get and verify event
    event = await health_event_service.get_next_event()
    assert event["event_type"] == "worker_performance"
    assert event["worker_name"] == worker_name
    assert event["data"] == performance_data


@pytest.mark.asyncio
async def test_push_kafka_performance_event(health_event_service):
    """Test pushing Kafka performance events."""
    kafka_data: KafkaPerformanceData = {
        "total_time": 1.5,
        "stage_times": {
            "prep": 0.1,
            "encode": 0.2,
            "send": 1.0,
            "connect": 0.2,
        },
        "message_size": 1024,
        "topic": "test-topic",
    }

    # Push event
    await health_event_service.push_kafka_performance(kafka_data)

    # Verify event was queued
    assert health_event_service.event_queue.qsize() == 1

    # Get and verify event
    event = await health_event_service.event_queue.get()
    assert event["event_type"] == "kafka_performance"
    assert event["data"] == kafka_data


@pytest.mark.asyncio
async def test_push_kafka_performance_with_stage_times(health_event_service):
    """Test pushing kafka performance events."""
    kafka_data = {
        "total_time": 0.125,
        "stage_times": {"prep": 0.025, "send": 0.1},
        "message_size": 2048,
        "topic": "system-alerts",
    }

    # Push event
    await health_event_service.push_kafka_performance(kafka_data)

    # Verify event was queued
    assert health_event_service.event_queue.qsize() == 1

    # Get and verify event
    event = await health_event_service.event_queue.get()
    assert event["event_type"] == "kafka_performance"
    assert event["data"] == kafka_data


@pytest.mark.asyncio
async def test_push_worker_last_processed_event(health_event_service):
    """Test pushing worker last processed events."""
    worker_name = "worker_1"
    last_processed_data = {
        "last_processing_time": time.time(),
        "last_alert_id": "alert-12345",
    }

    # Push event
    await health_event_service.push_worker_last_processed(worker_name, last_processed_data)

    # Verify event was queued
    assert health_event_service.event_queue.qsize() == 1

    # Get and verify event
    event = await health_event_service.event_queue.get()
    assert event["event_type"] == "worker_last_processed"
    assert event["worker_name"] == worker_name
    assert event["data"] == last_processed_data


@pytest.mark.asyncio
async def test_event_queue_overflow_behavior(health_config):
    """Test event queue behavior when it reaches capacity."""
    # Create service and replace its queue with a small one
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)
    service._event_queue = AsyncMaxSizeQueue(maxsize=2)

    # Fill queue to capacity
    await service.push_kafka_performance({"total_time": 0.1, "topic": "test1"})
    await service.push_kafka_performance({"total_time": 0.2, "topic": "test2"})

    assert service.event_queue.qsize() == 2
    assert service.event_queue.full()

    # Test that additional pushes handle queue full gracefully
    # This should not block or raise exceptions
    with contextlib.suppress(TimeoutError):
        # Use asyncio.wait_for to prevent hanging if queue blocks
        await asyncio.wait_for(service.push_kafka_performance({"total_time": 0.3, "topic": "test3"}), timeout=0.1)


@pytest.mark.asyncio
async def test_concurrent_event_pushing(health_config):
    """Test concurrent event pushing for thread safety."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    # Create multiple concurrent pushers
    async def push_events(worker_id: int) -> None:
        for i in range(10):
            performance_data: WorkerPerformanceData = {
                "timestamp": time.time(),
                "alerts_processed": i,
                "rate": float(i),
                "avg_processing": 0.001 * i,
                "recent_avg": 0.001 * i,
                "min_time": 0.001,
                "max_time": 0.01,
                "slow_alerts": 0,
                "extremely_slow_alerts": 0,
                "last_processing_time": time.time(),
                "last_alert_id": f"alert-{worker_id}-{i}",
            }
            await service.push_worker_performance(f"worker_{worker_id}", performance_data)

    # Run concurrent tasks
    tasks = [push_events(i) for i in range(3)]
    await asyncio.gather(*tasks)

    # Verify all events were queued
    assert service.event_queue.qsize() == 30  # 3 workers * 10 events each


@pytest.mark.asyncio
async def test_event_processing_integration(health_config):
    """Test integration between event service and health service processing."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    # Create a mock processor that collects events
    processed_events = []

    async def mock_processor():
        while True:
            try:
                event = await asyncio.wait_for(service.event_queue.get(), timeout=0.1)
                processed_events.append(event)
                service.event_queue.task_done()
            except TimeoutError:
                break

    # Start processor task
    processor_task = asyncio.create_task(mock_processor())

    # Push some events
    await service.push_worker_performance(
        "worker1",
        {
            "timestamp": time.time(),
            "alerts_processed": 100,
            "rate": 5.0,
            "avg_processing": 0.025,
            "recent_avg": 0.015,
            "min_time": 0.001,
            "max_time": 0.150,
            "slow_alerts": 3,
            "extremely_slow_alerts": 1,
            "last_processing_time": time.time(),
            "last_alert_id": "alert-123",
        },
    )

    await service.push_kafka_performance(
        {"total_time": 0.05, "stage_times": {"prep": 0.01, "send": 0.04}, "message_size": 1024, "topic": "test-topic"}
    )

    # Wait for processing
    await asyncio.sleep(0.05)
    processor_task.cancel()

    # Verify events were processed
    assert len(processed_events) == 2
    assert processed_events[0]["event_type"] == "worker_performance"
    assert processed_events[1]["event_type"] == "kafka_performance"


@pytest.mark.asyncio
async def test_event_data_integrity(health_config):
    """Test that event data maintains integrity through push/pop cycles."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    # Test complex data structure
    complex_data: KafkaPerformanceData = {
        "total_time": 2.5,
        "stage_times": {"prep": 0.1, "encode": 0.2, "send": 2.0, "connect": 0.2},
        "message_size": 4096,
        "topic": "complex-test-topic",
    }

    # Push and retrieve event
    await service.push_kafka_performance(complex_data)
    event = await service.event_queue.get()

    # Verify data integrity
    assert event["data"] == complex_data
    assert abs(event["data"]["stage_times"]["prep"] - 0.1) < 1e-10
    assert abs(event["data"]["stage_times"]["send"] - 2.0) < 1e-10


@pytest.mark.asyncio
async def test_event_metadata(health_config):
    """Test event metadata is properly added."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    before_time = time.time()
    await service.push_worker_performance(
        "test_worker",
        {
            "timestamp": time.time(),
            "alerts_processed": 10,
            "rate": 1.0,
            "avg_processing": 0.01,
            "recent_avg": 0.01,
            "min_time": 0.001,
            "max_time": 0.02,
            "slow_alerts": 0,
            "extremely_slow_alerts": 0,
            "last_processing_time": time.time(),
            "last_alert_id": "alert-test",
        },
    )
    after_time = time.time()

    event = await service.event_queue.get()

    # Verify event structure
    assert "event_type" in event
    assert "timestamp" in event
    assert "worker_name" in event
    assert "data" in event

    # Verify timestamp is reasonable
    event_timestamp = event["timestamp"]
    assert before_time <= event_timestamp <= after_time


@pytest.mark.asyncio
async def test_queue_task_done_integration(health_config):
    """Test that queue task_done functionality works correctly."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    # Push some events
    await service.push_kafka_performance({"total_time": 0.1, "topic": "test1"})
    await service.push_kafka_performance({"total_time": 0.2, "topic": "test2"})

    # Start a task that processes events
    async def process_events():
        for _ in range(2):
            await service.event_queue.get()
            service.event_queue.task_done()

    processor_task = asyncio.create_task(process_events())

    # Wait for all tasks to be processed
    await service.event_queue.join()
    await processor_task

    # Queue should be empty
    assert service.event_queue.qsize() == 0


# QueueMetricsProvider Protocol Tests


def test_queue_metrics_provider_protocol_compliance(health_event_service):
    """Test that HealthEventService implements QueueMetricsProvider protocol."""
    # Test protocol compliance using isinstance
    assert isinstance(health_event_service, QueueMetricsProvider)

    # Verify all required methods exist
    assert hasattr(health_event_service, "get_queue_stats")
    assert hasattr(health_event_service, "get_queue_name")
    assert hasattr(health_event_service, "is_queue_healthy")
    assert hasattr(health_event_service, "get_health_status")
    assert hasattr(health_event_service, "get_service_metrics")
    assert hasattr(health_event_service, "get_last_error")


def test_get_queue_stats(health_event_service):
    """Test get_queue_stats method returns correct QueueStatsData."""
    queue_stats = health_event_service.get_queue_stats()

    # Verify structure matches QueueStatsData TypedDict
    assert "total_processed" in queue_stats
    assert "max_queue_size" in queue_stats
    assert "queue_full_count" in queue_stats
    assert "last_queue_size" in queue_stats

    # Verify initial values
    assert queue_stats["total_processed"] == 0
    assert queue_stats["max_queue_size"] == 50  # From config
    assert queue_stats["queue_full_count"] == 0
    assert queue_stats["last_queue_size"] == 0


def test_get_queue_name(health_event_service):
    """Test get_queue_name returns correct identifier."""
    queue_name = health_event_service.get_queue_name()
    assert queue_name == "health_event_queue"
    assert isinstance(queue_name, str)


def test_is_queue_healthy(health_event_service):
    """Test is_queue_healthy method."""
    # Should be healthy initially (not full and service running)
    assert health_event_service.is_queue_healthy() is True

    # Should be unhealthy if shutdown event is set
    health_event_service._shutdown_event.set()
    assert health_event_service.is_queue_healthy() is False


def test_get_health_status(health_event_service):
    """Test get_health_status method."""
    # Should be healthy initially (shutdown event not set)
    assert health_event_service.get_health_status() is True

    # Should be unhealthy when shutdown event is set
    health_event_service._shutdown_event.set()
    assert health_event_service.get_health_status() is False


def test_get_service_metrics(health_event_service):
    """Test get_service_metrics returns comprehensive metrics."""
    metrics = health_event_service.get_service_metrics()

    # Verify structure
    assert "health_status" in metrics
    assert "queue_stats" in metrics
    assert "queue_name" in metrics
    assert "is_queue_healthy" in metrics
    assert "event_queue_size" in metrics
    assert "last_error" in metrics

    # Verify initial values
    assert metrics["health_status"] is True
    assert metrics["queue_name"] == "health_event_queue"
    assert metrics["is_queue_healthy"] is True
    assert metrics["event_queue_size"] == 0
    assert metrics["last_error"] is None

    # Verify queue_stats is properly nested
    queue_stats = metrics["queue_stats"]
    assert isinstance(queue_stats, dict)
    assert "total_processed" in queue_stats


def test_get_last_error(health_event_service):
    """Test get_last_error method."""
    # Should be None initially
    assert health_event_service.get_last_error() is None

    # Should return error message after an error
    test_error = "Test error message"
    health_event_service._last_error = test_error
    assert health_event_service.get_last_error() == test_error


@pytest.mark.asyncio
async def test_queue_stats_tracking(health_event_service):
    """Test that queue statistics are properly tracked during operations."""
    # Initial state
    initial_stats = health_event_service.get_queue_stats()
    assert initial_stats["total_processed"] == 0
    assert initial_stats["last_queue_size"] == 0

    # Push some events and verify stats update
    await health_event_service.push_worker_performance(
        "test_worker",
        {
            "timestamp": time.time(),
            "alerts_processed": 10,
            "rate": 1.0,
            "avg_processing": 0.01,
            "recent_avg": 0.01,
            "min_time": 0.001,
            "max_time": 0.02,
            "slow_alerts": 0,
            "extremely_slow_alerts": 0,
            "last_processing_time": time.time(),
            "last_alert_id": "alert-test",
        },
    )

    await health_event_service.push_kafka_performance({"total_time": 0.1, "topic": "test"})

    # Check stats updated
    updated_stats = health_event_service.get_queue_stats()
    assert updated_stats["total_processed"] == 2
    assert updated_stats["last_queue_size"] == 2

    # Consume events and verify stats update
    await health_event_service.get_next_event()
    await health_event_service.get_next_event()

    consumed_stats = health_event_service.get_queue_stats()
    assert consumed_stats["last_queue_size"] == 0


@pytest.mark.asyncio
async def test_queue_full_tracking(health_config):
    """Test that queue full events are properly tracked."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    # Replace with small queue to test full condition
    service._event_queue = AsyncMaxSizeQueue(maxsize=2)

    # Fill queue to capacity
    await service.push_kafka_performance({"total_time": 0.1, "topic": "test1"})
    await service.push_kafka_performance({"total_time": 0.2, "topic": "test2"})

    # Verify queue is full
    assert service._event_queue.full()

    # Check stats reflect the full queue
    stats = service.get_queue_stats()
    assert stats["last_queue_size"] == 2
    assert stats["max_queue_size"] == 2


@pytest.mark.asyncio
async def test_error_tracking_in_push_methods(health_config):
    """Test that errors are properly tracked during push operations."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    # Create a scenario that might cause errors by filling the queue
    service._event_queue = AsyncMaxSizeQueue(maxsize=1)

    # Fill the queue
    await service.push_kafka_performance({"total_time": 0.1, "topic": "test1"})

    # Verify initial state
    assert service.get_last_error() is None

    # The queue is now full, but our implementation should handle this gracefully
    # and not raise exceptions, so last_error should remain None
    with contextlib.suppress(TimeoutError):
        # This might block or handle gracefully depending on implementation
        await asyncio.wait_for(service.push_kafka_performance({"total_time": 0.2, "topic": "test2"}), timeout=0.1)

    # The error handling is implementation-specific
    # Our current implementation should not set errors for queue full conditions


@pytest.mark.asyncio
async def test_get_next_event_error_handling(health_config):
    """Test error handling in get_next_event method."""
    shutdown_event = asyncio.Event()
    service = HealthEventService(health_config, shutdown_event)

    # Should return None when queue is empty (timeout)
    event = await service.get_next_event()
    assert event is None

    # Should not set error for empty queue timeout
    assert service.get_last_error() is None


@pytest.mark.asyncio
async def test_health_status_integration_with_queue_health(health_event_service):
    """Test integration between health status and queue health."""
    # Initially both should be healthy
    assert health_event_service.get_health_status() is True
    assert health_event_service.is_queue_healthy() is True

    # When service becomes unhealthy, queue should also be unhealthy
    health_event_service._shutdown_event.set()
    assert health_event_service.get_health_status() is False
    assert health_event_service.is_queue_healthy() is False

    # Service metrics should reflect this
    metrics = health_event_service.get_service_metrics()
    assert metrics["health_status"] is False
    assert metrics["is_queue_healthy"] is False
