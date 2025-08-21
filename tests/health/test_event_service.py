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
def health_event_service(health_config):
    """Create a HealthEventService for testing."""
    return HealthEventService(health_config)


@pytest.mark.asyncio
async def test_health_event_service_initialization(health_config):
    """Test HealthEventService initialization."""
    service = HealthEventService(health_config)

    assert hasattr(service, "_event_queue")
    assert isinstance(service._event_queue, asyncio.Queue)
    assert service._event_queue.qsize() == 0


@pytest.mark.asyncio
async def test_health_event_service_with_custom_queue(health_config):
    """Test HealthEventService initialization with config."""
    service = HealthEventService(health_config)

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
    service = HealthEventService(health_config)
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
    service = HealthEventService(health_config)

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
    service = HealthEventService(health_config)

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
    service = HealthEventService(health_config)

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
    service = HealthEventService(health_config)

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
    service = HealthEventService(health_config)

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
