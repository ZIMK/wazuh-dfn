"""Comprehensive tests for health monitoring models and data structures.

This module tests the health models implementation including:
- TypedDict data structures for events and real-time data
- Pydantic models for comprehensive health status
- Status enums and classification logic
- Data validation and computed fields
- Health threshold configuration

Tests follow Python 3.12+ best practices with function-based approach and modern pytest features.
"""

import time
from datetime import datetime

import pytest
from pydantic import ValidationError

from wazuh_dfn.health.models import (
    FileMonitorStatsData,
    HealthMetrics,
    HealthStatus,
    HealthThresholds,
    KafkaInternalStatsData,
    KafkaPerformanceData,
    QueueHealth,
    QueueStatsData,
    ServiceHealth,
    ServiceStatus,
    SystemHealth,
    WorkerHealth,
    WorkerLastProcessedData,
    WorkerPerformanceData,
    WorkerStatus,
    determine_overall_status,
    determine_queue_status,
    determine_service_status,
    determine_system_status,
    determine_worker_status,
)


def test_worker_performance_data_structure():
    """Test WorkerPerformanceData TypedDict structure."""
    timestamp = time.time()
    data: WorkerPerformanceData = {
        "timestamp": timestamp,
        "alerts_processed": 100,
        "rate": 5.2,
        "avg_processing": 0.025,
        "recent_avg": 0.015,
        "min_time": 0.001,
        "max_time": 0.150,
        "slow_alerts": 3,
        "extremely_slow_alerts": 1,
        "last_processing_time": timestamp,
        "last_alert_id": "alert-123",
    }

    # Verify all required fields are present and accessible
    assert data["timestamp"] == timestamp
    assert data["alerts_processed"] == 100
    assert data["rate"] == 5.2
    assert data["slow_alerts"] == 3
    assert data["extremely_slow_alerts"] == 1
    assert data["last_alert_id"] == "alert-123"


def test_worker_last_processed_data_structure():
    """Test WorkerLastProcessedData TypedDict structure."""
    timestamp = time.time()
    data: WorkerLastProcessedData = {
        "last_processing_time": timestamp,
        "last_alert_id": "alert-456",
    }

    assert data["last_processing_time"] == timestamp
    assert data["last_alert_id"] == "alert-456"


def test_queue_stats_data_structure():
    """Test QueueStatsData TypedDict structure."""
    data: QueueStatsData = {
        "total_processed": 1000,
        "max_queue_size": 50,
        "queue_full_count": 5,
        "last_queue_size": 10,
    }

    assert data["total_processed"] == 1000
    assert data["max_queue_size"] == 50
    assert data["queue_full_count"] == 5
    assert data["last_queue_size"] == 10


def test_kafka_performance_data_structure():
    """Test KafkaPerformanceData TypedDict structure."""
    # Test minimal required data
    minimal_data: KafkaPerformanceData = {
        "total_time": 1.5,
    }
    assert minimal_data["total_time"] == 1.5

    # Test complete data structure
    complete_data: KafkaPerformanceData = {
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

    assert complete_data["total_time"] == 1.5
    assert complete_data["stage_times"]["send"] == 1.0
    assert complete_data["message_size"] == 1024
    assert complete_data["topic"] == "test-topic"


def test_kafka_internal_stats_data_structure():
    """Test KafkaInternalStatsData TypedDict structure."""
    data: KafkaInternalStatsData = {
        "slow_operations": 5,
        "total_operations": 100,
        "last_slow_operation_time": time.time(),
        "max_operation_time": 2.5,
        "recent_stage_times": [
            {"prep": 0.1, "encode": 0.2, "send": 1.0, "connect": 0.2},
            {"prep": 0.15, "encode": 0.25, "send": 1.2, "connect": 0.18},
            {"prep": 0.12, "encode": 0.22, "send": 0.9, "connect": 0.25},
            {"prep": 0.13, "encode": 0.19, "send": 1.1, "connect": 0.21},
        ],
    }

    assert data["slow_operations"] == 5
    assert data["total_operations"] == 100
    assert isinstance(data["last_slow_operation_time"], (int, float))
    assert data["max_operation_time"] == 2.5
    assert len(data["recent_stage_times"]) == 4


def test_file_monitor_stats_data_structure():
    """Test FileMonitorStatsData TypedDict structure."""
    data: FileMonitorStatsData = {
        "alerts_per_second": 2.5,
        "error_rate": 0.02,
        "total_alerts": 1000,
        "error_count": 20,
        "replaced_count": 5,
    }

    assert data["alerts_per_second"] == 2.5
    assert data["error_rate"] == 0.02
    assert data["total_alerts"] == 1000
    assert data["error_count"] == 20
    assert data["replaced_count"] == 5


def test_status_enums():
    """Test status enum values and string conversion."""
    # Test HealthStatus
    assert HealthStatus.HEALTHY == "HEALTHY"
    assert HealthStatus.DEGRADED == "DEGRADED"
    assert HealthStatus.CRITICAL == "CRITICAL"
    assert HealthStatus.ERROR == "ERROR"

    # Test WorkerStatus
    assert WorkerStatus.ACTIVE == "ACTIVE"
    assert WorkerStatus.STALLED == "STALLED"
    assert WorkerStatus.IDLE == "IDLE"

    # Test ServiceStatus (consolidated from KafkaStatus and MonitorStatus)
    assert ServiceStatus.HEALTHY == "HEALTHY"
    assert ServiceStatus.SLOW == "SLOW"
    assert ServiceStatus.DISCONNECTED == "DISCONNECTED"
    assert ServiceStatus.ERROR == "ERROR"


def test_health_thresholds_model():
    """Test HealthThresholds Pydantic model."""
    # Test with default values
    thresholds = HealthThresholds()

    assert thresholds.queue_warning_percentage == 70.0
    assert thresholds.queue_critical_percentage == 90.0
    assert thresholds.system_cpu_warning_percentage == 80.0
    assert thresholds.system_cpu_critical_percentage == 95.0
    assert thresholds.system_memory_warning_percentage == 85.0
    assert thresholds.system_memory_critical_percentage == 95.0

    # Test with custom values
    custom_thresholds = HealthThresholds(
        queue_warning_percentage=60.0,
        queue_critical_percentage=85.0,
        system_cpu_warning_percentage=75.0,
        system_cpu_critical_percentage=90.0,
    )

    assert custom_thresholds.queue_warning_percentage == 60.0
    assert custom_thresholds.queue_critical_percentage == 85.0
    assert custom_thresholds.system_cpu_warning_percentage == 75.0
    assert custom_thresholds.system_cpu_critical_percentage == 90.0


def test_health_thresholds_validation():
    """Test HealthThresholds validation logic."""
    # Test invalid values
    with pytest.raises(ValidationError):
        HealthThresholds(queue_warning_percentage=110.0)  # > 100

    with pytest.raises(ValidationError):
        HealthThresholds(queue_critical_percentage=-1.0)  # < 0

    with pytest.raises(ValidationError):
        HealthThresholds(system_cpu_warning_percentage=-1.0)  # < 0


def test_worker_health_model():
    """Test WorkerHealth Pydantic model."""
    worker_health = WorkerHealth(
        worker_name="test_worker",
        status=WorkerStatus.ACTIVE,
        alerts_processed=100,
        processing_rate=5.2,
        avg_processing_time=0.025,
        recent_avg_processing_time=0.015,
        min_processing_time=0.001,
        max_processing_time=0.150,
        slow_alerts_count=3,
        extremely_slow_alerts_count=1,
        last_processing_time=0.025,  # Use float, not datetime
        last_alert_id="alert-123",
        health_score=0.85,
    )

    assert worker_health.worker_name == "test_worker"
    assert worker_health.status == WorkerStatus.ACTIVE
    assert worker_health.alerts_processed == 100
    assert worker_health.processing_rate == 5.2
    assert worker_health.slow_alerts_count == 3
    assert worker_health.extremely_slow_alerts_count == 1
    assert worker_health.last_alert_id == "alert-123"


def test_queue_health_model():
    """Test QueueHealth Pydantic model."""
    queue_health = QueueHealth(
        queue_name="alert_queue",
        current_size=10,
        max_size=100,
        utilization_percentage=10.0,
        total_processed=1000,
        processing_rate=2.5,
        queue_full_events=5,
        avg_wait_time=0.25,
        status=HealthStatus.HEALTHY,
    )

    assert queue_health.queue_name == "alert_queue"
    assert queue_health.current_size == 10
    assert queue_health.max_size == 100
    assert queue_health.total_processed == 1000
    assert queue_health.queue_full_events == 5
    assert queue_health.status == HealthStatus.HEALTHY

    # Test computed field
    assert queue_health.utilization_percentage == 10.0


def test_system_health_model():
    """Test SystemHealth Pydantic model."""
    system_health = SystemHealth(
        process_id=12345,
        process_name="wazuh_dfn",
        status=HealthStatus.HEALTHY,
        cpu_percent=45.5,
        memory_percent=67.2,
        memory_usage_mb=512.0,
        open_files_count=125,
        max_open_files=1024,
        uptime_seconds=3600.0,
        threads_count=8,
    )

    assert system_health.status == HealthStatus.HEALTHY
    assert abs(system_health.cpu_percent - 45.5) < 0.01
    assert abs(system_health.memory_percent - 67.2) < 0.01
    assert system_health.open_files_count == 125
    assert system_health.max_open_files == 1024


def test_service_health_model():
    """Test ServiceHealth Pydantic model."""
    service_health = ServiceHealth(
        service_name="kafka_service",
        service_type="kafka",
        is_connected=True,
        connection_latency=0.05,
        total_operations=1000,
        successful_operations=990,
        failed_operations=10,
        avg_response_time=0.025,
        max_response_time=0.15,
        slow_operations_count=5,
        error_rate=1.0,
        status=HealthStatus.HEALTHY,
    )

    assert service_health.service_name == "kafka_service"
    assert service_health.service_type == "kafka"
    assert service_health.status == HealthStatus.HEALTHY
    assert service_health.is_connected
    assert service_health.error_rate == 1.0


def test_health_metrics_model():
    """Test HealthMetrics comprehensive model."""
    worker_health = WorkerHealth(
        worker_name="test_worker",
        status=WorkerStatus.ACTIVE,
        alerts_processed=100,
        processing_rate=5.2,
        avg_processing_time=0.025,
        recent_avg_processing_time=0.015,
        min_processing_time=0.010,
        max_processing_time=0.150,
        slow_alerts_count=3,
        extremely_slow_alerts_count=1,
        last_processing_time=0.035,
        last_alert_id="alert-123",
        health_score=0.85,
    )

    queue_health = QueueHealth(
        queue_name="alert_queue",
        current_size=10,
        max_size=100,
        utilization_percentage=10.0,
        total_processed=1000,
        processing_rate=5.5,
        queue_full_events=5,
        avg_wait_time=0.025,
        status=HealthStatus.HEALTHY,
    )

    system_health = SystemHealth(
        status=HealthStatus.HEALTHY,
        process_id=1234,
        process_name="wazuh_dfn",
        cpu_percent=45.5,
        memory_percent=67.2,
        memory_usage_mb=256.0,
        open_files_count=125,
        max_open_files=1024,
        uptime_seconds=3600.0,
        threads_count=8,
    )

    health_metrics = HealthMetrics(
        overall_status=HealthStatus.HEALTHY,
        health_score=85.5,
        timestamp=datetime.now(),
        system=system_health,
        workers={"test_worker": worker_health},
        queues={"alert_queue": queue_health},
        services={},
    )

    assert health_metrics.overall_status == HealthStatus.HEALTHY
    assert isinstance(health_metrics.timestamp, datetime)
    assert health_metrics.system == system_health
    assert len(health_metrics.workers) == 1
    assert health_metrics.workers["test_worker"] == worker_health
    assert len(health_metrics.queues) == 1
    assert health_metrics.queues["alert_queue"] == queue_health


def test_determine_worker_status_function():
    """Test worker status determination function."""
    thresholds = HealthThresholds()
    current_time = time.time()

    # Test ACTIVE status
    worker_health = WorkerHealth(
        worker_name="test_worker",
        alerts_processed=100,
        processing_rate=2.0,
        avg_processing_time=0.5,
        recent_avg_processing_time=0.4,
        min_processing_time=0.1,
        max_processing_time=1.0,
        slow_alerts_count=5,
        extremely_slow_alerts_count=1,
        last_processing_time=0.3,
        last_alert_id="alert-123",
        health_score=0.9,
    )
    status = determine_worker_status(worker_health, thresholds, current_time - 5.0)
    assert status == WorkerStatus.ACTIVE

    # Test STALLED status (no recent activity)
    status = determine_worker_status(worker_health, thresholds, current_time - 300.0)
    assert status == WorkerStatus.STALLED

    # Test IDLE status (zero processing rate)
    idle_worker = WorkerHealth(
        worker_name="idle_worker",
        alerts_processed=0,
        processing_rate=0.0,
        avg_processing_time=0.0,
        recent_avg_processing_time=0.0,
        min_processing_time=0.0,
        max_processing_time=0.0,
        slow_alerts_count=0,
        extremely_slow_alerts_count=0,
        last_processing_time=0.0,
        last_alert_id="",
        health_score=0.5,
    )
    status = determine_worker_status(idle_worker, thresholds, current_time - 30.0)
    assert status == WorkerStatus.IDLE


def test_determine_queue_status_function():
    """Test queue status determination function."""
    thresholds = HealthThresholds()

    # Test HEALTHY status
    queue_health = QueueHealth(
        queue_name="test_queue",
        current_size=50,
        max_size=100,
        utilization_percentage=50.0,
        total_processed=1000,
        processing_rate=5.0,
        queue_full_events=0,
        avg_wait_time=0.01,
    )
    status = determine_queue_status(queue_health, thresholds)
    assert status == HealthStatus.HEALTHY

    # Test DEGRADED status (warning threshold)
    queue_health_degraded = QueueHealth(
        queue_name="test_queue",
        current_size=75,
        max_size=100,
        utilization_percentage=75.0,  # Above warning threshold (70%)
        total_processed=1000,
        processing_rate=5.0,
        queue_full_events=0,
        avg_wait_time=0.01,
    )
    status = determine_queue_status(queue_health_degraded, thresholds)
    assert status == HealthStatus.DEGRADED

    # Test CRITICAL status
    queue_health_critical = QueueHealth(
        queue_name="test_queue",
        current_size=95,
        max_size=100,
        utilization_percentage=95.0,  # Above critical threshold (90%)
        total_processed=1000,
        processing_rate=5.0,
        queue_full_events=0,
        avg_wait_time=0.01,
    )
    status = determine_queue_status(queue_health_critical, thresholds)
    assert status == HealthStatus.CRITICAL


def test_determine_system_status_function():
    """Test system status determination function."""
    thresholds = HealthThresholds()  # Use default thresholds

    # Test HEALTHY status
    system_health = SystemHealth(
        process_id=1234,
        process_name="test_process",
        cpu_percent=50.0,
        memory_percent=60.0,
        memory_usage_mb=512.0,
        open_files_count=100,
        max_open_files=1024,
        uptime_seconds=3600.0,
        threads_count=4,
    )
    status = determine_system_status(system_health, thresholds)
    assert status == HealthStatus.HEALTHY

    # Test DEGRADED status (CPU warning: default 80%)
    system_health_degraded = SystemHealth(
        process_id=1234,
        process_name="test_process",
        cpu_percent=85.0,  # Above warning threshold (80%)
        memory_percent=60.0,
        memory_usage_mb=512.0,
        open_files_count=100,
        max_open_files=1024,
        uptime_seconds=3600.0,
        threads_count=4,
    )
    status = determine_system_status(system_health_degraded, thresholds)
    assert status == HealthStatus.DEGRADED

    # Test CRITICAL status (memory critical: default 95%)
    system_health_critical = SystemHealth(
        process_id=1234,
        process_name="test_process",
        cpu_percent=50.0,
        memory_percent=96.0,  # Above critical threshold (95%)
        memory_usage_mb=512.0,
        open_files_count=100,
        max_open_files=1024,
        uptime_seconds=3600.0,
        threads_count=4,
    )
    status = determine_system_status(system_health_critical, thresholds)
    assert status == HealthStatus.CRITICAL


def test_determine_service_status_function():
    """Test service status determination function."""
    thresholds = HealthThresholds()

    # Test HEALTHY status
    service_health = ServiceHealth(
        service_name="test_service",
        service_type="database",
        is_connected=True,
        connection_latency=0.05,
        total_operations=1000,
        successful_operations=995,
        failed_operations=5,
        avg_response_time=0.025,
        max_response_time=0.150,
        slow_operations_count=10,
        error_rate=0.5,  # Low error rate
    )
    status = determine_service_status(service_health, thresholds)
    assert status == HealthStatus.HEALTHY

    # Test CRITICAL status (disconnected)
    service_health_critical = ServiceHealth(
        service_name="test_service",
        service_type="database",
        is_connected=False,  # Disconnected
        connection_latency=0.05,
        total_operations=1000,
        successful_operations=995,
        failed_operations=5,
        avg_response_time=0.025,
        max_response_time=0.150,
        slow_operations_count=10,
        error_rate=0.5,
    )
    status = determine_service_status(service_health_critical, thresholds)
    assert status == HealthStatus.CRITICAL

    # Test DEGRADED status (high error rate)
    service_health_degraded = ServiceHealth(
        service_name="test_service",
        service_type="database",
        is_connected=True,
        connection_latency=0.05,
        total_operations=1000,
        successful_operations=995,
        failed_operations=5,
        avg_response_time=0.025,
        max_response_time=0.150,
        slow_operations_count=10,
        error_rate=10.0,  # Above warning threshold (5.0%)
    )
    status = determine_service_status(service_health_degraded, thresholds)
    assert status == HealthStatus.DEGRADED


def test_determine_overall_status_function():
    """Test overall status determination function."""
    thresholds = HealthThresholds()

    # Create sample health objects
    worker_health = WorkerHealth(
        worker_name="test_worker",
        alerts_processed=100,
        processing_rate=5.0,
        avg_processing_time=0.5,
        recent_avg_processing_time=0.4,
        min_processing_time=0.1,
        max_processing_time=1.0,
        slow_alerts_count=5,
        extremely_slow_alerts_count=1,
        last_processing_time=0.3,
        last_alert_id="alert-123",
        health_score=0.9,
    )

    queue_health = QueueHealth(
        queue_name="test_queue",
        current_size=30,
        max_size=100,
        utilization_percentage=30.0,
        total_processed=1000,
        processing_rate=5.0,
        queue_full_events=0,
        avg_wait_time=0.01,
    )

    service_health = ServiceHealth(
        service_name="test_service",
        service_type="database",
        is_connected=True,
        connection_latency=0.05,
        total_operations=1000,
        successful_operations=995,
        failed_operations=5,
        avg_response_time=0.025,
        max_response_time=0.150,
        slow_operations_count=10,
        error_rate=0.5,
    )

    system_health = SystemHealth(
        process_id=1234,
        process_name="test_process",
        cpu_percent=50.0,
        memory_percent=60.0,
        memory_usage_mb=512.0,
        open_files_count=100,
        max_open_files=1024,
        uptime_seconds=3600.0,
        threads_count=4,
    )

    # Test HEALTHY when all components healthy
    status, score = determine_overall_status(
        workers=[worker_health],
        queues=[queue_health],
        services=[service_health],
        system=system_health,
        thresholds=thresholds,
    )
    assert status == HealthStatus.HEALTHY
    assert score > 0.0

    # Test CRITICAL when system is critical
    system_health_critical = SystemHealth(
        process_id=1234,
        process_name="test_process",
        cpu_percent=96.0,  # Critical level (above 95%)
        memory_percent=60.0,
        memory_usage_mb=512.0,
        open_files_count=100,
        max_open_files=1024,
        uptime_seconds=3600.0,
        threads_count=4,
    )
    status, score = determine_overall_status(
        workers=[worker_health],
        queues=[queue_health],
        services=[service_health],
        system=system_health_critical,
        thresholds=thresholds,
    )
    assert status == HealthStatus.CRITICAL
    assert score == 0.0  # Known to be exactly 0.0 for critical

    # Test DEGRADED when some components degraded
    service_health_degraded = ServiceHealth(
        service_name="test_service",
        service_type="database",
        is_connected=True,
        connection_latency=0.05,
        total_operations=1000,
        successful_operations=900,
        failed_operations=100,
        avg_response_time=0.025,
        max_response_time=0.150,
        slow_operations_count=10,
        error_rate=10.0,  # High error rate (degraded)
    )
    status, score = determine_overall_status(
        workers=[worker_health],
        queues=[queue_health],
        services=[service_health_degraded],
        system=system_health,
        thresholds=thresholds,
    )
    assert status == HealthStatus.DEGRADED

    # Test empty lists
    status, score = determine_overall_status(
        workers=[],
        queues=[],
        services=[],
        system=system_health,
        thresholds=thresholds,
    )
    assert status == HealthStatus.HEALTHY


def test_model_serialization():
    """Test model JSON serialization capabilities."""
    worker_health = WorkerHealth(
        worker_name="test_worker",
        status=WorkerStatus.ACTIVE,
        alerts_processed=100,
        processing_rate=5.2,
        avg_processing_time=0.025,
        recent_avg_processing_time=0.015,
        min_processing_time=0.010,
        max_processing_time=0.150,
        slow_alerts_count=3,
        extremely_slow_alerts_count=1,
        last_processing_time=0.035,
        last_alert_id="alert-123",
        health_score=0.85,
    )

    # Test model_dump (Pydantic v2)
    data = worker_health.model_dump()
    assert isinstance(data, dict)
    assert data["worker_name"] == "test_worker"
    assert data["status"] == "ACTIVE"
    assert data["alerts_processed"] == 100

    # Test JSON serialization
    json_str = worker_health.model_dump_json()
    assert isinstance(json_str, (str, bytes))
    assert "test_worker" in json_str
    assert "ACTIVE" in json_str


def test_model_validation_edge_cases():
    """Test model validation with edge cases."""
    # Test QueueHealth with minimal valid values
    queue_health = QueueHealth(
        queue_name="test_queue",
        current_size=0,
        max_size=1,  # Minimum valid value (gt=0)
        utilization_percentage=0.0,
        total_processed=0,
        processing_rate=0.0,
        queue_full_events=0,
        avg_wait_time=0.0,
        status=HealthStatus.HEALTHY,
    )

    # Should handle minimal case gracefully
    assert queue_health.utilization_percentage >= 0.0

    # Test SystemHealth with minimal valid values
    system_health = SystemHealth(
        status=HealthStatus.HEALTHY,
        process_id=1,
        process_name="test",
        cpu_percent=0.0,
        memory_percent=0.0,
        memory_usage_mb=0.0,
        open_files_count=0,
        max_open_files=1,  # Minimum valid value (gt=0)
        uptime_seconds=0.0,
        threads_count=1,  # Minimum valid value (ge=1)
    )

    # Should handle minimal values gracefully
    assert system_health.is_healthy  # Should be healthy with low resource usage
    assert system_health.resource_pressure == "LOW"  # Low usage should result in low pressure
