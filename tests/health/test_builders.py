"""Comprehensive tests for health monitoring builder classes.

This module tests the builder pattern implementations including:
- WorkerPerformanceBuilder for type-safe worker data construction
- KafkaPerformanceBuilder for Kafka metrics building
- QueueStatsBuilder for queue statistics construction
- FileMonitorStatsBuilder for file monitoring data
- Builder validation and fluent API functionality
    for i in range(5):
        builder_instance = WorkerPerformanceBuilder()  # New builder for each snapshot
        snapshot = (builder_instance
                   .with_timestamp(base_timestamp + i * 60)  # Every minute
                   .with_alerts_processed(100 + i * 50)      # Increasing processing
                   .with_rate(2.0 + i * 0.5)                # Increasing rate
                   .with_processing_times(
                       avg=0.020 + i * 0.005,              # Slightly increasing time
                       recent_avg=0.015 + i * 0.003,       # Recent improvements
                       min_time=0.001,                     # Consistent minimum
                       max_time=0.100 + i * 0.020          # Increasing maximum
                   )
                   .with_slow_alerts(slow=i, extremely_slow=0)  # Some slow alerts
                   .with_last_alert(processing_time=0.020 + i * 0.005, alert_id=f"alert-{100+i}")
                   .build())Python 3.12+ best practices with function-based approach and modern pytest features.
"""

import time

import pytest

from wazuh_dfn.health.builders import (
    FileMonitorStatsBuilder,
    KafkaPerformanceBuilder,
    QueueStatsBuilder,
    WorkerLastProcessedBuilder,
    WorkerPerformanceBuilder,
)
from wazuh_dfn.health.models import WorkerPerformanceData


def test_worker_performance_builder_basic():
    """Test basic WorkerPerformanceBuilder functionality."""
    builder = WorkerPerformanceBuilder()
    timestamp = time.time()

    data = (
        builder.with_timestamp(timestamp)
        .with_alerts_processed(100)
        .with_rate(5.2)
        .with_processing_times(avg=0.025, recent_avg=0.015, min_time=0.001, max_time=0.150)
        .with_slow_alerts(slow=3, extremely_slow=1)
        .with_last_alert(processing_time=0.020, alert_id="alert-123")
        .build()
    )

    assert isinstance(data, dict)
    assert data["timestamp"] == timestamp
    assert data["alerts_processed"] == 100
    assert abs(data["rate"] - 5.2) < 1e-10
    assert abs(data["avg_processing"] - 0.025) < 1e-10
    assert abs(data["recent_avg"] - 0.015) < 1e-10
    assert abs(data["min_time"] - 0.001) < 1e-10
    assert abs(data["max_time"] - 0.150) < 1e-10
    assert data["slow_alerts"] == 3
    assert data["extremely_slow_alerts"] == 1
    assert abs(data["last_processing_time"] - 0.020) < 1e-10
    assert data["last_alert_id"] == "alert-123"


def test_worker_performance_builder_fluent_api():
    """Test fluent API chaining for WorkerPerformanceBuilder."""
    builder = WorkerPerformanceBuilder()

    # Test that each method returns the builder for chaining
    result = builder.with_timestamp(time.time())
    assert result is builder  # Same instance returned

    result = builder.with_alerts_processed(50)
    assert result is builder

    result = builder.with_rate(2.5)
    assert result is builder


def test_worker_performance_builder_missing_fields():
    """Test WorkerPerformanceBuilder with missing required fields."""
    builder = WorkerPerformanceBuilder()

    # Should raise ValueError when required fields are missing
    with pytest.raises(ValueError, match="Missing required fields"):
        builder.build()

    # Add timestamp but miss other required fields
    with pytest.raises(ValueError, match="Missing required fields"):
        builder.with_timestamp(time.time()).build()


def test_worker_performance_builder_reset():
    """Test WorkerPerformanceBuilder reusability."""
    # First builder instance
    builder1 = WorkerPerformanceBuilder()
    timestamp = time.time()

    # This will fail since missing required fields
    with pytest.raises(ValueError, match="Missing required fields"):
        builder1.with_timestamp(timestamp).with_alerts_processed(100).with_rate(5.0).build()

    # Second builder instance with complete data
    builder2 = WorkerPerformanceBuilder()
    new_timestamp = time.time() + 60
    second_data = (
        builder2.with_timestamp(new_timestamp)
        .with_alerts_processed(200)
        .with_rate(10.0)
        .with_processing_times(avg=0.02, recent_avg=0.015, min_time=0.005, max_time=0.08)
        .with_slow_alerts(slow=1, extremely_slow=0)
        .with_last_alert(processing_time=0.02, alert_id="alert-200")
        .build()
    )

    assert second_data["alerts_processed"] == 200
    assert abs(second_data["rate"] - 10.0) < 1e-10


def test_worker_last_processed_builder():
    """Test WorkerLastProcessedBuilder functionality."""
    builder = WorkerLastProcessedBuilder()
    timestamp = time.time()

    data = builder.with_processing_time(timestamp).with_alert_id("alert-456").build()

    assert isinstance(data, dict)
    assert data["last_processing_time"] == timestamp
    assert data["last_alert_id"] == "alert-456"

    # Test missing fields
    empty_builder = WorkerLastProcessedBuilder()
    with pytest.raises(ValueError, match="Missing required fields"):
        empty_builder.build()


def test_queue_stats_builder():
    """Test QueueStatsBuilder functionality."""
    builder = QueueStatsBuilder()

    data = (
        builder.with_total_processed(1000)
        .with_max_queue_size(50)
        .with_queue_full_count(5)
        .with_last_queue_size(10)
        .build()
    )

    assert isinstance(data, dict)
    assert data["total_processed"] == 1000
    assert data["max_queue_size"] == 50
    assert data["queue_full_count"] == 5
    assert data["last_queue_size"] == 10

    # Test missing fields
    empty_builder = QueueStatsBuilder()
    with pytest.raises(ValueError, match="Missing required fields"):
        empty_builder.build()


def test_kafka_performance_builder_minimal():
    """Test KafkaPerformanceBuilder with minimal required data."""
    builder = KafkaPerformanceBuilder(1.5)

    data = builder.build()

    assert isinstance(data, dict)
    assert abs(data.get("total_time", 0) - 1.5) < 1e-10
    assert len(data) == 1  # Only required field


def test_kafka_performance_builder_complete():
    """Test KafkaPerformanceBuilder with all optional fields."""
    builder = KafkaPerformanceBuilder(1.5)

    data = (
        builder.with_prep_time(0.1)
        .with_encode_time(0.2)
        .with_send_time(1.0)
        .with_connect_time(0.2)
        .with_message_size(1024)
        .with_topic("test-topic")
        .build()
    )

    assert abs(data.get("total_time", 0) - 1.5) < 1e-10
    stage_times = data.get("stage_times", {})
    assert abs(stage_times.get("prep", 0) - 0.1) < 1e-10
    assert abs(stage_times.get("encode", 0) - 0.2) < 1e-10
    assert abs(stage_times.get("send", 0) - 1.0) < 1e-10
    assert abs(stage_times.get("connect", 0) - 0.2) < 1e-10
    assert data.get("message_size") == 1024
    assert data.get("topic") == "test-topic"


def test_kafka_performance_builder_stage_specific():
    """Test KafkaPerformanceBuilder stage-specific methods."""
    builder = KafkaPerformanceBuilder(2.0)

    data = builder.with_prep_time(0.1).with_encode_time(0.3).with_send_time(1.4).with_connect_time(0.2).build()

    assert abs(data.get("total_time", 0) - 2.0) < 1e-10
    stage_times = data.get("stage_times", {})
    assert abs(stage_times.get("prep", 0) - 0.1) < 1e-10
    assert abs(stage_times.get("encode", 0) - 0.3) < 1e-10
    assert abs(stage_times.get("send", 0) - 1.4) < 1e-10
    assert abs(stage_times.get("connect", 0) - 0.2) < 1e-10


def test_file_monitor_stats_builder():
    """Test FileMonitorStatsBuilder functionality."""
    builder = FileMonitorStatsBuilder()

    data = (
        builder.with_alerts_per_second(2.5)
        .with_error_rate(0.02)
        .with_total_alerts(1000)
        .with_error_count(20)
        .with_replaced_count(5)
        .build()
    )

    assert isinstance(data, dict)
    assert abs(data["alerts_per_second"] - 2.5) < 1e-10
    assert abs(data["error_rate"] - 0.02) < 1e-10
    assert data["total_alerts"] == 1000
    assert data["error_count"] == 20
    assert data["replaced_count"] == 5


def test_file_monitor_stats_builder_from_tuple():
    """Test FileMonitorStatsBuilder creation from tuple."""
    # Simulate log_stats() return format
    stats_tuple = (2.5, 0.02, 1000, 20, 5)

    data = FileMonitorStatsBuilder.create_from_tuple(stats_tuple).build()

    assert abs(data["alerts_per_second"] - 2.5) < 1e-10
    assert abs(data["error_rate"] - 0.02) < 1e-10
    assert data["total_alerts"] == 1000
    assert data["error_count"] == 20
    assert data["replaced_count"] == 5


def test_file_monitor_stats_builder_from_tuple_invalid():
    """Test FileMonitorStatsBuilder with invalid tuple."""
    # Wrong number of elements
    with pytest.raises(ValueError, match="not enough values to unpack"):
        # Only 4 elements, should fail with "not enough values to unpack"
        FileMonitorStatsBuilder.create_from_tuple((1.0, 0.01, 100, 5))  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="too many values to unpack"):
        FileMonitorStatsBuilder.create_from_tuple((1.0, 0.01, 100, 5, 2, 999))  # type: ignore[arg-type]


def test_builder_type_safety():
    """Test that builders produce correctly typed data."""
    # Test WorkerPerformanceData type compliance
    builder = WorkerPerformanceBuilder()
    timestamp = time.time()

    data = (
        builder.with_timestamp(timestamp)
        .with_alerts_processed(100)
        .with_rate(5.2)
        .with_processing_times(avg=0.025, recent_avg=0.015, min_time=0.001, max_time=0.150)
        .with_slow_alerts(slow=3, extremely_slow=1)
        .with_last_alert(processing_time=0.025, alert_id="alert-123")
        .build()
    )

    # Should be assignable to TypedDict
    typed_data: WorkerPerformanceData = data
    assert typed_data["alerts_processed"] == 100


def test_builder_validation_edge_cases():
    """Test builder validation with edge cases."""
    # Test negative values where they shouldn't be allowed
    builder = WorkerPerformanceBuilder()

    # Negative alerts_processed should be handled by application logic
    data = (
        builder.with_timestamp(time.time())
        .with_alerts_processed(-1)  # Edge case: negative value
        .with_rate(0.0)
        .with_processing_times(avg=0.0, recent_avg=0.0, min_time=0.0, max_time=0.0)
        .with_slow_alerts(slow=0, extremely_slow=0)
        .with_last_alert(processing_time=0.0, alert_id="")
        .build()
    )

    # Builder should accept the data (validation happens at application level)
    assert data["alerts_processed"] == -1


def test_builder_reusability():
    """Test that builders can be reused after build()."""
    builder = WorkerPerformanceBuilder()
    timestamp1 = time.time()
    timestamp2 = timestamp1 + 60

    # Build first data set with all required fields
    data1 = (
        builder.with_timestamp(timestamp1)
        .with_alerts_processed(100)
        .with_rate(5.0)
        .with_processing_times(avg=0.02, recent_avg=0.015, min_time=0.005, max_time=0.08)
        .with_slow_alerts(slow=2, extremely_slow=0)
        .with_last_alert(processing_time=0.02, alert_id="alert-100")
        .build()
    )

    # Create new builder for second data set (builders are not meant to be reused after build)
    builder2 = WorkerPerformanceBuilder()
    data2 = (
        builder2.with_timestamp(timestamp2)
        .with_alerts_processed(200)
        .with_rate(10.0)
        .with_processing_times(avg=0.015, recent_avg=0.012, min_time=0.003, max_time=0.06)
        .with_slow_alerts(slow=1, extremely_slow=0)
        .with_last_alert(processing_time=0.015, alert_id="alert-200")
        .build()
    )

    # Both builds should work
    assert data1["timestamp"] == timestamp1
    assert data1["alerts_processed"] == 100

    assert data2["timestamp"] == timestamp2
    assert data2["alerts_processed"] == 200
    assert abs(data2["rate"] - 10.0) < 1e-10


def test_builder_immutability():
    """Test that built data is independent of builder state changes."""
    builder = WorkerPerformanceBuilder()
    timestamp = time.time()

    data1 = (
        builder.with_timestamp(timestamp)
        .with_alerts_processed(100)
        .with_rate(5.0)
        .with_processing_times(avg=0.02, recent_avg=0.015, min_time=0.005, max_time=0.08)
        .with_slow_alerts(slow=2, extremely_slow=0)
        .with_last_alert(processing_time=0.02, alert_id="alert-100")
        .build()
    )

    # Create new builder for second data (builders aren't meant to be reused after build)
    builder2 = WorkerPerformanceBuilder()
    data2 = (
        builder2.with_timestamp(timestamp + 60)
        .with_alerts_processed(200)
        .with_rate(10.0)
        .with_processing_times(avg=0.015, recent_avg=0.012, min_time=0.003, max_time=0.06)
        .with_slow_alerts(slow=1, extremely_slow=0)
        .with_last_alert(processing_time=0.015, alert_id="alert-200")
        .build()
    )

    # Data should be independent
    assert data1["alerts_processed"] == 100
    assert data2["alerts_processed"] == 200


def test_multiple_builders_independence():
    """Test that multiple builder instances are independent."""
    builder1 = WorkerPerformanceBuilder()
    builder2 = WorkerPerformanceBuilder()

    timestamp = time.time()

    # Configure builders differently
    data1 = (
        builder1.with_timestamp(timestamp)
        .with_alerts_processed(100)
        .with_rate(5.0)
        .with_processing_times(avg=0.02, recent_avg=0.015, min_time=0.005, max_time=0.08)
        .with_slow_alerts(slow=2, extremely_slow=0)
        .with_last_alert(processing_time=0.02, alert_id="alert-100")
        .build()
    )

    data2 = (
        builder2.with_timestamp(timestamp + 60)
        .with_alerts_processed(200)
        .with_rate(10.0)
        .with_processing_times(avg=0.015, recent_avg=0.012, min_time=0.003, max_time=0.06)
        .with_slow_alerts(slow=1, extremely_slow=0)
        .with_last_alert(processing_time=0.015, alert_id="alert-200")
        .build()
    )

    # Each builder should produce independent data
    assert data1["alerts_processed"] == 100
    assert abs(data1["rate"] - 5.0) < 1e-10

    assert data2["alerts_processed"] == 200
    assert abs(data2["rate"] - 10.0) < 1e-10


def test_builder_error_messages():
    """Test builder error messages are helpful."""
    builder = WorkerPerformanceBuilder()

    # Test specific error messages for missing fields
    try:
        builder.build()
        pytest.fail("Should have raised ValueError")
    except ValueError as e:
        assert "Missing required fields" in str(e)

    try:
        builder.with_timestamp(time.time()).build()
        pytest.fail("Should have raised ValueError")
    except ValueError as e:
        assert "Missing required fields" in str(e)


def test_complex_builder_scenarios():
    """Test complex real-world builder usage scenarios."""
    # Simulate service collecting performance data over time
    base_timestamp = time.time()

    performance_snapshots = []

    for i in range(5):
        builder_instance = WorkerPerformanceBuilder()  # New builder for each snapshot
        snapshot = (
            builder_instance.with_timestamp(base_timestamp + i * 60)  # Every minute
            .with_alerts_processed(100 + i * 50)  # Increasing processing
            .with_rate(2.0 + i * 0.5)  # Increasing rate
            .with_processing_times(
                avg=0.020 + i * 0.005,  # Slightly increasing time
                recent_avg=0.015 + i * 0.003,  # Recent improvements
                min_time=0.001,  # Consistent minimum
                max_time=0.100 + i * 0.020,  # Increasing maximum
            )
            .with_slow_alerts(slow=i, extremely_slow=max(0, i - 2))  # Some slow alerts
            .with_last_alert(processing_time=0.020 + i * 0.005, alert_id=f"alert-{i:03d}")
            .build()
        )

        performance_snapshots.append(snapshot)

    # Verify progression
    assert len(performance_snapshots) == 5
    assert performance_snapshots[0]["alerts_processed"] == 100
    assert performance_snapshots[4]["alerts_processed"] == 300
    assert abs(performance_snapshots[0]["rate"] - 2.0) < 1e-10
    assert abs(performance_snapshots[4]["rate"] - 4.0) < 1e-10
