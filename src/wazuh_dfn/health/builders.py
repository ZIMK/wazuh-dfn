"""Fluent builder classes for type-safe health data construction.

This module provides Java-like fluent builder patterns for constructing
health monitoring data structures. Builders ensure type safety, provide
IDE autocomplete support, and prevent construction errors.
"""

from __future__ import annotations

import time
from typing import Any, cast

from .models import (
    FileMonitorStatsData,
    KafkaPerformanceData,
    QueueStatsData,
    WorkerLastProcessedData,
    WorkerPerformanceData,
)


class WorkerPerformanceBuilder:
    """Fluent builder for type-safe WorkerPerformanceData construction."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def with_timestamp(self, timestamp: float) -> WorkerPerformanceBuilder:
        """Set the performance data timestamp."""
        self._data["timestamp"] = timestamp
        return self

    def with_alerts_processed(self, count: int) -> WorkerPerformanceBuilder:
        """Set the total number of alerts processed."""
        self._data["alerts_processed"] = count
        return self

    def with_rate(self, rate: float) -> WorkerPerformanceBuilder:
        """Set the processing rate (alerts per second)."""
        self._data["rate"] = rate
        return self

    def with_processing_times(
        self, avg: float, recent_avg: float, min_time: float, max_time: float
    ) -> WorkerPerformanceBuilder:
        """Set all processing time metrics at once (batch setter for efficiency)."""
        self._data.update(
            {
                "avg_processing": avg,
                "recent_avg": recent_avg,
                "min_time": min_time,
                "max_time": max_time,
            }
        )
        return self

    def with_slow_alerts(self, slow: int, extremely_slow: int) -> WorkerPerformanceBuilder:
        """Set slow alert counts (regular slow and extremely slow)."""
        self._data["slow_alerts"] = slow
        self._data["extremely_slow_alerts"] = extremely_slow
        return self

    def with_last_alert(self, processing_time: float, alert_id: str) -> WorkerPerformanceBuilder:
        """Set last processed alert information."""
        self._data["last_processing_time"] = processing_time
        self._data["last_alert_id"] = alert_id
        return self

    def with_worker_counts(self, worker_count: int, active_worker_count: int) -> WorkerPerformanceBuilder:
        """Set worker count information."""
        self._data["worker_count"] = worker_count
        self._data["active_worker_count"] = active_worker_count
        return self

    def build(self) -> WorkerPerformanceData:
        """Build the final type-safe WorkerPerformanceData.

        Raises:
            ValueError: If required fields are missing
        """
        required_fields = {
            "timestamp",
            "alerts_processed",
            "rate",
            "avg_processing",
            "recent_avg",
            "min_time",
            "max_time",
            "slow_alerts",
            "extremely_slow_alerts",
            "last_processing_time",
            "last_alert_id",
            "worker_count",
            "active_worker_count",
        }

        missing_fields = required_fields - set(self._data.keys())
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")

        # Type assertion is safe here since we've validated all required fields exist
        return cast(WorkerPerformanceData, self._data)

    @classmethod
    def create(cls) -> WorkerPerformanceBuilder:
        """Factory method for fluent creation."""
        return cls()

    @classmethod
    def create_with_defaults(cls, worker_name: str) -> WorkerPerformanceBuilder:
        """Factory method with sensible defaults for rapid prototyping."""
        return (
            cls()
            .with_timestamp(time.time())
            .with_alerts_processed(0)
            .with_rate(0.0)
            .with_processing_times(avg=0.0, recent_avg=0.0, min_time=0.0, max_time=0.0)
            .with_slow_alerts(slow=0, extremely_slow=0)
            .with_last_alert(processing_time=0.0, alert_id="")
            .with_worker_counts(worker_count=1, active_worker_count=1)
        )


class QueueStatsBuilder:
    """Fluent builder for QueueStatsData construction."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def with_total_processed(self, total: int) -> QueueStatsBuilder:
        """Set total number of processed items."""
        self._data["total_processed"] = total
        return self

    def with_max_queue_size(self, max_size: int) -> QueueStatsBuilder:
        """Set maximum queue size."""
        self._data["max_queue_size"] = max_size
        return self

    def with_config_max_queue_size(self, max_size: int) -> QueueStatsBuilder:
        """Set configured maximum queue size."""
        self._data["config_max_queue_size"] = max_size
        return self

    def with_queue_full_count(self, full_count: int) -> QueueStatsBuilder:
        """Set number of times queue was full."""
        self._data["queue_full_count"] = full_count
        return self

    def with_last_queue_size(self, last_size: int) -> QueueStatsBuilder:
        """Set last observed queue size."""
        self._data["last_queue_size"] = last_size
        return self

    def with_queue_metrics(
        self, total_processed: int, max_size: int, config_max_size: int, full_count: int, last_size: int
    ) -> QueueStatsBuilder:
        """Set all queue metrics at once (batch setter)."""
        self._data.update(
            {
                "total_processed": total_processed,
                "max_queue_size": max_size,
                "config_max_queue_size": config_max_size,
                "queue_full_count": full_count,
                "last_queue_size": last_size,
            }
        )
        return self

    def build(self) -> QueueStatsData:
        """Build the final QueueStatsData."""
        required_fields = {
            "total_processed",
            "max_queue_size",
            "config_max_queue_size",
            "queue_full_count",
            "last_queue_size",
        }
        missing_fields = required_fields - set(self._data.keys())
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")

        # Type assertion is safe here since we've validated all required fields exist
        return cast(QueueStatsData, self._data)

    @classmethod
    def create(cls) -> QueueStatsBuilder:
        """Factory method for fluent creation."""
        return cls()

    @classmethod
    def create_with_defaults(cls) -> QueueStatsBuilder:
        """Factory method with sensible defaults."""
        return (
            cls()
            .with_total_processed(0)
            .with_max_queue_size(0)
            .with_config_max_queue_size(0)
            .with_queue_full_count(0)
            .with_last_queue_size(0)
        )


class KafkaPerformanceBuilder:
    """Fluent builder for KafkaPerformanceData with stage helper methods."""

    def __init__(self, total_time: float) -> None:
        if total_time < 0:
            raise ValueError("total_time must be non-negative")
        self._data: KafkaPerformanceData = {"total_time": total_time}

    def with_prep_time(self, prep_time: float) -> KafkaPerformanceBuilder:
        """Add preparation stage timing (message preparation, validation, etc.)."""
        self._ensure_stage_times()
        if "stage_times" in self._data and self._data["stage_times"] is not None:
            self._data["stage_times"]["prep"] = prep_time
        return self

    def with_encode_time(self, encode_time: float) -> KafkaPerformanceBuilder:
        """Add encoding stage timing (JSON serialization, compression, etc.)."""
        self._ensure_stage_times()
        if "stage_times" in self._data and self._data["stage_times"] is not None:
            self._data["stage_times"]["encode"] = encode_time
        return self

    def with_send_time(self, send_time: float) -> KafkaPerformanceBuilder:
        """Add send stage timing (actual Kafka producer send operation)."""
        self._ensure_stage_times()
        if "stage_times" in self._data and self._data["stage_times"] is not None:
            self._data["stage_times"]["send"] = send_time
        return self

    def with_connect_time(self, connect_time: float) -> KafkaPerformanceBuilder:
        """Add connection stage timing (Kafka broker connection establishment)."""
        self._ensure_stage_times()
        if "stage_times" in self._data and self._data["stage_times"] is not None:
            self._data["stage_times"]["connect"] = connect_time
        return self

    def with_custom_stage(self, stage_name: str, stage_time: float) -> KafkaPerformanceBuilder:
        """Add custom stage timing with arbitrary name (flexible for custom pipelines).

        Args:
            stage_name: Name of the custom stage (e.g., 'validation', 'compression', 'encryption')
            stage_time: Time spent in this stage (seconds)
        """
        self._ensure_stage_times()
        if "stage_times" in self._data and self._data["stage_times"] is not None:
            self._data["stage_times"][stage_name] = stage_time
        return self

    def with_message_size(self, size: int) -> KafkaPerformanceBuilder:
        """Add message size in bytes."""
        self._data["message_size"] = size
        return self

    def with_topic(self, topic: str) -> KafkaPerformanceBuilder:
        """Add Kafka topic name."""
        self._data["topic"] = topic
        return self

    def _ensure_stage_times(self) -> None:
        """Ensure stage_times dict exists in the data."""
        if "stage_times" not in self._data:
            self._data["stage_times"] = {}

    def build(self) -> KafkaPerformanceData:
        """Build the final KafkaPerformanceData."""
        return self._data

    @classmethod
    def create(cls, total_time: float) -> KafkaPerformanceBuilder:
        """Factory method for fluent creation."""
        return cls(total_time)

    @classmethod
    def create_basic(cls, total_time: float, topic: str) -> KafkaPerformanceBuilder:
        """Factory method for basic Kafka operations with minimal data."""
        return cls(total_time).with_topic(topic)


class WorkerLastProcessedBuilder:
    """Fluent builder for WorkerLastProcessedData construction.

    Simple builder for last processed alert information with validation.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def with_processing_time(self, processing_time: float) -> WorkerLastProcessedBuilder:
        """Set the processing time for the last alert."""
        if processing_time < 0.0:
            raise ValueError("processing_time must be non-negative")
        self._data["last_processing_time"] = processing_time
        return self

    def with_alert_id(self, alert_id: str) -> WorkerLastProcessedBuilder:
        """Set the ID of the last processed alert."""
        if not alert_id:
            raise ValueError("alert_id cannot be empty")
        self._data["last_alert_id"] = alert_id
        return self

    def with_alert_info(self, processing_time: float, alert_id: str) -> WorkerLastProcessedBuilder:
        """Set both processing time and alert ID at once."""
        return self.with_processing_time(processing_time).with_alert_id(alert_id)

    def build(self) -> WorkerLastProcessedData:
        """Build the final WorkerLastProcessedData."""
        required_fields = {"last_processing_time", "last_alert_id"}
        missing_fields = required_fields - set(self._data.keys())
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")

        return cast(WorkerLastProcessedData, self._data)

    @classmethod
    def create(cls) -> WorkerLastProcessedBuilder:
        """Factory method for fluent creation."""
        return cls()

    @classmethod
    def create_with_defaults(cls) -> WorkerLastProcessedBuilder:
        """Factory method with sensible defaults."""
        return cls().with_alert_info(processing_time=0.0, alert_id="")


class FileMonitorStatsBuilder:
    """Fluent builder for FileMonitorStatsData construction.

    Replaces the tuple return from file_monitor.log_stats() with type-safe construction.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def with_alerts_per_second(self, rate: float) -> FileMonitorStatsBuilder:
        """Set the alerts per second rate."""
        if rate < 0.0:
            raise ValueError("alerts_per_second must be non-negative")
        self._data["alerts_per_second"] = rate
        return self

    def with_error_rate(self, rate: float) -> FileMonitorStatsBuilder:
        """Set the error rate percentage."""
        if rate < 0.0 or rate > 100.0:
            raise ValueError("error_rate must be between 0.0 and 100.0")
        self._data["error_rate"] = rate
        return self

    def with_totals(self, total_alerts: int, error_count: int, replaced_count: int) -> FileMonitorStatsBuilder:
        """Set all count totals at once (batch setter for efficiency)."""
        if total_alerts < 0 or error_count < 0 or replaced_count < 0:
            raise ValueError("All counts must be non-negative")
        self._data["total_alerts"] = total_alerts
        self._data["error_count"] = error_count
        self._data["replaced_count"] = replaced_count
        return self

    def with_total_alerts(self, count: int) -> FileMonitorStatsBuilder:
        """Set the total number of alerts processed."""
        if count < 0:
            raise ValueError("total_alerts must be non-negative")
        self._data["total_alerts"] = count
        return self

    def with_error_count(self, count: int) -> FileMonitorStatsBuilder:
        """Set the number of errors encountered."""
        if count < 0:
            raise ValueError("error_count must be non-negative")
        self._data["error_count"] = count
        return self

    def with_replaced_count(self, count: int) -> FileMonitorStatsBuilder:
        """Set the number of replaced/corrected items."""
        if count < 0:
            raise ValueError("replaced_count must be non-negative")
        self._data["replaced_count"] = count
        return self

    def build(self) -> FileMonitorStatsData:
        """Build the final FileMonitorStatsData."""
        required_fields = {"alerts_per_second", "error_rate", "total_alerts", "error_count", "replaced_count"}
        missing_fields = required_fields - set(self._data.keys())
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")

        return cast(FileMonitorStatsData, self._data)

    @classmethod
    def create(cls) -> FileMonitorStatsBuilder:
        """Factory method for fluent creation."""
        return cls()

    @classmethod
    def create_from_tuple(cls, stats_tuple: tuple[float, float, int, int, int]) -> FileMonitorStatsBuilder:
        """Factory method to convert from log_stats() tuple format."""
        alerts_per_second, error_rate, total_alerts, error_count, replaced_count = stats_tuple
        return (
            cls()
            .with_alerts_per_second(alerts_per_second)
            .with_error_rate(error_rate)
            .with_totals(total_alerts, error_count, replaced_count)
        )
