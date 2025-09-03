"""Unified health monitoring models and data structures.

This module contains all health monitoring data structures and models:
- Enums for status types
- TypedDicts for events and real-time data
- Pydantic models for comprehensive health status
- Unified in one place for better maintainability
"""

from __future__ import annotations

import collections
import os
import time
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Self, TypedDict

from pydantic import BaseModel, ConfigDict, Field, SkipValidation, computed_field, field_validator


# Kafka Performance Data (moved from kafka_service.py to avoid circular imports)
class KafkaPerformanceData(TypedDict, total=False):
    """Type definition for Kafka performance data."""

    # Required fields
    total_time: float

    # Optional fields
    stage_times: dict[str, float]  # Keys include 'prep', 'encode', 'send', 'connect'
    message_size: int
    topic: str


# Service health type with mandatory fields and flexible additional data
class ServiceHealthBase(TypedDict):
    """Base service health data with mandatory fields."""

    service_name: str
    is_healthy: bool
    status: str  # HealthStatus value


class ServiceHealthExtended(ServiceHealthBase, total=False):
    """Extended service health data with optional fields."""

    # Common optional fields
    service_type: str
    is_connected: bool
    connection_latency: float
    last_successful_connection: str  # ISO timestamp

    # Performance metrics
    total_operations: int
    successful_operations: int
    failed_operations: int
    error_rate: float
    success_rate: float

    # Timing metrics
    avg_response_time: float
    max_response_time: float
    slow_operations_count: int

    # Timestamp
    timestamp: str  # ISO timestamp

    # Any additional service-specific metrics
    metrics: dict[str, Any]


# Type alias for service health data (replaces rigid ServiceHealth model)
ServiceHealth = ServiceHealthExtended


# Status Enums (using StrEnum for better serialization)
class HealthStatus(StrEnum):
    """Universal health status for all components and API responses."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"

    def __eq__(self, other) -> bool:
        """Case-insensitive equality comparison for HealthStatus."""
        if isinstance(other, str):
            return self.value.lower() == other.lower()
        elif isinstance(other, HealthStatus):
            return self.value.lower() == other.value.lower()
        return False

    def __hash__(self) -> int:
        """Ensure hash consistency with case-insensitive equality."""
        return hash(self.value.lower())


class WorkerStatus(StrEnum):
    """Worker-specific status."""

    ACTIVE = "ACTIVE"
    STALLED = "STALLED"
    IDLE = "IDLE"


class ServiceStatus(StrEnum):
    """Service-specific status (Kafka, databases, etc.)."""

    HEALTHY = "HEALTHY"
    SLOW = "SLOW"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"


# TypedDicts for events and real-time data
class WorkerPerformanceData(TypedDict):
    """Type-safe definition for worker performance data (for events).

    Used for real-time event pushing. The full WorkerHealth model below
    is used for comprehensive health status.
    """

    timestamp: float
    alerts_processed: int
    rate: float
    avg_processing: float
    recent_avg: float
    min_time: float
    max_time: float
    slow_alerts: int
    extremely_slow_alerts: int
    last_processing_time: float
    last_alert_id: str
    worker_count: int  # Total configured worker count
    active_worker_count: int  # Currently active worker count


class WorkerLastProcessedData(TypedDict):
    """Type-safe definition for worker last processed data (for events)."""

    last_processing_time: float
    last_alert_id: str


class QueueStatsData(TypedDict):
    """Type-safe definition for queue statistics (for events)."""

    total_processed: int
    max_queue_size: int
    config_max_queue_size: int
    queue_full_count: int
    last_queue_size: int


class KafkaInternalStatsData(TypedDict):
    """Type-safe definition for internal Kafka performance tracking."""

    slow_operations: int
    total_operations: int
    last_slow_operation_time: float
    max_operation_time: float
    recent_stage_times: list[dict[str, float]]  # Last 5 slow operation stage times


class WorkerProcessedTimesData(TypedDict):
    """Type-safe wrapper for worker processed times mapping."""

    worker_times: dict[str, float]  # worker name → timestamp


class FileMonitorStatsData(TypedDict):
    """Type-safe definition for file monitor statistics (replaces log_stats tuple)."""

    alerts_per_second: float
    error_rate: float
    total_alerts: int
    error_count: int
    replaced_count: int


class ServicePerformanceData(TypedDict):
    """Type-safe definition for general service performance data (for events)."""

    service_name: str
    service_type: str
    timestamp: float
    total_operations: int
    successful_operations: int
    failed_operations: int
    avg_response_time: float
    max_response_time: float
    slow_operations_count: int
    error_rate: float
    is_connected: bool
    connection_latency: float


# Event structures for real-time pushing
class HealthEvent(TypedDict):
    """Base health event structure."""

    event_type: str
    timestamp: float


class WorkerPerformanceEvent(TypedDict):
    """Worker performance event structure."""

    event_type: str  # "worker_performance"
    timestamp: float
    worker_name: str
    data: WorkerPerformanceData


class WorkerLastProcessedEvent(TypedDict):
    """Worker last processed event structure."""

    event_type: str  # "worker_last_processed"
    timestamp: float
    worker_name: str
    data: WorkerLastProcessedData


class KafkaPerformanceEvent(TypedDict):
    """Kafka performance event structure."""

    event_type: str  # "kafka_performance"
    timestamp: float
    data: KafkaPerformanceData


class ServicePerformanceEvent(TypedDict):
    """Service performance event structure."""

    event_type: str  # "service_performance"
    timestamp: float
    data: ServicePerformanceData


class FileMonitorStatsEvent(TypedDict):
    """File monitor statistics event structure."""

    event_type: str  # "file_monitor_stats"
    timestamp: float
    data: FileMonitorStatsData


# Base classes for Pydantic models
class BaseHealthModel(BaseModel):
    """Base class for all health monitoring models.

    Provides:
    - Immutable configuration via ConfigDict
    - Automatic timestamp generation
    - Consistent validation rules
    - JSON serialization for REST API
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        # Immutability and validation
        frozen=True,
        validate_assignment=True,
        extra="forbid",
        # Performance optimizations
        str_strip_whitespace=True,
        use_enum_values=True,
        # JSON serialization
        json_encoders={
            # Custom encoders can be added here
        },
        # Field validation
        validate_default=True,
        arbitrary_types_allowed=False,
    )


class HealthThresholds(BaseHealthModel):
    """Configurable health monitoring thresholds.

    Centralizes all threshold values with environment variable support
    for easy configuration across deployment environments.
    """

    model_config: ClassVar[ConfigDict] = BaseHealthModel.model_config.copy()

    # Queue health thresholds (extracted from hardcoded values)
    queue_warning_percentage: float = Field(
        default=70.0, ge=0.0, le=100.0, description="Queue fill percentage triggering warnings"
    )
    queue_critical_percentage: float = Field(
        default=90.0, ge=0.0, le=100.0, description="Queue fill percentage triggering critical alerts"
    )
    queue_high_throughput_percentage: float = Field(
        default=80.0, ge=0.0, le=100.0, description="Queue fill percentage triggering high throughput mode"
    )
    queue_recovery_percentage: float = Field(
        default=50.0, ge=0.0, le=100.0, description="Queue fill percentage for recovery from high throughput mode"
    )

    # Worker health thresholds
    worker_stall_seconds: float = Field(
        default=60.0, ge=0.0, description="Seconds without activity before worker considered stalled"
    )
    worker_slow_processing_threshold: float = Field(
        default=2.0, ge=0.0, description="Processing time threshold for slow alert classification"
    )
    worker_extremely_slow_threshold: float = Field(
        default=10.0, ge=0.0, description="Processing time threshold for extremely slow alert classification"
    )

    # Kafka/service health thresholds (from logging_service.py constants)
    kafka_slow_operation_seconds: float = Field(
        default=1.0, ge=0.0, description="Kafka operation time threshold for slow classification"
    )
    kafka_extremely_slow_seconds: float = Field(
        default=5.0, ge=0.0, description="Kafka operation time threshold for extremely slow classification"
    )
    service_connection_timeout_seconds: float = Field(
        default=30.0, ge=0.0, description="Service connection timeout before marked disconnected"
    )
    service_error_rate_warning: float = Field(
        default=5.0, ge=0.0, le=100.0, description="Service error rate percentage triggering warnings"
    )
    service_error_rate_critical: float = Field(
        default=15.0, ge=0.0, le=100.0, description="Service error rate percentage triggering critical alerts"
    )

    # System resource thresholds (new - not currently implemented)
    system_cpu_warning_percentage: float = Field(
        default=80.0, ge=0.0, le=100.0, description="CPU usage percentage triggering warnings"
    )
    system_cpu_critical_percentage: float = Field(
        default=95.0, ge=0.0, le=100.0, description="CPU usage percentage triggering critical alerts"
    )
    system_memory_warning_percentage: float = Field(
        default=85.0, ge=0.0, le=100.0, description="Memory usage percentage triggering warnings"
    )
    system_memory_critical_percentage: float = Field(
        default=95.0, ge=0.0, le=100.0, description="Memory usage percentage triggering critical alerts"
    )
    system_disk_warning_percentage: float = Field(
        default=80.0, ge=0.0, le=100.0, description="Disk usage percentage triggering warnings"
    )
    system_disk_critical_percentage: float = Field(
        default=90.0, ge=0.0, le=100.0, description="Disk usage percentage triggering critical alerts"
    )

    # File descriptor thresholds
    open_files_warning_percentage: float = Field(
        default=80.0, ge=0.0, le=100.0, description="Open file descriptors percentage triggering warnings"
    )
    open_files_critical_percentage: float = Field(
        default=95.0, ge=0.0, le=100.0, description="Open file descriptors percentage triggering critical alerts"
    )

    @classmethod
    def from_environment(cls) -> Self:
        """Create HealthThresholds from environment variables.

        Supports environment variables with HEALTH_THRESHOLD_ prefix:
        - HEALTH_THRESHOLD_QUEUE_WARNING_PERCENTAGE=75.0
        - HEALTH_THRESHOLD_WORKER_STALL_SECONDS=120.0
        - etc.
        """
        env_data: dict[str, Any] = {}
        prefix = "HEALTH_THRESHOLD_"

        # Map environment variables to model field names
        for env_key, env_value in os.environ.items():
            if env_key.startswith(prefix):
                field_name = env_key[len(prefix) :].lower()
                try:
                    # Convert string to appropriate type (float for all current fields)
                    env_data[field_name] = float(env_value)
                except (ValueError, TypeError):
                    # Skip invalid values - use defaults
                    continue

        return cls(**env_data)

    @computed_field
    @property
    def validation_errors(self) -> list[str]:
        """Computed field: Validate threshold relationships."""
        errors: list[str] = []

        # Queue thresholds should be ordered
        if self.queue_warning_percentage >= self.queue_critical_percentage:
            errors.append("queue_warning_percentage must be less than queue_critical_percentage")

        if self.queue_recovery_percentage >= self.queue_high_throughput_percentage:
            errors.append("queue_recovery_percentage must be less than queue_high_throughput_percentage")

        # System thresholds should be ordered
        if self.system_cpu_warning_percentage >= self.system_cpu_critical_percentage:
            errors.append("cpu warning threshold must be less than critical threshold")

        if self.system_memory_warning_percentage >= self.system_memory_critical_percentage:
            errors.append("memory warning threshold must be less than critical threshold")

        if self.system_disk_warning_percentage >= self.system_disk_critical_percentage:
            errors.append("disk warning threshold must be less than critical threshold")

        # Worker thresholds should be ordered
        if self.worker_slow_processing_threshold >= self.worker_extremely_slow_threshold:
            errors.append("slow processing threshold must be less than extremely slow threshold")

        # Service thresholds should be ordered
        if self.service_error_rate_warning >= self.service_error_rate_critical:
            errors.append("service error rate warning must be less than critical")

        if self.kafka_slow_operation_seconds >= self.kafka_extremely_slow_seconds:
            errors.append("kafka slow threshold must be less than extremely slow threshold")

        return errors


# Pydantic Health Models
class WorkerHealth(BaseHealthModel):
    """Enhanced worker health model with computed health scoring.

    This model provides comprehensive worker health assessment using
    pydantic v2 features for optimal performance and validation.
    """

    model_config: ClassVar[ConfigDict] = BaseHealthModel.model_config.copy()

    # Core identification
    worker_name: str = Field(..., description="Unique worker identifier")

    # Performance metrics (maps to current 12-field structure)
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
    alerts_processed: int = Field(ge=0, description="Total alerts processed")

    # Rate and timing metrics
    processing_rate: float = Field(ge=0.0, description="Alerts per second")
    avg_processing_time: float = Field(ge=0.0, description="Average processing time in seconds")
    recent_avg_processing_time: float = Field(ge=0.0, description="Recent average processing time")

    # Timing bounds
    min_processing_time: float = Field(ge=0.0, description="Minimum processing time observed")
    max_processing_time: float = Field(ge=0.0, description="Maximum processing time observed")

    # Alert categorization
    slow_alerts_count: int = Field(ge=0, description="Count of slow alerts processed")
    extremely_slow_alerts_count: int = Field(ge=0, description="Count of extremely slow alerts")

    # Latest processing info
    last_processing_time: float = Field(ge=0.0, description="Time for last alert processed")
    last_alert_id: str = Field(description="ID of last processed alert")

    # Health assessment
    status: WorkerStatus = Field(default=WorkerStatus.ACTIVE)
    health_score: float = Field(ge=0.0, le=1.0, description="Computed health score")

    @computed_field
    @property
    def is_healthy(self) -> bool:
        """Computed field: True if worker is in good health."""
        return self.status == WorkerStatus.ACTIVE and self.health_score >= 0.7

    @computed_field
    @property
    def performance_summary(self) -> dict[str, Any]:
        """Computed field: Summary of key performance metrics."""
        return {
            "rate": self.processing_rate,
            "avg_time": self.avg_processing_time,
            "slow_percentage": (self.slow_alerts_count / max(self.alerts_processed, 1)) * 100,
            "health_score": self.health_score,
        }


class QueueHealth(BaseHealthModel):
    """Enhanced queue health model with utilization analysis.

    Provides detailed queue health assessment with configurable
    thresholds and trend analysis.
    """

    model_config: ClassVar[ConfigDict] = BaseHealthModel.model_config.copy()

    # Core queue metrics
    queue_name: str = Field(..., description="Queue identifier")
    current_size: int = Field(ge=0, description="Current number of items in queue")
    max_size: int = Field(ge=0, description="Maximum queue capacity")

    config_max_size: int = Field(ge=0, description="Configured maximum queue capacity")

    # Utilization metrics
    utilization_percentage: float = Field(ge=0.0, le=100.0, description="Queue utilization as percentage")

    # Processing statistics
    total_processed: int = Field(ge=0, description="Total items processed")
    processing_rate: float = Field(ge=0.0, description="Items per second")

    # Performance indicators
    queue_full_events: int = Field(ge=0, description="Times queue reached capacity")
    avg_wait_time: float = Field(ge=0.0, description="Average time items wait in queue")

    # Health assessment
    status: HealthStatus = Field(default=HealthStatus.HEALTHY)
    timestamp: datetime = Field(default_factory=lambda: datetime.now())

    @computed_field
    @property
    def is_healthy(self) -> bool:
        """Computed field: True if queue is operating normally."""
        return self.status == HealthStatus.HEALTHY and self.utilization_percentage < 80.0

    @computed_field
    @property
    def risk_level(self) -> str:
        """Computed field: Risk assessment based on utilization."""
        if self.utilization_percentage >= 90.0:
            return "CRITICAL"
        elif self.utilization_percentage >= 70.0:
            return "WARNING"
        else:
            return "LOW"


class SystemHealth(BaseHealthModel):
    """Enhanced system health model with resource monitoring.

    Tracks system-level health including CPU, memory, disk usage,
    and process-specific metrics.
    """

    model_config: ClassVar[ConfigDict] = BaseHealthModel.model_config.copy()

    # Process identification
    process_id: int = Field(gt=0, description="Process ID")
    process_name: str = Field(description="Process name")

    # Resource utilization
    cpu_percent: float = Field(ge=0.0, le=100.0, description="CPU usage percentage")
    memory_percent: float = Field(ge=0.0, le=100.0, description="Memory usage percentage")
    memory_usage_mb: float = Field(ge=0.0, description="Memory usage in MB")

    # File system metrics
    open_files_count: int = Field(ge=0, description="Number of open file descriptors")
    max_open_files: int = Field(ge=0, description="Maximum allowed open files")

    # Runtime metrics
    uptime_seconds: float = Field(ge=0.0, description="Process uptime in seconds")
    threads_count: int = Field(ge=1, description="Number of active threads")

    # System load
    load_average: list[float] = Field(default_factory=list, description="System load average [1min, 5min, 15min]")

    # Health assessment
    status: HealthStatus = Field(default=HealthStatus.HEALTHY)
    timestamp: datetime = Field(default_factory=lambda: datetime.now())

    @computed_field
    @property
    def is_healthy(self) -> bool:
        """Computed field: True if system resources are healthy."""
        return self.cpu_percent < 80.0 and self.memory_percent < 85.0 and self.status == HealthStatus.HEALTHY

    @computed_field
    @property
    def resource_pressure(self) -> str:
        """Computed field: Overall resource pressure assessment."""
        if self.cpu_percent > 90.0 or self.memory_percent > 95.0:
            return "HIGH"
        elif self.cpu_percent > 70.0 or self.memory_percent > 80.0:
            return "MEDIUM"
        else:
            return "LOW"


class HealthMetrics(BaseHealthModel):
    """Root health metrics model aggregating all component health data.

    This is the primary model returned by the health API, providing
    a complete view of system health with computed overall status.
    """

    model_config: ClassVar[ConfigDict] = BaseHealthModel.model_config.copy()

    # Metadata
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
    version: str = Field(default="1.0.0", description="Health metrics schema version")

    # Aggregated health status
    overall_status: HealthStatus = Field(description="Overall system health")
    health_score: float = Field(ge=0.0, le=100.0, description="Overall health score (0-100)")

    # Component health
    system: SystemHealth = Field(description="System resource health")
    workers: dict[str, WorkerHealth] = Field(default_factory=dict, description="Worker health by worker name")
    queues: dict[str, QueueHealth] = Field(default_factory=dict, description="Queue health by queue name")
    services: SkipValidation[dict[str, ServiceHealth]] = Field(
        default_factory=dict,
        description="External service health by service name (ServiceHealth-compatible with flexible fields)",
    )

    @field_validator("services")
    @classmethod
    def validate_services(cls, v: dict[str, ServiceHealth]) -> dict[str, ServiceHealth]:
        """Validate that each service has required ServiceHealthBase fields, allow extra fields.

        Ensures compatibility with ServiceHealth structure while allowing additional service-specific fields.
        """
        if not isinstance(v, dict):
            raise ValueError("Services must be a dictionary")

        validated_services = {}

        for service_name, service_data in v.items():
            if not isinstance(service_data, dict):
                raise ValueError(f"Service '{service_name}' must be a dictionary")

            # Check required ServiceHealthBase fields
            required_fields = {"service_name", "is_healthy", "status"}
            missing_fields = required_fields - set(service_data.keys())

            if missing_fields:
                raise ValueError(f"Service '{service_name}' missing required fields: {missing_fields}")

            # Validate required field types
            if not isinstance(service_data["service_name"], str):
                raise ValueError(f"Service '{service_name}' field 'service_name' must be a string")

            if not isinstance(service_data["is_healthy"], bool):
                raise ValueError(f"Service '{service_name}' field 'is_healthy' must be a boolean")

            if not isinstance(service_data["status"], str):
                raise ValueError(f"Service '{service_name}' field 'status' must be a string")

            # All validation passed, keep the service data as-is (including extra fields)
            validated_services[service_name] = service_data

        return validated_services

    @computed_field
    @property
    def is_healthy(self) -> bool:
        """Computed field: True if overall system is healthy."""
        return self.overall_status == HealthStatus.HEALTHY

    @computed_field
    @property
    def component_summary(self) -> dict[str, int]:
        """Computed field: Count of healthy/unhealthy components."""
        healthy_workers = sum(1 for w in self.workers.values() if w.is_healthy)
        healthy_queues = sum(1 for q in self.queues.values() if q.is_healthy)
        healthy_services = sum(1 for s in self.services.values() if s["is_healthy"])

        total_workers = len(self.workers)
        total_queues = len(self.queues)
        total_services = len(self.services)

        return {
            "healthy_workers": healthy_workers,
            "total_workers": total_workers,
            "healthy_queues": healthy_queues,
            "total_queues": total_queues,
            "healthy_services": healthy_services,
            "total_services": total_services,
            "system_healthy": self.system.is_healthy,
        }

    @classmethod
    def create_bounded_history(cls, max_entries: int = 1000) -> collections.deque[Self]:
        """Create bounded history container to prevent memory leaks."""
        return collections.deque(maxlen=max_entries)


# Health Status Classification Functions
def determine_worker_status(
    worker_health: WorkerHealth, thresholds: HealthThresholds, last_activity_time: float | None = None
) -> WorkerStatus:
    """Determine worker health status based on metrics and thresholds.

    Args:
        worker_health: Current worker health metrics
        thresholds: Configurable threshold values
        last_activity_time: Time of last worker activity (timestamp)

    Returns:
        WorkerStatus enum value (ACTIVE, STALLED, IDLE)
    """
    current_time = time.time()

    # Check for stalled worker (no activity within threshold)
    if last_activity_time is not None:
        time_since_activity = current_time - last_activity_time
        if time_since_activity > thresholds.worker_stall_seconds:
            return WorkerStatus.STALLED

    # Check processing performance
    if worker_health.processing_rate <= 0.0:
        return WorkerStatus.IDLE

    # Check if too many slow alerts
    if worker_health.alerts_processed > 0:
        slow_percentage = (worker_health.slow_alerts_count / worker_health.alerts_processed) * 100
        if slow_percentage > 20.0:  # More than 20% slow alerts indicates issues
            return WorkerStatus.STALLED

    # Check if processing times are consistently high
    if (
        worker_health.avg_processing_time > thresholds.worker_slow_processing_threshold
        or worker_health.last_processing_time > thresholds.worker_extremely_slow_threshold
    ):
        return WorkerStatus.STALLED

    return WorkerStatus.ACTIVE


def determine_queue_status(queue_health: QueueHealth, thresholds: HealthThresholds) -> HealthStatus:
    """Determine queue health status based on utilization and thresholds.

    Args:
        queue_health: Current queue health metrics
        thresholds: Configurable threshold values

    Returns:
        HealthStatus enum value (HEALTHY, DEGRADED, CRITICAL)
    """
    utilization = queue_health.utilization_percentage

    if utilization >= thresholds.queue_critical_percentage:
        return HealthStatus.CRITICAL
    elif utilization >= thresholds.queue_warning_percentage:
        return HealthStatus.DEGRADED
    else:
        return HealthStatus.HEALTHY


def determine_service_status(  # noqa: PLR0911
    service_health: ServiceHealth, thresholds: HealthThresholds
) -> HealthStatus:
    """Determine service health status based on connection and performance.

    Args:
        service_health: Current service health metrics
        thresholds: Configurable threshold values

    Returns:
        HealthStatus enum value (HEALTHY, DEGRADED, CRITICAL)
    """
    # Check if service has health status indicator
    if not service_health["is_healthy"]:
        return HealthStatus.CRITICAL

    # Check connection status
    if not service_health.get("is_connected", True):
        return HealthStatus.CRITICAL

    # Check error rate if available
    error_rate = service_health.get("error_rate", 0.0)
    if error_rate >= thresholds.service_error_rate_critical:
        return HealthStatus.CRITICAL
    elif error_rate >= thresholds.service_error_rate_warning:
        return HealthStatus.DEGRADED

    # Check response times for Kafka services
    service_type = service_health.get("service_type", "unknown")
    if service_type == "kafka":
        avg_response_time = service_health.get("avg_response_time", 0.0)
        if avg_response_time >= thresholds.kafka_extremely_slow_seconds:
            return HealthStatus.CRITICAL
        elif avg_response_time >= thresholds.kafka_slow_operation_seconds:
            return HealthStatus.DEGRADED

    # Check connection latency if available
    connection_latency = service_health.get("connection_latency", 0.0)
    if connection_latency > thresholds.service_connection_timeout_seconds:
        return HealthStatus.DEGRADED

    return HealthStatus.HEALTHY


def determine_system_status(system_health: SystemHealth, thresholds: HealthThresholds) -> HealthStatus:  # noqa: PLR0911
    """Determine system health status based on resource usage.

    Args:
        system_health: Current system health metrics
        thresholds: Configurable threshold values

    Returns:
        HealthStatus enum value (HEALTHY, DEGRADED, CRITICAL)
    """
    # Check CPU usage
    if system_health.cpu_percent >= thresholds.system_cpu_critical_percentage:
        return HealthStatus.CRITICAL
    elif system_health.cpu_percent >= thresholds.system_cpu_warning_percentage:
        return HealthStatus.DEGRADED

    # Check memory usage
    if system_health.memory_percent >= thresholds.system_memory_critical_percentage:
        return HealthStatus.CRITICAL
    elif system_health.memory_percent >= thresholds.system_memory_warning_percentage:
        return HealthStatus.DEGRADED

    # Check file descriptor usage
    fd_usage = (system_health.open_files_count / system_health.max_open_files) * 100
    if fd_usage >= thresholds.open_files_critical_percentage:
        return HealthStatus.CRITICAL
    elif fd_usage >= thresholds.open_files_warning_percentage:
        return HealthStatus.DEGRADED

    return HealthStatus.HEALTHY


def determine_overall_status(  # noqa: PLR0912
    workers: list[WorkerHealth],
    queues: list[QueueHealth],
    services: list[ServiceHealth],
    system: SystemHealth,
    thresholds: HealthThresholds,
) -> tuple[HealthStatus, float]:
    """Determine overall system health status with priority-based classification.

    Args:
        workers: List of worker health metrics
        queues: List of queue health metrics
        services: List of service health metrics
        system: System health metrics
        thresholds: Configurable threshold values

    Returns:
        Tuple of (overall_status, health_score) where health_score is 0-100
    """
    # Priority order: CRITICAL > DEGRADED > HEALTHY
    # System issues are highest priority
    system_status = determine_system_status(system, thresholds)
    if system_status == HealthStatus.CRITICAL:
        return HealthStatus.CRITICAL, 0.0

    # Check for any critical services (especially Kafka)
    critical_services = 0
    degraded_services = 0
    for service in services:
        service_status = determine_service_status(service, thresholds)
        if service_status == HealthStatus.CRITICAL:
            critical_services += 1
        elif service_status == HealthStatus.DEGRADED:
            degraded_services += 1

    if critical_services > 0:
        return HealthStatus.CRITICAL, 10.0  # Very low score for critical services

    # Check for critical queues
    critical_queues = 0
    degraded_queues = 0
    for queue in queues:
        queue_status = determine_queue_status(queue, thresholds)
        if queue_status == HealthStatus.CRITICAL:
            critical_queues += 1
        elif queue_status == HealthStatus.DEGRADED:
            degraded_queues += 1

    if critical_queues > 0:
        return HealthStatus.CRITICAL, 20.0  # Low score for critical queues

    # Calculate health score based on component health
    total_components = len(workers) + len(queues) + len(services) + 1  # +1 for system
    healthy_components = 0

    # Count healthy components
    if system_status == HealthStatus.HEALTHY:
        healthy_components += 1

    for service in services:
        if determine_service_status(service, thresholds) == HealthStatus.HEALTHY:
            healthy_components += 1

    for queue in queues:
        if determine_queue_status(queue, thresholds) == HealthStatus.HEALTHY:
            healthy_components += 1

    for worker in workers:
        if worker.status == WorkerStatus.ACTIVE:
            healthy_components += 1

    health_score = (healthy_components / total_components) * 100

    # Determine overall status
    if degraded_services > 0 or degraded_queues > 0 or system_status == HealthStatus.DEGRADED:
        return HealthStatus.DEGRADED, max(health_score, 30.0)  # At least 30% for degraded

    # Check worker health
    stalled_workers = sum(1 for w in workers if w.status == WorkerStatus.STALLED)
    if stalled_workers > len(workers) / 2:  # More than half workers stalled
        return HealthStatus.DEGRADED, max(health_score, 40.0)

    return HealthStatus.HEALTHY, health_score
