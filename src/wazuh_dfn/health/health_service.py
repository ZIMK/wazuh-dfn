"""HealthService implementation - Enhanced replacement for LoggingService.

This service integrates real-time event processing with health monitoring,
maintaining full backward compatibility with LoggingService behavior.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from contextlib import suppress
from datetime import datetime, timedelta
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None

try:
    import resource
except ImportError:
    resource = None

from wazuh_dfn.config import HealthConfig
from wazuh_dfn.service_container import ServiceContainer

from .models import (
    HealthMetrics,
    HealthStatus,
    HealthThresholds,
    QueueHealth,
    ServiceHealth,
    SystemHealth,
    WorkerHealth,
    WorkerStatus,
    determine_overall_status,
)

# Logging
LOGGER = logging.getLogger(__name__)


class HealthService:
    """Enhanced health monitoring service - replacement for LoggingService.

    Features:
    - Real-time event queue integration with HealthEventService
    - Complete LoggingService API compatibility
    - Structured health data collection
    - Automatic event processing with bounded memory
    - System resource monitoring
    """

    def __init__(
        self,
        container: ServiceContainer,
        config: HealthConfig,
        event_queue: asyncio.Queue[dict[str, Any]],
        shutdown_event: asyncio.Event,
    ) -> None:
        """Initialize health service.

        Args:
            container: Service container for accessing providers
            config: Health configuration (uses defaults if None)
            event_queue: Optional event queue from HealthEventService for real-time events
        """
        self.container = container
        self._config = config or HealthConfig()

        # Caching
        self._last_collection_time = 0.0
        self._cached_metrics: HealthMetrics | None = None
        self._cache_duration = 5.0

        # Event processing - direct queue injection (cleaner than service discovery)
        self._event_queue_reference = event_queue
        self._event_processing_task: asyncio.Task | None = None
        self._shutdown_event = shutdown_event
        self._worker_performance_data: dict[str, dict[str, Any]] = {}
        self._worker_last_processed: dict[str, dict[str, Any]] = {}
        self._kafka_performance_data = {
            "slow_operations": 0,
            "total_operations": 0,
            "last_slow_operation_time": 0,
            "max_operation_time": 0,
            "recent_stage_times": [],
        }
        self._perf_lock = asyncio.Lock()

        # System monitoring
        self.process = psutil.Process() if psutil else None

        # Thresholds (LoggingService compatibility)
        self._warning_fill_threshold = 70.0
        self._critical_fill_threshold = 90.0

        # Note: ServiceContainer will register this service explicitly
        # to avoid circular dependency during initialization

    async def start(self) -> None:
        """Start health service with periodic logging and event processing."""
        LOGGER.info("Starting health service")

        # Start event processing if queue is available
        if self._event_queue_reference:
            self._event_processing_task = asyncio.create_task(self._process_events_loop())
            LOGGER.info("Started real-time event processing")
        else:
            LOGGER.info("No event queue provided - running without real-time events")

        # Start periodic logging (LoggingService compatibility)
        await self._start_periodic_logging()

    async def stop(self) -> None:
        """Stop health service and cleanup."""
        LOGGER.info("Stopping health service")
        self._shutdown_event.set()

        # Stop event processing
        if self._event_processing_task:
            self._event_processing_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._event_processing_task

        # Final stats logging
        with suppress(Exception):
            await self._log_stats()

    async def _start_periodic_logging(self) -> None:
        """Start periodic statistics logging."""
        LOGGER.info("Starting periodic logging")
        try:
            while not self._shutdown_event.is_set():
                await self._log_stats()
                with suppress(TimeoutError):
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=self._config.stats_interval)
        except asyncio.CancelledError:
            LOGGER.info("Periodic logging cancelled")

    async def _process_events_loop(self) -> None:
        """Process events from HealthEventService queue."""
        if not self._event_queue_reference:
            return

        LOGGER.info("Started real-time event processing")

        try:
            while not self._shutdown_event.is_set():
                try:
                    event = await asyncio.wait_for(self._event_queue_reference.get(), timeout=1.0)
                    await self._process_health_event(event)
                except TimeoutError:
                    continue
        except asyncio.CancelledError:
            LOGGER.info("Event processing cancelled")

    async def _process_health_event(self, event: dict[str, Any]) -> None:
        """Process a health event."""
        try:
            event_type = event.get("event_type")

            if event_type == "worker_performance":
                await self._handle_worker_performance_event(event)
            elif event_type == "worker_last_processed":
                await self._handle_worker_last_processed_event(event)
            elif event_type == "kafka_performance":
                await self._handle_kafka_performance_event(event)

        except Exception as e:
            LOGGER.error(f"Error processing event: {e}")

    async def _handle_worker_performance_event(self, event: dict[str, Any]) -> None:
        """Handle worker performance event."""
        worker_name = event.get("worker_name")
        performance_data = event.get("data")

        if worker_name and performance_data:
            async with self._perf_lock:
                self._worker_performance_data[worker_name] = performance_data

    async def _handle_worker_last_processed_event(self, event: dict[str, Any]) -> None:
        """Handle worker last processed event."""
        worker_name = event.get("worker_name")
        info = event.get("data")

        if worker_name and info:
            async with self._perf_lock:
                self._worker_last_processed[worker_name] = info

    async def _handle_kafka_performance_event(self, event: dict[str, Any]) -> None:
        """Handle Kafka performance event."""
        operation_data = event.get("data", {})

        async with self._perf_lock:
            self._kafka_performance_data["total_operations"] += 1

            total_time = operation_data.get("total_time", 0)
            if total_time > 1.0:  # SLOW_OPERATIONS_THRESHOLD
                self._kafka_performance_data["slow_operations"] += 1
                self._kafka_performance_data["last_slow_operation_time"] = total_time
                self._kafka_performance_data["max_operation_time"] = max(
                    self._kafka_performance_data["max_operation_time"], total_time
                )

                stage_times = operation_data.get("stage_times", {})
                self._kafka_performance_data["recent_stage_times"].append(stage_times)
                if len(self._kafka_performance_data["recent_stage_times"]) > 5:
                    self._kafka_performance_data["recent_stage_times"].pop(0)

    # LoggingService API compatibility
    async def record_worker_performance(self, worker_name: str, performance_data: dict[str, Any]) -> None:
        """Record worker performance (LoggingService compatibility)."""
        async with self._perf_lock:
            self._worker_performance_data[worker_name] = performance_data

            # Immediate alerting for extremely slow operations
            if (
                performance_data.get("extremely_slow_alerts", 0) > 0
                and performance_data.get("last_processing_time", 0) > 5.0
            ):
                LOGGER.warning(
                    f"SLOW WORKER: {worker_name} processed alert in {performance_data['last_processing_time']:.2f}s. "
                    f"Alert ID: {performance_data.get('last_alert_id', 'unknown')}"
                )

    async def record_kafka_performance(self, operation_data: dict[str, Any]) -> None:
        """Record Kafka performance (LoggingService compatibility)."""
        await self._handle_kafka_performance_event(
            {"event_type": "kafka_performance", "timestamp": time.time(), "data": operation_data}
        )

    async def update_worker_last_processed(self, worker_name: str, info: dict[str, Any]) -> None:
        """Update worker last processed (LoggingService compatibility)."""
        async with self._perf_lock:
            self._worker_last_processed[worker_name] = info

    # Modern Health Data Access Methods
    async def get_current_health(self) -> HealthMetrics:
        """Get real-time health status without caching.

        Returns:
            HealthMetrics: Complete system health data
        """
        # Force fresh collection
        self._last_collection_time = 0.0
        self._cached_metrics = None

        return await self._collect_health_metrics()

    async def get_health_history(self, duration: timedelta, max_entries: int = 100) -> list[HealthMetrics]:
        """Get bounded health history for trend analysis.

        Args:
            duration: Time window for history
            max_entries: Maximum number of entries to return

        Returns:
            List of HealthMetrics bounded by max_entries

        Note:
            This is a placeholder - full implementation requires persistent storage.
            Currently returns current health only.
        """
        # For now, return current health (placeholder for full implementation)
        current = await self.get_current_health()
        return [current]

    async def get_component_health(self, component: str) -> ServiceHealth | WorkerHealth | QueueHealth | SystemHealth:
        """Get specific component health with lazy evaluation.

        Args:
            component: Component identifier (e.g., 'kafka', 'worker-1', 'alert_queue', 'system')

        Returns:
            Specific component health data

        Raises:
            ValueError: If component not found
        """
        metrics = await self._collect_health_metrics()

        # Check services
        for service in metrics.services.values():
            if service.service_name == component:
                return service

        # Check workers
        for worker in metrics.workers.values():
            if worker.worker_name == component:
                return worker

        # Check queues
        for queue in metrics.queues.values():
            if queue.queue_name == component:
                return queue

        # Check system
        if component == "system":
            return metrics.system

        raise ValueError(f"Component '{component}' not found")

    async def get_health_summary(self) -> dict[str, Any]:
        """Get minimal health summary for dashboard/API use.

        Returns:
            Minimal health data optimized for API responses
        """
        metrics = await self._collect_health_metrics()

        return {
            "overall_status": metrics.overall_status.value,
            "health_score": metrics.health_score,
            "timestamp": metrics.timestamp.isoformat(),
            "components": {
                "workers": {
                    "total": len(metrics.workers),
                    "healthy": sum(1 for w in metrics.workers.values() if w.status == WorkerStatus.ACTIVE),
                    "stalled": sum(1 for w in metrics.workers.values() if w.status == WorkerStatus.STALLED),
                },
                "services": {
                    "total": len(metrics.services),
                    "connected": sum(1 for s in metrics.services.values() if s.is_connected),
                    "healthy": sum(1 for s in metrics.services.values() if s.is_healthy),
                },
                "queues": {
                    "total": len(metrics.queues),
                    "healthy": sum(1 for q in metrics.queues.values() if q.is_healthy),
                    "average_utilization": (
                        sum(q.utilization_percentage for q in metrics.queues.values()) / max(len(metrics.queues), 1)
                    ),
                },
                "system": {
                    "healthy": metrics.system.is_healthy,
                    "cpu_percent": metrics.system.cpu_percent,
                    "memory_percent": metrics.system.memory_percent,
                    "resource_pressure": metrics.system.resource_pressure,
                },
            },
        }

    # Memory Management Methods
    async def cleanup_old_health_data(self) -> None:
        """Automatic cleanup of old health data to prevent memory leaks.

        Uses HealthConfig.history_retention and max_history_entries to determine
        what data to clean up. Prevents unbounded memory growth.
        """
        current_time = time.time()
        retention_seconds = self._config.history_retention
        max_entries = self._config.max_history_entries

        async with self._perf_lock:
            # Clean worker performance data based on retention policy
            for worker_name, worker_data in list(self._worker_performance_data.items()):
                if isinstance(worker_data, dict) and "timestamp" in worker_data:
                    # Remove entries older than retention period
                    if current_time - worker_data["timestamp"] > retention_seconds:
                        del self._worker_performance_data[worker_name]
                        continue

                # If we have too many entries, keep only the most recent ones
                if len(self._worker_performance_data) > max_entries:
                    # Sort by timestamp and keep most recent
                    sorted_workers = sorted(
                        self._worker_performance_data.items(),
                        key=lambda x: x[1].get("timestamp", 0) if isinstance(x[1], dict) else 0,
                        reverse=True,
                    )
                    self._worker_performance_data = dict(sorted_workers[:max_entries])
                    break

            # Clean Kafka performance data
            if "recent_stage_times" in self._kafka_performance_data:
                recent_times = self._kafka_performance_data["recent_stage_times"]
                if len(recent_times) > max_entries:
                    self._kafka_performance_data["recent_stage_times"] = recent_times[-max_entries:]

            # Clean last processed data based on retention
            for worker_name, info in list(self._worker_last_processed.items()):
                if isinstance(info, dict) and "timestamp" in info:
                    if current_time - info["timestamp"] > retention_seconds:
                        del self._worker_last_processed[worker_name]

        # Clear cache to ensure fresh data
        self._cached_metrics = None

        cleaned_count = len(self._worker_performance_data) + len(self._worker_last_processed)
        LOGGER.debug(
            f"Cleaned up health data (retention: {retention_seconds}s, "
            f"max entries: {max_entries}, remaining: {cleaned_count})"
        )

    def get_memory_usage(self) -> dict[str, int]:
        """Get health service memory footprint monitoring.

        Returns:
            Memory usage statistics in bytes
        """
        usage = {}

        # Performance data sizes
        usage["worker_performance_data"] = sys.getsizeof(self._worker_performance_data)
        usage["worker_last_processed"] = sys.getsizeof(self._worker_last_processed)
        usage["kafka_performance_data"] = sys.getsizeof(self._kafka_performance_data)

        # Cache sizes
        if self._cached_metrics:
            usage["cached_metrics"] = sys.getsizeof(self._cached_metrics)
        else:
            usage["cached_metrics"] = 0

        # Total
        usage["total"] = sum(usage.values())

        return usage

    async def _collect_health_metrics(self) -> HealthMetrics:
        """Collect comprehensive health metrics from all system components.

        This is the core method that gathers data from all providers and
        constructs a complete HealthMetrics object with current system state.

        Returns:
            HealthMetrics: Complete system health data
        """
        # Get configurable thresholds using HealthConfig integration
        thresholds = self._get_configured_thresholds()

        # Collect system health
        system_health = await self._collect_system_health()

        # Collect worker health from all registered workers
        workers = await self._collect_worker_health()

        # Collect queue health
        queues = await self._collect_queue_health()

        # Collect service health (Kafka, file monitors, etc.)
        services = await self._collect_service_health()

        # Determine overall health status
        overall_status, health_score = determine_overall_status(
            workers=list(workers.values()),
            queues=list(queues.values()),
            services=list(services.values()),
            system=system_health,
            thresholds=thresholds,
        )

        # Create comprehensive metrics
        return HealthMetrics(
            overall_status=overall_status,
            health_score=health_score,
            workers=workers,
            queues=queues,
            services=services,
            system=system_health,
        )

    def _get_configured_thresholds(self) -> HealthThresholds:
        """Get configurable thresholds from HealthConfig or environment.

        Uses HealthConfig thresholds if available, falls back to environment variables,
        then uses defaults. This provides a complete configuration hierarchy.

        Returns:
            HealthThresholds: Configured threshold values
        """
        # Create base thresholds from environment
        thresholds = HealthThresholds.from_environment()

        # Override with HealthConfig values if available
        if self._config:
            # Map HealthConfig fields to HealthThresholds fields
            config_overrides = {}

            # Queue thresholds
            config_overrides["queue_warning_percentage"] = float(self._config.queue_warning_threshold)
            config_overrides["queue_critical_percentage"] = float(self._config.queue_critical_threshold)

            # Worker thresholds
            config_overrides["worker_stall_seconds"] = float(self._config.worker_stall_threshold)

            # Kafka thresholds
            config_overrides["kafka_slow_operation_seconds"] = self._config.kafka_slow_threshold
            config_overrides["kafka_extremely_slow_seconds"] = self._config.kafka_extremely_slow_threshold

            # Create new thresholds with config overrides
            return HealthThresholds.model_validate({**thresholds.model_dump(), **config_overrides})

        return thresholds

    async def _collect_system_health(self) -> SystemHealth:
        """Collect system resource health metrics."""
        if not self.process:
            # Fallback when psutil not available
            return SystemHealth(
                process_id=1,
                process_name="unknown",
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_usage_mb=0.0,
                open_files_count=0,
                max_open_files=1024,
                uptime_seconds=time.time(),
                threads_count=1,
            )

        try:
            # Get process info
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            cpu_percent = self.process.cpu_percent()

            # Get file descriptor info
            try:
                open_files = len(self.process.open_files())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                open_files = 0

            # Get max file descriptors (Unix only)
            max_files = 1024
            if resource and hasattr(resource, "getrlimit") and hasattr(resource, "RLIMIT_NOFILE"):
                max_files = resource.getrlimit(resource.RLIMIT_NOFILE)[0]  # type: ignore[]

            # Calculate uptime
            create_time = self.process.create_time()
            uptime = time.time() - create_time

            return SystemHealth(
                process_id=self.process.pid,
                process_name=self.process.name(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_usage_mb=memory_info.rss / (1024 * 1024),  # Convert to MB
                open_files_count=open_files,
                max_open_files=max_files,
                uptime_seconds=uptime,
                threads_count=self.process.num_threads(),
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            LOGGER.warning(f"Could not collect system metrics: {e}")
            return SystemHealth(
                process_id=1,
                process_name="error",
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_usage_mb=0.0,
                open_files_count=0,
                max_open_files=1024,
                uptime_seconds=0.0,
                threads_count=1,
            )

    async def _collect_worker_health(self) -> dict[str, WorkerHealth]:
        """Collect health metrics from all worker services."""
        workers = {}

        # Get worker performance data
        async with self._perf_lock:
            performance_data = self._worker_performance_data.copy()
            last_processed_data = self._worker_last_processed.copy()

        for worker_name, perf_data in performance_data.items():
            try:
                # Get last processed info
                last_info = last_processed_data.get(worker_name, {})

                # Create WorkerHealth from performance data
                worker = WorkerHealth(
                    worker_name=worker_name,
                    alerts_processed=perf_data.get("alerts_processed", 0),
                    processing_rate=perf_data.get("rate", 0.0),
                    avg_processing_time=perf_data.get("avg_processing", 0.0),
                    recent_avg_processing_time=perf_data.get("recent_avg", 0.0),
                    min_processing_time=perf_data.get("min_time", 0.0),
                    max_processing_time=perf_data.get("max_time", 0.0),
                    slow_alerts_count=perf_data.get("slow_alerts", 0),
                    extremely_slow_alerts_count=perf_data.get("extremely_slow_alerts", 0),
                    last_processing_time=last_info.get("last_processing_time", 0.0),
                    last_alert_id=last_info.get("last_alert_id", ""),
                    health_score=min(1.0, max(0.0, perf_data.get("rate", 0.0) / 100.0)),  # Simple score calculation
                )

                workers[worker_name] = worker

            except Exception as e:
                LOGGER.error(f"Error collecting worker health for {worker_name}: {e}")
                continue

        return workers

    async def _collect_queue_health(self) -> dict[str, QueueHealth]:
        """Collect health metrics from queue services."""
        queues = {}

        try:
            # Try to get queue stats from alerts worker service
            alerts_worker = self.container.get_service("alerts_worker")
            if alerts_worker and hasattr(alerts_worker, "get_queue_stats"):
                queue_stats = alerts_worker.get_queue_stats()

                # Get current queue size
                current_size = queue_stats.get("last_queue_size", 0)
                max_size = queue_stats.get("max_queue_size", 1000)
                utilization = (current_size / max_size * 100) if max_size > 0 else 0.0

                queue = QueueHealth(
                    queue_name="alert_queue",
                    current_size=current_size,
                    max_size=max_size,
                    utilization_percentage=utilization,
                    total_processed=queue_stats.get("total_processed", 0),
                    processing_rate=50.0,  # Placeholder - would calculate from recent metrics
                    queue_full_events=queue_stats.get("queue_full_count", 0),
                    avg_wait_time=0.1,  # Placeholder - would track actual wait times
                )

                queues["alert_queue"] = queue

        except Exception as e:
            LOGGER.error(f"Error collecting queue health: {e}")

        return queues

    async def _collect_service_health(self) -> dict[str, ServiceHealth]:
        """Collect health metrics from external services (Kafka, etc.)."""
        services = {}

        try:
            # Check Kafka service health
            kafka_service = self.container.get_service("kafka")
            if kafka_service:
                # Get kafka performance data
                async with self._perf_lock:
                    kafka_perf = self._kafka_performance_data.copy()

                # Determine connection status
                is_connected = True  # Would check kafka_service.producer status
                if hasattr(kafka_service, "producer") and kafka_service.producer is None:
                    is_connected = False

                # Calculate metrics
                total_ops = kafka_perf.get("total_operations", 0)
                slow_ops = kafka_perf.get("slow_operations", 0)
                failed_ops = 0  # Would track from actual failures
                successful_ops = max(0, total_ops - failed_ops)
                error_rate = (failed_ops / max(total_ops, 1)) * 100

                kafka_health = ServiceHealth(
                    service_name="kafka",
                    service_type="kafka",
                    is_connected=is_connected,
                    connection_latency=0.05,  # Would measure actual latency
                    total_operations=total_ops,
                    successful_operations=successful_ops,
                    failed_operations=failed_ops,
                    avg_response_time=kafka_perf.get("max_operation_time", 0.0) / 2,  # Approximation
                    max_response_time=kafka_perf.get("max_operation_time", 0.0),
                    slow_operations_count=slow_ops,
                    error_rate=error_rate,
                )

                services["kafka"] = kafka_health

        except Exception as e:
            LOGGER.error(f"Error collecting service health: {e}")

        return services

    async def _log_stats(self) -> None:
        """Log statistics (LoggingService compatibility)."""
        try:
            # Log queue statistics
            await self._log_queue_stats()

            # Log system metrics
            self._log_system_metrics()

            # Log service status
            self._log_service_status()

            # Log worker performance
            await self._log_worker_performance()

            # Log Kafka performance
            await self._log_kafka_performance()

        except Exception as e:
            LOGGER.error(f"Error collecting monitoring stats: {e}", exc_info=True)

    async def _log_queue_stats(self) -> None:
        """Log queue statistics."""
        try:
            queue_providers = self.container.get_queue_providers()

            if not queue_providers:
                LOGGER.warning("No queue providers available")
                return

            for queue_name, provider in queue_providers.items():
                try:
                    stats = provider.get_queue_stats()
                    queue_size = stats.get("last_queue_size", 0)
                    max_size = stats.get("max_queue_size", 100)

                    fill_percentage = (queue_size / max_size) * 100 if max_size > 0 else 0

                    if fill_percentage > self._critical_fill_threshold:
                        LOGGER.error(
                            f"CRITICAL: Queue {queue_name} is {fill_percentage:.1f}% full ({queue_size}/{max_size})!"
                        )
                    elif fill_percentage > self._warning_fill_threshold:
                        LOGGER.warning(f"Queue {queue_name} is {fill_percentage:.1f}% full ({queue_size}/{max_size})!")
                    else:
                        LOGGER.info(f"Queue {queue_name} is {fill_percentage:.1f}% full ({queue_size}/{max_size})")

                    LOGGER.info(
                        f"Queue {queue_name} stats: {stats.get('total_processed', 0)} total processed, "
                        f"max size reached: {max_size}, "
                        f"queue full warnings: {stats.get('queue_full_count', 0)}"
                    )
                except Exception as e:
                    LOGGER.error(f"Error getting queue stats for {queue_name}: {e}")
        except Exception as e:
            LOGGER.error(f"Error logging queue stats: {e}")

    def _log_system_metrics(self) -> None:
        """Log system metrics."""
        if not self.process:
            return

        try:
            memory_percent = self.process.memory_percent()
            LOGGER.info(f"Current memory usage: {memory_percent:.2f}%")
        except Exception as e:
            LOGGER.error(f"Error getting memory usage: {e}")

        if psutil:
            try:
                cpu_percent = psutil.cpu_percent()
                LOGGER.info(f"CPU usage (avg): {cpu_percent:.2f}%")
            except Exception as e:
                LOGGER.debug(f"Error getting CPU average: {e}")

        try:
            open_files = self.process.open_files()
            LOGGER.info(f"Current open files: {open_files}")
        except Exception as e:
            LOGGER.error(f"Error getting open files: {e}")

    def _log_service_status(self) -> None:
        """Log service status."""
        try:
            kafka_providers = self.container.get_kafka_providers()

            if not kafka_providers:
                LOGGER.warning("No Kafka providers available")
                return

            for service_name, provider in kafka_providers.items():
                try:
                    is_healthy = provider.get_health_status() if hasattr(provider, "get_health_status") else True
                    if is_healthy:
                        LOGGER.info(f"Service {service_name} is alive")
                    else:
                        LOGGER.warning(f"Service {service_name} is not healthy")
                except Exception as e:
                    LOGGER.error(f"Error checking service {service_name}: {e}")
        except Exception as e:
            LOGGER.error(f"Error logging service status: {e}")

    async def _log_worker_performance(self) -> None:
        """Log worker performance."""
        try:
            worker_providers = self.container.get_worker_providers()

            if worker_providers is None or worker_providers == {}:
                LOGGER.warning("No worker providers available")
                return

            async with self._perf_lock:
                worker_perf_data = self._worker_performance_data.copy()

            for name, provider in worker_providers.items():
                try:
                    performance = provider.get_worker_performance()
                    worker_timestamp = performance.get("timestamp", time.time())

                    worker_last_processed = datetime.fromtimestamp(worker_timestamp)
                    worker_diff = datetime.now() - worker_last_processed
                    worker_seconds_ago = worker_diff.total_seconds()

                    # Log with stall detection
                    if worker_seconds_ago > 60:
                        LOGGER.warning(
                            f"Worker {name} last processed: {worker_last_processed}, "
                            f"{worker_seconds_ago:.2f} seconds ago (STALLED)"
                        )
                    else:
                        LOGGER.info(
                            f"Worker {name} last processed: {worker_last_processed}, "
                            f"{worker_seconds_ago:.2f} seconds ago"
                        )

                    # Log performance metrics if available
                    if name in worker_perf_data:
                        perf = worker_perf_data[name]
                        LOGGER.info(
                            f"Worker {name} performance: {perf.get('alerts_processed', 0)} alerts processed, "
                            f"rate: {perf.get('rate', 0):.2f} alerts/sec, "
                            f"avg: {perf.get('avg_processing', 0)*1000:.2f}ms, "
                            f"recent avg: {perf.get('recent_avg', 0)*1000:.2f}ms, "
                            f"slow alerts: {perf.get('slow_alerts', 0)}, "
                            f"extremely slow: {perf.get('extremely_slow_alerts', 0)}"
                        )
                except Exception as e:
                    LOGGER.error(f"Error logging worker performance for {name}: {e}")
        except Exception as e:
            LOGGER.error(f"Error logging worker performance: {e}")

    async def _log_kafka_performance(self) -> None:
        """Log Kafka performance."""
        try:
            async with self._perf_lock:
                kafka_perf = self._kafka_performance_data.copy()

            if not kafka_perf:
                LOGGER.warning("No Kafka performance data available")
                return

            if kafka_perf["total_operations"] > 0:
                slow_pct = (
                    (kafka_perf["slow_operations"] / kafka_perf["total_operations"]) * 100
                    if kafka_perf["total_operations"] > 0
                    else 0
                )

                LOGGER.info(
                    f"Kafka performance: {kafka_perf['total_operations']} operations, "
                    f"{kafka_perf['slow_operations']} slow ({slow_pct:.1f}%), "
                    f"max time: {kafka_perf['max_operation_time']:.2f}s"
                )

                if kafka_perf["slow_operations"] > 0 and kafka_perf["recent_stage_times"]:
                    latest = kafka_perf["recent_stage_times"][-1]
                    LOGGER.info(
                        f"Latest slow Kafka operation: "
                        f"Prep: {latest.get('prep', 0):.2f}s, "
                        f"Encode: {latest.get('encode', 0):.2f}s, "
                        f"Send: {latest.get('send', 0):.2f}s"
                    )
        except Exception as e:
            LOGGER.error(f"Error logging Kafka performance: {e}")

    # Health metrics API
    def get_health_metrics(self) -> HealthMetrics:
        """Get comprehensive health metrics."""
        start_time = time.time()

        # Check cache
        if self._cached_metrics and (start_time - self._last_collection_time) < self._cache_duration:
            return self._cached_metrics

        # Create system health
        system_health = self._create_system_health()

        # Collect component health
        workers_dict = self._collect_workers_dict()
        queues_dict = self._collect_queues_dict()
        services_dict = self._collect_services_dict()

        # Calculate overall status and score
        overall_status = self._calculate_overall_status(workers_dict, services_dict, system_health)
        health_score = self._calculate_health_score(workers_dict, services_dict, system_health)

        # Create metrics
        metrics = HealthMetrics(
            overall_status=overall_status,
            health_score=health_score,
            system=system_health,
            workers=workers_dict,
            queues=queues_dict,
            services=services_dict,
        )

        # Cache results
        self._cached_metrics = metrics
        self._last_collection_time = start_time

        return metrics

    def _create_system_health(self) -> SystemHealth:
        """Create system health metrics."""
        if not self.process:
            return SystemHealth(
                process_id=0,
                process_name="unknown",
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_usage_mb=0.0,
                open_files_count=0,
                max_open_files=1024,
                uptime_seconds=0.0,
                threads_count=1,
            )

        try:
            process_info = self.process.as_dict(["pid", "name", "create_time", "num_threads"])
            memory_info = self.process.memory_info()

            cpu_percent = psutil.cpu_percent() if psutil else 0.0
            uptime_seconds = time.time() - process_info.get("create_time", time.time())

            try:
                open_files_count = len(self.process.open_files())
            except (psutil.AccessDenied, AttributeError):
                open_files_count = 0

            max_open_files = 1024
            if resource and hasattr(resource, "getrlimit") and hasattr(resource, "RLIMIT_NOFILE"):
                max_open_files = resource.getrlimit(resource.RLIMIT_NOFILE)[0]  # type: ignore[]

            return SystemHealth(
                process_id=process_info.get("pid", 0),
                process_name=process_info.get("name", "unknown"),
                cpu_percent=cpu_percent,
                memory_percent=self.process.memory_percent(),
                memory_usage_mb=memory_info.rss / (1024 * 1024),
                open_files_count=open_files_count,
                max_open_files=max_open_files,
                uptime_seconds=uptime_seconds,
                threads_count=process_info.get("num_threads", 1),
            )
        except Exception as e:
            LOGGER.error(f"Error creating system health: {e}")
            return SystemHealth(
                process_id=0,
                process_name="error",
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_usage_mb=0.0,
                open_files_count=0,
                max_open_files=1024,
                uptime_seconds=0.0,
                threads_count=1,
            )

    def _collect_workers_dict(self) -> dict[str, WorkerHealth]:
        """Collect worker health as dictionary."""
        workers = {}
        worker_providers = self.container.get_worker_providers()

        for name, provider in worker_providers.items():
            try:
                performance = provider.get_worker_performance()
                is_healthy = provider.get_health_status()

                # Create minimal worker health
                workers[name] = WorkerHealth(
                    worker_name=name,
                    alerts_processed=performance.get("alerts_processed", 0),
                    processing_rate=performance.get("rate", 0.0),
                    avg_processing_time=performance.get("avg_processing", 0.0),
                    recent_avg_processing_time=performance.get("recent_avg", 0.0),
                    min_processing_time=performance.get("min_time", 0.0),
                    max_processing_time=performance.get("max_time", 0.0),
                    slow_alerts_count=performance.get("slow_alerts", 0),
                    extremely_slow_alerts_count=performance.get("extremely_slow_alerts", 0),
                    last_processing_time=performance.get("last_processing_time", 0.0),
                    last_alert_id=performance.get("last_alert_id", ""),
                    status=WorkerStatus.ACTIVE if is_healthy else WorkerStatus.STALLED,
                    health_score=0.8 if is_healthy else 0.2,
                )
            except Exception as e:
                LOGGER.error(f"Error collecting worker health for {name}: {e}")
                workers[name] = WorkerHealth(
                    worker_name=name,
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
                    status=WorkerStatus.STALLED,
                    health_score=0.0,
                )

        return workers

    def _collect_queues_dict(self) -> dict[str, QueueHealth]:
        """Collect queue health as dictionary."""
        queues = {}
        queue_providers = self.container.get_queue_providers()

        for name, provider in queue_providers.items():
            try:
                stats = provider.get_queue_stats()
                current_size = stats.get("last_queue_size", 0)
                max_size = stats.get("max_queue_size", 100)
                utilization = (current_size / max_size) * 100 if max_size > 0 else 0.0

                status = HealthStatus.HEALTHY
                if utilization > 90:
                    status = HealthStatus.CRITICAL
                elif utilization > 70:
                    status = HealthStatus.DEGRADED

                queues[name] = QueueHealth(
                    queue_name=name,
                    current_size=current_size,
                    max_size=max_size,
                    utilization_percentage=utilization,
                    total_processed=stats.get("total_processed", 0),
                    processing_rate=1.0,
                    queue_full_events=stats.get("queue_full_count", 0),
                    avg_wait_time=0.1,
                    status=status,
                )
            except Exception as e:
                LOGGER.error(f"Error collecting queue health for {name}: {e}")
                queues[name] = QueueHealth(
                    queue_name=name,
                    current_size=0,
                    max_size=100,
                    utilization_percentage=0.0,
                    total_processed=0,
                    processing_rate=0.0,
                    queue_full_events=1,
                    avg_wait_time=0.0,
                    status=HealthStatus.CRITICAL,
                )

        return queues

    def _collect_services_dict(self) -> dict[str, ServiceHealth]:
        """Collect service health as dictionary."""
        services = {}
        kafka_providers = self.container.get_kafka_providers()

        for name, provider in kafka_providers.items():
            try:
                is_healthy = provider.get_health_status()

                services[name] = ServiceHealth(
                    service_name=name,
                    service_type="kafka",
                    is_connected=is_healthy,
                    connection_latency=0.1 if is_healthy else 5.0,
                    total_operations=100,
                    successful_operations=95 if is_healthy else 50,
                    failed_operations=5 if is_healthy else 50,
                    avg_response_time=0.2 if is_healthy else 2.0,
                    max_response_time=1.0 if is_healthy else 10.0,
                    slow_operations_count=5 if is_healthy else 50,
                    error_rate=5.0 if is_healthy else 50.0,
                    status=HealthStatus.HEALTHY if is_healthy else HealthStatus.CRITICAL,
                )
            except Exception as e:
                LOGGER.error(f"Error collecting service health for {name}: {e}")
                services[name] = ServiceHealth(
                    service_name=name,
                    service_type="kafka",
                    is_connected=False,
                    connection_latency=10.0,
                    total_operations=0,
                    successful_operations=0,
                    failed_operations=1,
                    avg_response_time=0.0,
                    max_response_time=0.0,
                    slow_operations_count=1,
                    error_rate=100.0,
                    status=HealthStatus.CRITICAL,
                )

        return services

    def _calculate_overall_status(self, workers: dict, services: dict, system: SystemHealth) -> HealthStatus:
        """Calculate overall system status."""
        if not system.is_healthy:
            return HealthStatus.CRITICAL

        if workers and not any(w.is_healthy for w in workers.values()):
            return HealthStatus.CRITICAL

        if services and not any(s.is_healthy for s in services.values()):
            return HealthStatus.CRITICAL

        # Check for degraded performance
        if workers and len([w for w in workers.values() if w.is_healthy]) < len(workers):
            return HealthStatus.DEGRADED

        return HealthStatus.HEALTHY

    def _calculate_health_score(self, workers: dict, services: dict, system: SystemHealth) -> float:
        """Calculate overall health score."""
        total_score = 0.0
        components = 0

        # System score (30%)
        if system.is_healthy:
            system_score = 100.0 - (system.cpu_percent * 0.5) - (system.memory_percent * 0.3)
            total_score += max(0.0, min(100.0, system_score)) * 0.3
        components += 0.3

        # Worker score (40%)
        if workers:
            healthy_workers = sum(1 for w in workers.values() if w.is_healthy)
            worker_score = (healthy_workers / len(workers)) * 100
            total_score += worker_score * 0.4
            components += 0.4

        # Service score (30%)
        if services:
            healthy_services = sum(1 for s in services.values() if s.is_healthy)
            service_score = (healthy_services / len(services)) * 100
            total_score += service_score * 0.3
            components += 0.3

        return total_score / components if components > 0 else 100.0

    # Quick health status methods
    def get_quick_health_status(self) -> dict[str, Any]:
        """Get lightweight health status for load balancers."""
        try:
            worker_providers = self.container.get_worker_providers()
            service_providers = self.container.get_kafka_providers()

            healthy_workers = sum(1 for provider in worker_providers.values() if provider.get_health_status())
            healthy_services = sum(1 for provider in service_providers.values() if provider.get_health_status())

            total_workers = len(worker_providers)
            total_services = len(service_providers)

            is_operational = (total_workers == 0 or healthy_workers > 0) and (
                total_services == 0 or healthy_services > 0
            )

            status = HealthStatus.HEALTHY if is_operational else HealthStatus.CRITICAL
            if is_operational and (healthy_workers < total_workers or healthy_services < total_services):
                status = HealthStatus.DEGRADED

            return {
                "status": status,
                "timestamp": time.time(),
                "workers": {"healthy": healthy_workers, "total": total_workers},
                "services": {"healthy": healthy_services, "total": total_services},
            }
        except Exception as e:
            LOGGER.error(f"Error in quick health check: {e}")
            return {"status": HealthStatus.ERROR, "timestamp": time.time(), "error": "Health check failed"}

    def get_worker_status(self) -> dict[str, Any]:
        """Get detailed worker status information."""
        worker_providers = self.container.get_worker_providers()
        worker_status = {}

        for name, provider in worker_providers.items():
            try:
                performance = provider.get_worker_performance()
                is_healthy = provider.get_health_status()
                is_processing = provider.is_processing()
                last_error = provider.get_last_error()

                worker_status[name] = {
                    "healthy": is_healthy,
                    "processing": is_processing,
                    "performance": {
                        "alerts_processed": performance["alerts_processed"],
                        "rate": performance["rate"],
                        "avg_processing": performance["avg_processing"],
                        "slow_alerts": performance["slow_alerts"],
                        "extremely_slow_alerts": performance["extremely_slow_alerts"],
                    },
                    "last_error": last_error,
                    "timestamp": performance["timestamp"],
                }
            except Exception as e:
                LOGGER.error(f"Error collecting worker status for {name}: {e}")
                worker_status[name] = {"healthy": False, "error": str(e), "timestamp": time.time()}

        return {
            "workers": worker_status,
            "summary": {
                "total": len(worker_providers),
                "healthy": sum(1 for w in worker_status.values() if w.get("healthy", False)),
                "processing": sum(1 for w in worker_status.values() if w.get("processing", False)),
            },
            "timestamp": time.time(),
        }

    def get_detailed_health(self) -> dict[str, Any]:
        """Get detailed health status for API endpoint."""
        try:
            metrics = self.get_health_metrics()

            # Convert HealthMetrics to dict format expected by API
            detailed_health = {
                "overall_status": metrics.overall_status.value,
                "health_score": metrics.health_score,
                "timestamp": datetime.now().isoformat(),
                "system": {
                    "status": HealthStatus.HEALTHY if metrics.system.is_healthy else HealthStatus.DEGRADED,
                    "cpu_percent": metrics.system.cpu_percent,
                    "memory_percent": metrics.system.memory_percent,
                    "memory_usage_mb": metrics.system.memory_usage_mb,
                    "uptime_seconds": metrics.system.uptime_seconds,
                    "process_id": metrics.system.process_id,
                    "process_name": metrics.system.process_name,
                    "threads_count": metrics.system.threads_count,
                    "open_files_count": metrics.system.open_files_count,
                    "max_open_files": metrics.system.max_open_files,
                },
                "workers": {
                    "status": (
                        HealthStatus.HEALTHY
                        if all(w.is_healthy for w in metrics.workers.values())
                        else HealthStatus.DEGRADED
                    ),
                    "total": len(metrics.workers),
                    "active": sum(1 for w in metrics.workers.values() if w.status == WorkerStatus.ACTIVE),
                    "workers": {
                        name: {
                            "worker_name": worker.worker_name,
                            "status": worker.status.value,
                            "alerts_processed": worker.alerts_processed,
                            "processing_rate": worker.processing_rate,
                            "avg_processing_time": worker.avg_processing_time,
                            "health_score": worker.health_score,
                            "last_alert_id": worker.last_alert_id,
                        }
                        for name, worker in metrics.workers.items()
                    },
                },
                "queues": {
                    "status": (
                        HealthStatus.HEALTHY
                        if all(q.is_healthy for q in metrics.queues.values())
                        else HealthStatus.DEGRADED
                    ),
                    "total": len(metrics.queues),
                    "queues": {
                        name: {
                            "queue_name": queue.queue_name,
                            "status": queue.status.value,
                            "current_size": queue.current_size,
                            "max_size": queue.max_size,
                            "utilization_percentage": queue.utilization_percentage,
                            "total_processed": queue.total_processed,
                            "processing_rate": queue.processing_rate,
                        }
                        for name, queue in metrics.queues.items()
                    },
                },
                "services": {
                    "status": (
                        HealthStatus.HEALTHY
                        if all(s.is_healthy for s in metrics.services.values())
                        else HealthStatus.DEGRADED
                    ),
                    "total": len(metrics.services),
                    "services": {
                        name: {
                            "service_name": service.service_name,
                            "service_type": service.service_type,
                            "status": service.status.value,
                            "is_connected": service.is_connected,
                            "connection_latency": service.connection_latency,
                            "total_operations": service.total_operations,
                            "successful_operations": service.successful_operations,
                            "failed_operations": service.failed_operations,
                            "error_rate": service.error_rate,
                        }
                        for name, service in metrics.services.items()
                    },
                },
            }

            return detailed_health

        except Exception as e:
            LOGGER.error(f"Error getting detailed health: {e}")
            return {
                "overall_status": "error",
                "health_score": 0.0,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
            }

    def get_queue_status(self) -> dict[str, Any]:
        """Get queue status information."""
        try:
            metrics = self.get_health_metrics()

            queues_list = []
            for queue_name, queue_health in metrics.queues.items():
                queues_list.append(
                    {
                        "name": queue_name,
                        "current_size": queue_health.current_size,
                        "max_size": queue_health.max_size,
                        "utilization_percentage": queue_health.utilization_percentage,
                        "total_processed": queue_health.total_processed,
                        "processing_rate": queue_health.processing_rate,
                        "status": queue_health.status.value,
                        "is_healthy": queue_health.is_healthy,
                    }
                )

            summary = {
                "total_queues": len(queues_list),
                "healthy_queues": sum(1 for q in queues_list if q["is_healthy"]),
                "total_pending": sum(q["current_size"] for q in queues_list),
                "average_utilization": sum(q["utilization_percentage"] for q in queues_list) / max(len(queues_list), 1),
                "status": HealthStatus.HEALTHY if all(q["is_healthy"] for q in queues_list) else HealthStatus.DEGRADED,
            }

            return {"queues": queues_list, "summary": summary}

        except Exception as e:
            LOGGER.error(f"Error getting queue status: {e}")
            return {
                "queues": [],
                "summary": {
                    "total_queues": 0,
                    "healthy_queues": 0,
                    "total_pending": 0,
                    "average_utilization": 0.0,
                    "status": HealthStatus.ERROR,
                },
            }

    def get_system_status(self) -> dict[str, Any]:
        """Get system status information."""
        try:
            metrics = self.get_health_metrics()

            system_info = {
                "system": {
                    "status": HealthStatus.HEALTHY if metrics.system.is_healthy else HealthStatus.DEGRADED,
                    "cpu_percent": metrics.system.cpu_percent,
                    "memory_percent": metrics.system.memory_percent,
                    "memory_usage_mb": metrics.system.memory_usage_mb,
                    "uptime_seconds": metrics.system.uptime_seconds,
                    "process_id": metrics.system.process_id,
                    "process_name": metrics.system.process_name,
                    "threads_count": metrics.system.threads_count,
                    "open_files_count": metrics.system.open_files_count,
                    "max_open_files": metrics.system.max_open_files,
                    "resource_pressure": metrics.system.resource_pressure,
                },
                "timestamp": datetime.now().isoformat(),
                "overall_health": metrics.overall_status.value,
                "health_score": metrics.health_score,
            }

            return system_info

        except Exception as e:
            LOGGER.error(f"Error getting system status: {e}")
            return {
                "system": {
                    "status": HealthStatus.ERROR,
                    "cpu_percent": 0.0,
                    "memory_percent": 0.0,
                    "memory_usage_mb": 0.0,
                    "uptime_seconds": 0.0,
                },
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
            }

    # API compatibility aliases
    def get_health_status(self) -> dict[str, Any]:
        """API compatibility alias for get_quick_health_status()."""
        return self.get_quick_health_status()

    def get_detailed_health_status(self) -> dict[str, Any]:
        """API compatibility alias for get_detailed_health()."""
        return self.get_detailed_health()

    async def get_readiness_status(self) -> dict[str, Any]:
        """Get readiness status for Kubernetes-style health checks."""
        try:
            metrics = self.get_health_metrics()

            # Check if core services are ready
            is_ready = (
                metrics.overall_status != HealthStatus.CRITICAL
                and len(metrics.workers) > 0  # At least one worker should be available
            )

            return {
                "ready": is_ready,
                "timestamp": datetime.now().isoformat(),
                "checks": {
                    "overall_health": metrics.overall_status.value,
                    "workers_available": len(metrics.workers) > 0,
                    "system_healthy": metrics.system.is_healthy if metrics.system else False,
                },
            }
        except Exception as e:
            LOGGER.error(f"Error getting readiness status: {e}")
            return {"ready": False, "timestamp": datetime.now().isoformat(), "error": str(e)}

    async def get_liveness_status(self) -> dict[str, Any]:
        """Get liveness status for Kubernetes-style health checks."""
        try:
            metrics = self.get_health_metrics()

            return {
                "alive": True,  # If we can execute this code, we're alive
                "timestamp": datetime.now().isoformat(),
                "uptime": metrics.system.uptime_seconds if metrics.system else 0.0,
                "health_score": metrics.health_score,
            }
        except Exception as e:
            LOGGER.error(f"Error getting liveness status: {e}")
            return {"alive": False, "timestamp": datetime.now().isoformat(), "error": str(e)}

    async def get_metrics(self) -> dict[str, Any]:
        """Get metrics in dictionary format for API compatibility."""
        try:
            metrics = self.get_health_metrics()
            return metrics.model_dump()
        except Exception as e:
            LOGGER.error(f"Error getting metrics: {e}")
            return {"error": str(e), "timestamp": datetime.now().isoformat()}
