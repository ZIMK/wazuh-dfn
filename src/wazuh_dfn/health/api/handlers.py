"""API endpoint handlers for Health API Server."""

from __future__ import annotations

import logging
from importlib.metadata import version
from typing import TYPE_CHECKING

from wazuh_dfn.health.models import HealthMetrics, HealthStatus
from wazuh_dfn.health.protocols import APIHealthProvider

if TYPE_CHECKING:
    from aiohttp.web import Request, Response

try:
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    web = None
    AIOHTTP_AVAILABLE = False

LOGGER = logging.getLogger(__name__)


class HealthHandlers:
    """HTTP endpoint handlers for health monitoring API.

    Provides handlers for all health check endpoints including basic health,
    detailed metrics, system status, and API information.
    """

    def __init__(self, health_service: APIHealthProvider):
        """Initialize handlers with health provider.

        Args:
            health_service: Health provider instance that implements APIHealthProvider protocol
        """
        self.health_service = health_service

    def register_routes(self, app):
        """Register all API routes with the application.

        Args:
            app: aiohttp Application instance
        """
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for API routes")

        # Phase 2.1 Basic API routes
        app.router.add_get("/health", self.health_basic_handler)
        app.router.add_get("/health/detailed", self.health_detailed_handler)
        app.router.add_get("/metrics", self.metrics_handler)
        app.router.add_get("/status/workers", self.worker_status_handler)
        app.router.add_get("/status/queue", self.queue_status_handler)
        app.router.add_get("/status/system", self.system_status_handler)
        app.router.add_get("/api/info", self.api_info_handler)

    def health_basic_handler(self, request: Request) -> Response:
        """Handle basic health check endpoint.

        Returns:
            JSON response with basic health status
        """
        try:
            # Get basic health status
            health_data = self.health_service.get_health_status()

            LOGGER.debug(f"Health check successful: {health_data}")

            # Determine status code based on health
            status_value = health_data.get("status", HealthStatus.ERROR)
            if status_value == HealthStatus.HEALTHY:
                status_code = 200
            elif status_value == HealthStatus.DEGRADED:
                status_code = 200  # Still operational
            else:
                status_code = 503

            return web.json_response(health_data, status=status_code)

        except Exception as e:
            LOGGER.exception(f"Error in basic health check: {e}", exc_info=True)
            return web.json_response(
                {"status": HealthStatus.ERROR, "message": "Health check failed", "timestamp": ""}, status=500
            )

    def health_detailed_handler(self, request: Request) -> Response:
        """Handle detailed health metrics endpoint.

        Returns:
            JSON response with detailed health metrics
        """
        try:
            # Get detailed health metrics
            health_data = self.health_service.get_detailed_health_status()

            # Determine status code based on health
            if health_data.get("overall_status") == HealthStatus.HEALTHY:
                status_code = 200
            elif health_data.get("overall_status") == HealthStatus.DEGRADED:
                status_code = 200  # Still operational
            else:
                status_code = 503

            return web.json_response(health_data, status=status_code)

        except Exception as e:
            LOGGER.exception(f"Error in detailed health check: {e}", exc_info=True)
            return web.json_response(
                {"status": HealthStatus.ERROR, "message": "Detailed health check failed", "timestamp": ""}, status=500
            )

    def metrics_handler(self, request: Request) -> Response:
        """Handle Prometheus metrics endpoint.

        Returns:
            Plain text response with Prometheus metrics
        """
        try:
            # Get metrics from health service
            metrics_data = self.health_service.get_health_metrics()

            # Convert to Prometheus format
            prometheus_metrics = self._format_prometheus_metrics(metrics_data)

            return web.Response(text=prometheus_metrics, content_type="text/plain")

        except Exception as e:
            LOGGER.exception(f"Error in metrics endpoint: {e}", exc_info=True)
            return web.json_response(
                {"status": HealthStatus.ERROR, "message": "Metrics collection failed", "timestamp": ""}, status=500
            )

    def worker_status_handler(self, request: Request) -> Response:
        """Handle worker status endpoint.

        Returns:
            JSON response with worker status information
        """
        try:
            # Get worker status from health service
            worker_data = self.health_service.get_worker_status()

            return web.json_response(worker_data, status=200)

        except Exception as e:
            LOGGER.exception(f"Error in worker status endpoint: {e}", exc_info=True)
            return web.json_response(
                {"status": HealthStatus.ERROR, "message": "Worker status check failed", "timestamp": ""}, status=500
            )

    def queue_status_handler(self, request: Request) -> Response:
        """Handle queue status endpoint.

        Returns:
            JSON response with queue status information
        """
        try:
            # Get queue status from health service
            queue_data = self.health_service.get_queue_status()

            return web.json_response(queue_data, status=200)

        except Exception as e:
            LOGGER.exception(f"Error in queue status endpoint: {e}", exc_info=True)
            return web.json_response(
                {"status": HealthStatus.ERROR, "message": "Queue status check failed", "timestamp": ""}, status=500
            )

    def system_status_handler(self, request: Request) -> Response:
        """Handle system status endpoint.

        Returns:
            JSON response with system status information
        """
        try:
            # Get system status from health service
            system_data = self.health_service.get_system_status()

            return web.json_response(system_data, status=200)

        except Exception as e:
            LOGGER.exception(f"Error in system status endpoint: {e}", exc_info=True)
            return web.json_response(
                {"status": HealthStatus.ERROR, "message": "System status check failed", "timestamp": ""}, status=500
            )

    def api_info_handler(self, request: Request) -> Response:
        """Handle API information endpoint.

        Returns:
            JSON response with API version and capabilities
        """
        try:
            api_info = {
                "api_version": version("wazuh-dfn"),
                "server": "Wazuh DFN Health API",
                "capabilities": [
                    "health_checks",
                    "detailed_metrics",
                    "prometheus_metrics",
                    "worker_status",
                    "queue_status",
                    "system_status",
                ],
                "endpoints": {
                    "health": "/health",
                    "detailed_health": "/health/detailed",
                    "metrics": "/metrics",
                    "worker_status": "/status/workers",
                    "queue_status": "/status/queue",
                    "system_status": "/status/system",
                    "api_info": "/api/info",
                },
            }

            return web.json_response(api_info, status=200)

        except Exception as e:
            LOGGER.exception(f"Error in API info endpoint: {e}", exc_info=True)
            return web.json_response(
                {"status": HealthStatus.ERROR, "message": "API info request failed", "timestamp": ""}, status=500
            )

    def _format_prometheus_metrics(self, metrics_data: HealthMetrics) -> str:
        """Format metrics data as Prometheus exposition format.

        Args:
            metrics_data: HealthMetrics object to format

        Returns:
            Prometheus-formatted metrics string
        """
        lines = []

        # Overall health metrics
        lines.append("# HELP health_score Overall health score")
        lines.append("# TYPE health_score gauge")

        if metrics_data.health_score:
            lines.append(f"health_score {metrics_data.health_score}")
        else:
            LOGGER.warning("Health score is not available, using default value of 0")
            lines.append("health_score 0")

        lines.append("# HELP overall_status Overall system status (0=healthy, 1=degraded, 2=critical)")
        lines.append("# TYPE overall_status gauge")
        status_map = {HealthStatus.HEALTHY: 0, HealthStatus.DEGRADED: 1, HealthStatus.CRITICAL: 2}
        status_value = status_map.get(metrics_data.overall_status, 2)
        lines.append(f"overall_status {status_value}")

        # System metrics
        if metrics_data.system:
            lines.append("# HELP system_cpu_percent CPU usage percentage")
            lines.append("# TYPE system_cpu_percent gauge")
            lines.append(f"system_cpu_percent {metrics_data.system.cpu_percent}")

            lines.append("# HELP system_memory_percent Memory usage percentage")
            lines.append("# TYPE system_memory_percent gauge")
            lines.append(f"system_memory_percent {metrics_data.system.memory_percent}")

            lines.append("# HELP system_memory_usage_mb Memory usage in MB")
            lines.append("# TYPE system_memory_usage_mb gauge")
            lines.append(f"system_memory_usage_mb {metrics_data.system.memory_usage_mb}")

            lines.append("# HELP system_uptime_seconds System uptime in seconds")
            lines.append("# TYPE system_uptime_seconds gauge")
            lines.append(f"system_uptime_seconds {metrics_data.system.uptime_seconds}")

            lines.append("# HELP system_open_files_count Number of open files")
            lines.append("# TYPE system_open_files_count gauge")
            lines.append(f"system_open_files_count {metrics_data.system.open_files_count}")

            lines.append("# HELP system_threads_count Number of threads")
            lines.append("# TYPE system_threads_count gauge")
            lines.append(f"system_threads_count {metrics_data.system.threads_count}")

        # Worker metrics
        lines.append("# HELP worker_alerts_processed Total alerts processed by worker")
        lines.append("# TYPE worker_alerts_processed counter")
        for worker_name, worker in metrics_data.workers.items():
            lines.append(f'worker_alerts_processed{{worker="{worker_name}"}} {worker.alerts_processed}')

        lines.append("# HELP worker_processing_rate Worker processing rate")
        lines.append("# TYPE worker_processing_rate gauge")
        for worker_name, worker in metrics_data.workers.items():
            lines.append(f'worker_processing_rate{{worker="{worker_name}"}} {worker.processing_rate}')

        lines.append("# HELP worker_health_score Worker health score")
        lines.append("# TYPE worker_health_score gauge")
        for worker_name, worker in metrics_data.workers.items():
            lines.append(f'worker_health_score{{worker="{worker_name}"}} {worker.health_score}')

        # Queue metrics
        lines.append("# HELP queue_current_size Current queue size")
        lines.append("# TYPE queue_current_size gauge")
        for queue_name, queue in metrics_data.queues.items():
            lines.append(f'queue_current_size{{queue="{queue_name}"}} {queue.current_size}')

        lines.append("# HELP queue_utilization_percentage Queue utilization percentage")
        lines.append("# TYPE queue_utilization_percentage gauge")
        for queue_name, queue in metrics_data.queues.items():
            lines.append(f'queue_utilization_percentage{{queue="{queue_name}"}} {queue.utilization_percentage}')

        lines.append("# HELP queue_total_processed Total processed items")
        lines.append("# TYPE queue_total_processed counter")
        for queue_name, queue in metrics_data.queues.items():
            lines.append(f'queue_total_processed{{queue="{queue_name}"}} {queue.total_processed}')

        # Service metrics
        lines.append("# HELP service_is_connected Service connection status")
        lines.append("# TYPE service_is_connected gauge")
        for service_name, service in metrics_data.services.items():
            connection_value = 1 if service.is_connected else 0
            lines.append(
                f'service_is_connected{{service="{service_name}",' f'type="{service.service_type}"}} {connection_value}'
            )

        lines.append("# HELP service_total_operations Total service operations")
        lines.append("# TYPE service_total_operations counter")
        for service_name, service in metrics_data.services.items():
            lines.append(
                f'service_total_operations{{service="{service_name}",'
                f'type="{service.service_type}"}} {service.total_operations}'
            )

        lines.append("# HELP service_error_rate Service error rate percentage")
        lines.append("# TYPE service_error_rate gauge")
        for service_name, service in metrics_data.services.items():
            lines.append(
                f'service_error_rate{{service="{service_name}"' f',type="{service.service_type}"}} {service.error_rate}'
            )

        return "\n".join(lines) + "\n"
