"""API endpoint handlers for Health API Server."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiohttp.web import Request, Response

try:
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    web = None
    AIOHTTP_AVAILABLE = False

logger = logging.getLogger(__name__)


class HealthHandlers:
    """HTTP endpoint handlers for health monitoring API.

    Provides handlers for all health check endpoints including basic health,
    detailed metrics, system status, and API information.
    """

    def __init__(self, health_provider):
        """Initialize handlers with health provider.

        Args:
            health_provider: Health provider instance for status checks
        """
        self.health_provider = health_provider

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

    async def health_basic_handler(self, request: Request) -> Response:
        """Handle basic health check endpoint.

        Returns:
            JSON response with basic health status
        """
        try:
            # Get basic health status
            health_data = await self.health_provider.get_health_status()

            # Determine status code based on health
            if health_data.get("status") == "healthy":
                status_code = 200
            elif health_data.get("status") == "degraded":
                status_code = 200  # Still operational
            else:
                status_code = 503

            return web.json_response(health_data, status=status_code)

        except Exception as e:
            logger.error(f"Error in basic health check: {e}")
            return web.json_response({"status": "error", "message": "Health check failed", "timestamp": ""}, status=500)

    async def health_detailed_handler(self, request: Request) -> Response:
        """Handle detailed health metrics endpoint.

        Returns:
            JSON response with detailed health metrics
        """
        try:
            # Get detailed health metrics
            health_data = await self.health_provider.get_detailed_health()

            # Determine status code based on health
            if health_data.get("overall_status") == "healthy":
                status_code = 200
            elif health_data.get("overall_status") == "degraded":
                status_code = 200  # Still operational
            else:
                status_code = 503

            return web.json_response(health_data, status=status_code)

        except Exception as e:
            logger.error(f"Error in detailed health check: {e}")
            return web.json_response(
                {"status": "error", "message": "Detailed health check failed", "timestamp": ""}, status=500
            )

    async def metrics_handler(self, request: Request) -> Response:
        """Handle Prometheus metrics endpoint.

        Returns:
            Plain text response with Prometheus metrics
        """
        try:
            # Get metrics from health provider
            metrics_data = await self.health_provider.get_metrics()

            # Convert to Prometheus format
            prometheus_metrics = self._format_prometheus_metrics(metrics_data)

            return web.Response(text=prometheus_metrics, content_type="text/plain")

        except Exception as e:
            logger.error(f"Error in metrics endpoint: {e}")
            return web.json_response(
                {"status": "error", "message": "Metrics collection failed", "timestamp": ""}, status=500
            )

    async def worker_status_handler(self, request: Request) -> Response:
        """Handle worker status endpoint.

        Returns:
            JSON response with worker status information
        """
        try:
            # Get worker status from health provider
            worker_data = await self.health_provider.get_worker_status()

            return web.json_response(worker_data, status=200)

        except Exception as e:
            logger.error(f"Error in worker status endpoint: {e}")
            return web.json_response(
                {"status": "error", "message": "Worker status check failed", "timestamp": ""}, status=500
            )

    async def queue_status_handler(self, request: Request) -> Response:
        """Handle queue status endpoint.

        Returns:
            JSON response with queue status information
        """
        try:
            # Get queue status from health provider
            queue_data = await self.health_provider.get_queue_status()

            return web.json_response(queue_data, status=200)

        except Exception as e:
            logger.error(f"Error in queue status endpoint: {e}")
            return web.json_response(
                {"status": "error", "message": "Queue status check failed", "timestamp": ""}, status=500
            )

    async def system_status_handler(self, request: Request) -> Response:
        """Handle system status endpoint.

        Returns:
            JSON response with system status information
        """
        try:
            # Get system status from health provider
            system_data = await self.health_provider.get_system_status()

            return web.json_response(system_data, status=200)

        except Exception as e:
            logger.error(f"Error in system status endpoint: {e}")
            return web.json_response(
                {"status": "error", "message": "System status check failed", "timestamp": ""}, status=500
            )

    def api_info_handler(self, request: Request) -> Response:
        """Handle API information endpoint.

        Returns:
            JSON response with API version and capabilities
        """
        try:
            api_info = {
                "api_version": "2.1",
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
            logger.error(f"Error in API info endpoint: {e}")
            return web.json_response(
                {"status": "error", "message": "API info request failed", "timestamp": ""}, status=500
            )

    def _format_prometheus_metrics(self, metrics_data: dict) -> str:
        """Format metrics data as Prometheus exposition format.

        Args:
            metrics_data: Dictionary of metrics to format

        Returns:
            Prometheus-formatted metrics string
        """
        lines = []

        for metric_name, metric_value in metrics_data.items():
            if isinstance(metric_value, (int, float)):
                # Simple numeric metric
                lines.append(f"wazuh_dfn_{metric_name} {metric_value}")
            elif isinstance(metric_value, dict):
                # Complex metric with labels
                for sub_key, sub_value in metric_value.items():
                    if isinstance(sub_value, (int, float)):
                        lines.append(f'wazuh_dfn_{metric_name}{{type="{sub_key}"}} {sub_value}')

        return "\n".join(lines) + "\n"
