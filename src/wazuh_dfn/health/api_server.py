"""HealthAPIServer implementation using aiohttp with modern Python 3.12+ features.

This module provides:
- Production-grade HTTP server with aiohttp
- Modern async patterns with asyncio.TaskGroup
- Context management with asynccontextmanager
- Type-safe request handling with Protocol interfaces
- Comprehensive security features
- Optional dependency support (requires pip install wazuh-dfn[health-api])
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, Protocol

from pydantic import BaseModel, Field

from wazuh_dfn.health.models import HealthMetrics
from wazuh_dfn.service_container import ServiceContainer

# Type checking for optional aiohttp dependency
try:
    from aiohttp import web
    from aiohttp.web import Request, Response, StreamResponse

    AIOHTTP_AVAILABLE = True
except ImportError:
    # Create stub classes for type checking when aiohttp is not available
    AIOHTTP_AVAILABLE = False

    class Request:  # type: ignore[misc]
        """Stub for aiohttp.web.Request when not available."""

        pass

    class Response:  # type: ignore[misc]
        """Stub for aiohttp.web.Response when not available."""

        pass

    class StreamResponse:  # type: ignore[misc]
        """Stub for aiohttp.web.StreamResponse when not available."""

        pass

    class Web:  # type: ignore[misc]
        """Stub for aiohttp.web when not available."""

        @staticmethod
        def application(**kwargs: Any) -> Any:
            """Stub for Application."""
            return None

        @staticmethod
        def app_runner(app: Any) -> Any:
            """Stub for AppRunner."""
            return None

        @staticmethod
        def tcp_site(runner: Any, host: str, port: int) -> Any:
            """Stub for TCPSite."""
            return None


logger = logging.getLogger(__name__)


class HealthProvider(Protocol):
    """Protocol for health metrics providers used by the API server."""

    def get_health_metrics(self) -> HealthMetrics:
        """Get comprehensive health metrics."""
        ...

    def get_quick_health_status(self) -> dict[str, Any]:
        """Get lightweight health status for load balancer checks."""
        ...


class APIConfiguration(BaseModel):
    """Configuration for the Health API server with Python 3.12+ features."""

    # Server settings
    enabled: bool = Field(default=False, description="Enable HTTP server")
    host: str = Field(default="127.0.0.1", description="Server bind address")
    port: int = Field(default=8080, ge=1, le=65535, description="Server port")

    # Security settings
    auth_token: str | None = Field(default=None, description="Optional bearer token")
    allowed_ips: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "::1"], description="Allowed IP addresses/CIDR blocks"
    )

    # Rate limiting
    rate_limit: int = Field(default=100, ge=1, description="Requests per minute limit")

    # TLS settings (future enhancement)
    enable_tls: bool = Field(default=False, description="Enable HTTPS")
    cert_file: str | None = Field(default=None, description="TLS certificate file")
    key_file: str | None = Field(default=None, description="TLS private key file")

    def validate_ip_addresses(self) -> None:
        """Validate that all allowed IPs are valid IPv4/IPv6 addresses or CIDR blocks."""
        for ip_str in self.allowed_ips:
            try:
                # Try parsing as network (CIDR) first, then as individual address
                try:
                    ipaddress.ip_network(ip_str, strict=False)
                except ValueError:
                    ipaddress.ip_address(ip_str)
            except ValueError as e:
                raise ValueError(f"Invalid IP address or CIDR block '{ip_str}': {e}") from e


class RateLimiter:
    """Simple in-memory rate limiter for API requests."""

    def __init__(self, requests_per_minute: int) -> None:
        """Initialize rate limiter.

        Args:
            requests_per_minute: Maximum requests allowed per minute per IP
        """
        self.requests_per_minute = requests_per_minute
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        """Check if request from client IP is allowed.

        Args:
            client_ip: Client IP address

        Returns:
            bool: True if request is allowed, False if rate limited
        """
        now = time.time()
        minute_ago = now - 60.0

        # Clean old requests
        ip_requests = self.requests[client_ip]
        self.requests[client_ip] = [req_time for req_time in ip_requests if req_time > minute_ago]

        # Check current request count
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return False

        # Record this request
        self.requests[client_ip].append(now)
        return True


class SecurityMiddleware:
    """Security middleware for authentication and IP filtering."""

    def __init__(self, config: APIConfiguration) -> None:
        """Initialize security middleware.

        Args:
            config: API configuration with security settings
        """
        self.config = config
        self.allowed_networks = self._parse_allowed_networks()
        self.rate_limiter = RateLimiter(config.rate_limit)

    def _parse_allowed_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse allowed IP addresses/CIDR blocks into network objects."""
        networks = []
        for ip_str in self.config.allowed_ips:
            try:
                # Try as network first
                try:
                    networks.append(ipaddress.ip_network(ip_str, strict=False))
                except ValueError:
                    # Fall back to individual address
                    addr = ipaddress.ip_address(ip_str)
                    if isinstance(addr, ipaddress.IPv4Address):
                        networks.append(ipaddress.IPv4Network(f"{addr}/32"))
                    else:
                        networks.append(ipaddress.IPv6Network(f"{addr}/128"))
            except ValueError:
                logger.warning(f"Invalid IP address/CIDR block: {ip_str}")
        return networks

    def is_ip_allowed(self, client_ip: str) -> bool:
        """Check if client IP is in allowed networks.

        Args:
            client_ip: Client IP address to check

        Returns:
            bool: True if IP is allowed, False otherwise
        """
        try:
            client_addr = ipaddress.ip_address(client_ip)
            return any(client_addr in network for network in self.allowed_networks)
        except ValueError:
            logger.warning(f"Invalid client IP address: {client_ip}")
            return False

    def authenticate_request(self, request: Request) -> bool:
        """Authenticate request using bearer token if configured.

        Args:
            request: HTTP request object

        Returns:
            bool: True if authenticated or no auth required, False otherwise
        """
        if not self.config.auth_token:
            return True  # No authentication required

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False

        token = auth_header[7:]  # Remove "Bearer " prefix
        return token == self.config.auth_token


class HealthAPIServer:
    """Production-grade health monitoring API server using aiohttp.

    Features:
    - Modern async patterns with asyncio.TaskGroup
    - Context management for proper resource cleanup
    - Type-safe request handling
    - Comprehensive security (auth, IP filtering, rate limiting)
    - Prometheus metrics support
    - Optional dependency handling (graceful degradation)
    """

    def __init__(self, config: APIConfiguration, container: ServiceContainer | None = None) -> None:
        """Initialize API server.

        Args:
            config: Server configuration
            container: Service container for dependency injection

        Raises:
            ImportError: If aiohttp is not available but server is enabled
        """
        if config.enabled and not AIOHTTP_AVAILABLE:
            raise ImportError("Health API server requires aiohttp. Install with: pip install wazuh-dfn[health-api]")

        self.config = config
        self.container = container
        if self.container is None:
            raise ValueError("ServiceContainer is required for HealthAPIServer")
        self.security = SecurityMiddleware(config) if config.enabled else None

        # Server state
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._task_group: asyncio.TaskGroup | None = None

        logger.info(f"HealthAPIServer initialized (enabled={config.enabled})")

    @asynccontextmanager
    async def _server_context(self):
        """Async context manager for server lifecycle management."""
        if not self.config.enabled or not AIOHTTP_AVAILABLE:
            logger.info("Health API server disabled or aiohttp not available")
            yield
            return

        try:
            # Create and configure application
            self._app = web.Application()
            self._setup_routes()
            self._setup_middleware()

            # Create runner and site
            self._runner = web.AppRunner(self._app)
            await self._runner.setup()

            self._site = web.TCPSite(self._runner, self.config.host, self.config.port)
            await self._site.start()

            logger.info(f"Health API server started on {self.config.host}:{self.config.port}")
            yield

        finally:
            # Cleanup in reverse order
            if self._site:
                await self._site.stop()
                logger.debug("API server site stopped")

            if self._runner:
                await self._runner.cleanup()
                logger.debug("API server runner cleaned up")

            logger.info("Health API server stopped")

    def _setup_routes(self) -> None:
        """Set up API routes."""
        if not self._app:
            return

        # Health endpoints
        self._app.router.add_get("/health", self._handle_health)
        self._app.router.add_get("/health/detailed", self._handle_detailed_health)

        # General status endpoint
        self._app.router.add_get("/status", self._handle_status)

        # Metrics endpoints
        self._app.router.add_get("/metrics", self._handle_metrics)

        # Detailed status endpoints
        self._app.router.add_get("/status/workers", self._handle_worker_status)
        self._app.router.add_get("/status/queue", self._handle_queue_status)
        self._app.router.add_get("/status/system", self._handle_system_status)

        # Info endpoint
        self._app.router.add_get("/info", self._handle_info)

        logger.debug("API routes configured")

    def _setup_middleware(self) -> None:
        """Set up middleware for security and logging."""
        if not self._app or not self.security:
            return

        @web.middleware
        async def security_middleware(request: Request, handler) -> StreamResponse:
            """Apply security checks to all requests."""
            # Get client IP (handle proxy headers)
            client_ip = self._get_client_ip(request)

            # IP allowlist check
            if not self.security.is_ip_allowed(client_ip):
                logger.warning(f"Blocked request from disallowed IP: {client_ip}")
                return web.Response(status=403, text="Forbidden")

            # Rate limiting check
            if not self.security.rate_limiter.is_allowed(client_ip):
                logger.warning(f"Rate limited request from IP: {client_ip}")
                return web.Response(status=429, text="Too Many Requests")

            # Authentication check
            if not self.security.authenticate_request(request):
                logger.warning(f"Unauthenticated request from IP: {client_ip}")
                return web.Response(status=401, text="Unauthorized")

            # Request allowed, proceed
            return await handler(request)

        self._app.middlewares.append(security_middleware)
        logger.debug("Security middleware configured")

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address, handling proxy headers.

        Args:
            request: HTTP request object

        Returns:
            str: Client IP address
        """
        # Check for proxy headers (in order of preference)
        for header in ["X-Forwarded-For", "X-Real-IP", "X-Client-IP"]:
            if header in request.headers:
                # X-Forwarded-For can contain multiple IPs, take the first
                ip = request.headers[header].split(",")[0].strip()
                if ip:
                    return ip

        # Fall back to direct connection info
        return request.remote or "unknown"

    async def _handle_health(self, request: Request) -> Response:
        """Handle GET /health - quick health check for load balancers.

        Args:
            request: HTTP request object

        Returns:
            Response: JSON response with basic health status
        """
        try:
            health_provider = self._get_health_provider()
            if not health_provider:
                return web.Response(
                    status=503,
                    content_type="application/json",
                    text=json.dumps({"status": "ERROR", "message": "Health provider not available"}),
                )

            status = health_provider.get_quick_health_status()
            return web.Response(status=200, content_type="application/json", text=json.dumps(status))

        except Exception as e:
            logger.error(f"Error in health endpoint: {e}")
            return web.Response(
                status=500,
                content_type="application/json",
                text=json.dumps({"status": "ERROR", "message": "Internal server error"}),
            )

    async def _handle_detailed_health(self, request: Request) -> Response:
        """Handle GET /health/detailed - comprehensive health metrics.

        Args:
            request: HTTP request object

        Returns:
            Response: JSON response with detailed health metrics
        """
        try:
            health_provider = self._get_health_provider()
            if not health_provider:
                return web.Response(
                    status=503,
                    content_type="application/json",
                    text=json.dumps({"error": "Health provider not available"}),
                )

            metrics = health_provider.get_health_metrics()
            return web.Response(status=200, content_type="application/json", text=json.dumps(metrics.to_json_dict()))

        except Exception as e:
            logger.error(f"Error in detailed health endpoint: {e}")
            return web.Response(
                status=500, content_type="application/json", text=json.dumps({"error": "Internal server error"})
            )

    async def _handle_status(self, request: Request) -> Response:
        """Handle GET /status - general system status information.

        Args:
            request: HTTP request object

        Returns:
            Response: System status with health metrics
        """
        try:
            health_provider = self._get_health_provider()
            if not health_provider:
                return web.Response(
                    status=503,
                    content_type="application/json",
                    text=json.dumps({"status": "UNAVAILABLE", "error": "Health provider not available"}),
                )

            metrics = health_provider.get_health_metrics()
            return web.Response(
                status=200, content_type="application/json", text=json.dumps(metrics.model_dump(), default=str)
            )

        except Exception as e:
            logger.error(f"Error in status endpoint: {e}")
            return web.Response(
                status=500, content_type="application/json", text=json.dumps({"error": "Internal server error"})
            )

    async def _handle_metrics(self, request: Request) -> Response:
        """Handle GET /metrics - Prometheus-style metrics.

        Args:
            request: HTTP request object

        Returns:
            Response: Prometheus exposition format metrics
        """
        try:
            health_provider = self._get_health_provider()
            if not health_provider:
                return web.Response(status=503, content_type="text/plain", text="# Health provider not available\n")

            metrics = health_provider.get_health_metrics()
            prometheus_metrics = self._format_prometheus_metrics(metrics)

            return web.Response(
                status=200, content_type="text/plain; version=0.0.4", text=prometheus_metrics, charset="utf-8"
            )

        except Exception as e:
            logger.error(f"Error in metrics endpoint: {e}")
            return web.Response(status=500, content_type="text/plain", text="# Error generating metrics\n")

    async def _handle_worker_status(self, request: Request) -> Response:
        """Handle GET /status/workers - worker-specific metrics."""
        # Implementation will be added in next step
        return web.Response(
            status=501,
            content_type="application/json",
            text=json.dumps({"message": "Worker status endpoint not implemented yet"}),
        )

    async def _handle_queue_status(self, request: Request) -> Response:
        """Handle GET /status/queue - queue-specific metrics."""
        # Implementation will be added in next step
        return web.Response(
            status=501,
            content_type="application/json",
            text=json.dumps({"message": "Queue status endpoint not implemented yet"}),
        )

    async def _handle_system_status(self, request: Request) -> Response:
        """Handle GET /status/system - system resource metrics."""
        # Implementation will be added in next step
        return web.Response(
            status=501,
            content_type="application/json",
            text=json.dumps({"message": "System status endpoint not implemented yet"}),
        )

    async def _handle_info(self, request: Request) -> Response:
        """Handle GET /info - API server information."""
        info = {
            "server": "wazuh-dfn Health API",
            "version": "1.0.0",  # Will be dynamic later
            "endpoints": [
                "/health",
                "/health/detailed",
                "/metrics",
                "/status/workers",
                "/status/queue",
                "/status/system",
                "/info",
            ],
            "timestamp": time.time(),
        }

        return web.Response(status=200, content_type="application/json", text=json.dumps(info))

    def _get_health_provider(self) -> HealthProvider | None:
        """Get health provider from service container.

        Returns:
            HealthProvider | None: Health provider instance or None if not available
        """
        try:
            # Try to get the HealthService from the container
            if self.container.has_service("health_service"):
                health_service = self.container.get_service("health_service")
                # Check if it implements our protocol
                if hasattr(health_service, "get_health_metrics") and hasattr(health_service, "get_quick_health_status"):
                    return health_service

            logger.debug("HealthService not found in container")
            return None
        except Exception as e:
            logger.error(f"Error getting health provider: {e}")
            return None

    def _format_prometheus_metrics(self, metrics: HealthMetrics) -> str:
        """Format health metrics in Prometheus exposition format.

        Args:
            metrics: Health metrics to format

        Returns:
            str: Prometheus-formatted metrics
        """
        lines = [
            "# HELP wazuh_dfn_system_health_score Overall system health score (0-1)",
            "# TYPE wazuh_dfn_system_health_score gauge",
            f"wazuh_dfn_system_health_score {metrics.system.system_health_score}",
            "",
            "# HELP wazuh_dfn_system_operational System operational status (1=operational, 0=down)",
            "# TYPE wazuh_dfn_system_operational gauge",
            f"wazuh_dfn_system_operational {1 if metrics.system.is_operational else 0}",
            "",
            "# HELP wazuh_dfn_workers_total Total number of workers",
            "# TYPE wazuh_dfn_workers_total gauge",
            f"wazuh_dfn_workers_total {metrics.system.total_workers}",
            "",
            "# HELP wazuh_dfn_workers_healthy Number of healthy workers",
            "# TYPE wazuh_dfn_workers_healthy gauge",
            f"wazuh_dfn_workers_healthy {metrics.system.healthy_workers}",
            "",
            "# HELP wazuh_dfn_critical_issues Number of critical issues",
            "# TYPE wazuh_dfn_critical_issues gauge",
            f"wazuh_dfn_critical_issues {metrics.system.critical_issues}",
            "",
            "# HELP wazuh_dfn_data_quality_score Data collection quality score (0-1)",
            "# TYPE wazuh_dfn_data_quality_score gauge",
            f"wazuh_dfn_data_quality_score {metrics.data_quality_score}",
            "",
        ]

        return "\n".join(lines)

    async def start(self) -> None:
        """Start the API server with modern async patterns."""
        if not self.config.enabled:
            logger.info("Health API server is disabled")
            return

        if not AIOHTTP_AVAILABLE:
            logger.error(
                "Cannot start Health API server: aiohttp not available. Install with: pip install wazuh-dfn[health-api]"
            )
            return

        async with asyncio.TaskGroup() as tg:
            self._task_group = tg
            async with self._server_context():
                # Server is now running, this will block until cancelled
                try:
                    # Keep the server running indefinitely
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    logger.info("API server task cancelled")
                    raise

    async def stop(self) -> None:
        """Stop the API server gracefully."""
        if self._task_group:
            # The context manager will handle cleanup
            logger.info("Stopping Health API server...")
        else:
            logger.debug("API server was not running")


# Factory function for easy server creation
def create_health_api_server(
    enabled: bool = False,
    host: str = "127.0.0.1",
    port: int = 8080,
    auth_token: str | None = None,
    allowed_ips: list[str] | None = None,
    rate_limit: int = 100,
    container: ServiceContainer | None = None,
) -> HealthAPIServer:
    """Factory function to create a configured HealthAPIServer.

    Args:
        enabled: Whether to enable the server
        host: Server bind address
        port: Server port
        auth_token: Optional bearer token for authentication
        allowed_ips: List of allowed IP addresses/CIDR blocks
        rate_limit: Requests per minute limit
        container: Service container for dependency injection

    Returns:
        HealthAPIServer: Configured server instance
    """
    config = APIConfiguration(
        enabled=enabled,
        host=host,
        port=port,
        auth_token=auth_token,
        allowed_ips=allowed_ips or ["127.0.0.1", "::1"],
        rate_limit=rate_limit,
    )

    # Validate configuration
    if enabled:
        config.validate_ip_addresses()

    return HealthAPIServer(config, container)
