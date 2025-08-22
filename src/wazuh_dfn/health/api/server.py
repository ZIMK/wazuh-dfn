"""Main Health API Server implementation."""

from __future__ import annotations

import asyncio
import logging
import ssl

from wazuh_dfn.config import APIConfig
from wazuh_dfn.health.protocols import APIHealthProvider

try:
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    web = None
    AIOHTTP_AVAILABLE = False

from .handlers import HealthHandlers
from .middleware import SecurityMiddleware

LOGGER = logging.getLogger(__name__)


class HealthAPIServer:
    """HTTP API server for health monitoring endpoints.

    Provides REST API endpoints for health checks, metrics, and status information
    with comprehensive security features including authentication, rate limiting,
    IP allowlists, and HTTPS support.
    """

    def __init__(
        self,
        health_provider: APIHealthProvider,
        api_config: APIConfig,
        shutdown_event: asyncio.Event | None = None,
    ):
        """Initialize the Health API Server.

        Args:
            health_provider: Health service instance or compatible provider
                           that implements the APIHealthProvider protocol
            api_config: API configuration object with all settings
            shutdown_event: Optional shutdown event to listen for server stop
        """
        if not AIOHTTP_AVAILABLE:
            LOGGER.warning("aiohttp is not available, cannot start Health API Server")
            raise ImportError("aiohttp is required for the Health API Server. Install it with: pip install aiohttp")

        # Store the provider directly - handlers will use its interface
        self.health_provider = health_provider
        self.api_config = api_config
        self.shutdown_event = shutdown_event or asyncio.Event()
        self.app = None
        self.runner = None
        self.site = None

        # Initialize components
        self.handlers = HealthHandlers(self.health_provider)
        self.security = SecurityMiddleware(api_config)
        self.rate_limiter = self.security.rate_limiter  # Reference for server info

    def _create_ssl_context(self):
        """Create SSL context for HTTPS if enabled.

        Returns:
            SSL context configured for secure connections, or None if HTTPS disabled
        """
        if not self.api_config.https_enabled:
            return None

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            # Configure TLS settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers("HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!SRP:!CAMELLIA")

            # Load certificate and key
            context.load_cert_chain(str(self.api_config.cert_file), str(self.api_config.key_file))

            LOGGER.info("SSL context created successfully")
            return context

        except Exception as e:
            LOGGER.error(f"Failed to create SSL context: {e}")
            raise

    def _create_app(self):
        """Create and configure the aiohttp application.

        Returns:
            Configured aiohttp Application instance
        """
        # Get middleware in correct order
        middlewares = self.security.get_middlewares()

        app = web.Application(middlewares=middlewares)

        # Register routes
        self.handlers.register_routes(app)

        return app

    async def start(self) -> None:
        """Start the Health API Server.

        Raises:
            RuntimeError: If server is already running or aiohttp is not available
        """
        if not AIOHTTP_AVAILABLE:
            LOGGER.warning("aiohttp is not available, cannot start Health API Server")
            raise RuntimeError("aiohttp is not available")

        if self.runner is not None:
            LOGGER.warning("Health API Server is already running")
            raise RuntimeError("Server is already running")

        try:
            # Create application
            LOGGER.debug("Creating Health API application...")
            self.app = self._create_app()

            # Create runner
            LOGGER.debug("Creating Health API runner...")
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()

            # Configure SSL if enabled
            LOGGER.debug("Configuring SSL context...")
            ssl_context = self._create_ssl_context()

            # Create site
            self.site = web.TCPSite(
                self.runner, host=self.api_config.host, port=self.api_config.port, ssl_context=ssl_context
            )

            LOGGER.debug("Starting Health API Server...")
            await self.site.start()

            protocol = "https" if ssl_context else "http"
            LOGGER.info(f"Health API Server started at {protocol}://{self.api_config.host}: {self.api_config.port}")

            # Keep running until shutdown
            await self.shutdown_event.wait()
        except Exception as e:
            LOGGER.error(f"Failed to start Health API Server: {e}")
            await self.cleanup()
            raise
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop the Health API Server gracefully."""
        LOGGER.info("Stopping Health API Server...")
        await self.cleanup()
        LOGGER.info("Health API Server stopped")

    async def cleanup(self) -> None:
        """Clean up server resources."""
        if self.site:
            await self.site.stop()
            self.site = None

        if self.runner:
            await self.runner.cleanup()
            self.runner = None

        self.app = None

    def is_running(self) -> bool:
        """Check if the server is currently running.

        Returns:
            True if server is running, False otherwise
        """
        return self.runner is not None and self.site is not None

    def get_server_info(self) -> dict:
        """Get information about the server configuration.

        Returns:
            Dictionary with server configuration details
        """
        return {
            "host": self.api_config.host,
            "port": self.api_config.port,
            "https_enabled": self.api_config.https_enabled,
            "authentication_enabled": bool(self.api_config.auth_token),
            "rate_limiting_enabled": bool(self.rate_limiter),
            "ip_allowlist_enabled": set(self.api_config.allowed_ips) != {"127.0.0.1", "::1"},
            "is_running": self.is_running(),
        }
