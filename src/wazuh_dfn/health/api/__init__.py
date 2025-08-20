"""Health API sub-package for REST API implementation.

This package provides Phase 2 REST API Implementation according to TODO_HEALTH_MONITORING.md:
- Production-grade HTTP server with aiohttp
- Modern async patterns with asyncio.Task
- Context management with asynccontextmanager
- Type-safe request handling with Protocol interfaces
- Comprehensive security features
- Optional dependency support (requires pip install wazuh-dfn[health-api])

Package Structure:
- server: Main HealthAPIServer class and server lifecycle management
- middleware: Security middleware (auth, rate limiting, headers)
- handlers: API endpoint handlers for all Phase 2.2 endpoints
- rate_limiter: Rate limiting implementation
"""

from __future__ import annotations

import importlib.util

# Check aiohttp availability
AIOHTTP_AVAILABLE = importlib.util.find_spec("aiohttp") is not None

# Import main components if aiohttp is available
if AIOHTTP_AVAILABLE:
    from .handlers import HealthHandlers
    from .middleware import SecurityMiddleware
    from .rate_limiter import RateLimiter
    from .server import HealthAPIServer  # type: ignore[assignment]

    __all__ = [
        "AIOHTTP_AVAILABLE",
        "HealthAPIServer",
        "HealthHandlers",
        "RateLimiter",
        "SecurityMiddleware",
    ]
else:
    # Provide dummy classes for type checking when aiohttp is not available
    class HealthAPIServer:
        """Dummy HealthAPIServer when aiohttp is not available."""

        def __init__(self, *args, **kwargs):
            raise ImportError("aiohttp is required for HealthAPIServer")

    __all__ = [
        "AIOHTTP_AVAILABLE",
        "HealthAPIServer",
    ]
