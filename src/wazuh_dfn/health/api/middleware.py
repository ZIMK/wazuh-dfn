"""Security middleware for Health API Server."""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiohttp.web import Request, StreamResponse

try:
    from aiohttp import web
    from aiohttp.web import middleware

    AIOHTTP_AVAILABLE = True
except ImportError:
    # Create dummy decorators for type checking
    def middleware(f):
        """Dummy middleware decorator for type checking when aiohttp is not available."""
        return f

    web = None
    AIOHTTP_AVAILABLE = False

from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """Collection of security middleware for the Health API Server."""

    def __init__(self, api_config):
        """Initialize security middleware.

        Args:
            api_config: API configuration object with security settings
        """
        self.api_config = api_config
        self.rate_limiter = (
            RateLimiter(
                max_requests=api_config.rate_limit,
                window_seconds=60,  # Fixed 60-second window as rate_limit is per minute
            )
            if api_config.rate_limit > 0
            else None
        )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.

        Args:
            request: aiohttp request object

        Returns:
            Client IP address as string
        """
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP if there are multiple
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct connection
        return request.remote or "127.0.0.1"

    def _is_ip_allowed(self, client_ip: str) -> bool:
        """Check if client IP is in allowlist.

        Args:
            client_ip: IP address to check

        Returns:
            True if IP is allowed, False otherwise
        """
        if not self.api_config.allowed_ips:
            return True

        try:
            client_addr = ipaddress.ip_address(client_ip)
            for allowed_cidr in self.api_config.allowed_ips:
                allowed_network = ipaddress.ip_network(allowed_cidr, strict=False)
                if client_addr in allowed_network:
                    return True
            return False
        except ValueError as e:
            logger.warning(f"Invalid IP address format: {client_ip}, error: {e}")
            return False

    @middleware
    async def security_headers_middleware(self, request: Request, handler) -> StreamResponse:
        """Add security headers to all responses."""
        response = await handler(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'; object-src 'none'"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        # HSTS header for HTTPS
        if request.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    @middleware
    async def ip_allowlist_middleware(self, request: Request, handler) -> StreamResponse:
        """Check IP allowlist if enabled."""
        # Always check if allowed_ips has more than just localhost
        default_localhost = {"127.0.0.1", "::1"}
        if set(self.api_config.allowed_ips) == default_localhost:
            return await handler(request)

        client_ip = self._get_client_ip(request)

        if not self._is_ip_allowed(client_ip):
            logger.warning(f"Access denied for IP: {client_ip}")
            raise web.HTTPForbidden(text="Access denied: IP not in allowlist")

        return await handler(request)

    @middleware
    async def rate_limiting_middleware(self, request: Request, handler) -> StreamResponse:
        """Apply rate limiting if enabled."""
        if not self.rate_limiter:
            return await handler(request)

        client_ip = self._get_client_ip(request)

        if not self.rate_limiter.is_allowed(client_ip):
            remaining = self.rate_limiter.get_remaining_requests(client_ip)
            reset_time = self.rate_limiter.get_window_reset_time(client_ip)

            logger.warning(f"Rate limit exceeded for IP: {client_ip}")

            response = web.HTTPTooManyRequests(text="Rate limit exceeded")
            response.headers["X-RateLimit-Limit"] = str(self.api_config.rate_limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(int(reset_time))
            response.headers["Retry-After"] = str(60)  # 60 seconds window
            raise response

        return await handler(request)

    @middleware
    async def authentication_middleware(self, request: Request, handler) -> StreamResponse:
        """Check authentication if enabled."""
        if not self.api_config.auth_token:
            return await handler(request)

        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning(f"Missing or invalid authorization header from {self._get_client_ip(request)}")
            raise web.HTTPUnauthorized(text="Authentication required", headers={"WWW-Authenticate": "Bearer"})

        token = auth_header[7:]  # Remove 'Bearer ' prefix

        if token != self.api_config.auth_token:
            logger.warning(f"Invalid token from {self._get_client_ip(request)}")
            raise web.HTTPUnauthorized(text="Invalid authentication token", headers={"WWW-Authenticate": "Bearer"})

        return await handler(request)

    def get_middlewares(self) -> list:
        """Get all configured middleware in the correct order.

        Returns:
            List of middleware functions to be applied by aiohttp
        """
        middlewares = []

        # Order matters: most restrictive first
        # Check if IP allowlist is configured (more than just localhost)
        default_localhost = {"127.0.0.1", "::1"}
        if set(self.api_config.allowed_ips) != default_localhost:
            middlewares.append(self.ip_allowlist_middleware)

        if self.rate_limiter:
            middlewares.append(self.rate_limiting_middleware)

        if self.api_config.auth_token:
            middlewares.append(self.authentication_middleware)

        # Security headers last to ensure they're on all responses
        middlewares.append(self.security_headers_middleware)

        return middlewares
