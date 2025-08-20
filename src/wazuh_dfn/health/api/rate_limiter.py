"""Rate limiting functionality for Health API Server."""

from __future__ import annotations

import time
from collections import defaultdict


class RateLimiter:
    """Simple in-memory rate limiter for API requests.

    Implements a sliding window rate limiter that tracks requests per IP address.
    Thread-safe for async operations within a single event loop.
    """

    def __init__(self, max_requests: int, window_seconds: int = 60):
        """Initialize rate limiter.

        Args:
            max_requests: Maximum number of requests allowed per window
            window_seconds: Time window in seconds (default: 60 for per-minute limiting)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        """Check if request from client IP is allowed based on rate limit.

        Args:
            client_ip: IP address of the client making the request

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old requests outside the current window
        self.requests[client_ip] = [req_time for req_time in self.requests[client_ip] if req_time > window_start]

        # Check if under limit
        if len(self.requests[client_ip]) >= self.max_requests:
            return False

        # Record this request
        self.requests[client_ip].append(now)
        return True

    def get_remaining_requests(self, client_ip: str) -> int:
        """Get number of remaining requests for a client IP.

        Args:
            client_ip: IP address of the client

        Returns:
            Number of requests remaining in current window
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old requests
        self.requests[client_ip] = [req_time for req_time in self.requests[client_ip] if req_time > window_start]

        current_count = len(self.requests[client_ip])
        return max(0, self.max_requests - current_count)

    def reset_client(self, client_ip: str) -> None:
        """Reset rate limit for a specific client IP.

        Args:
            client_ip: IP address to reset
        """
        if client_ip in self.requests:
            del self.requests[client_ip]

    def get_window_reset_time(self, client_ip: str) -> float:
        """Get the time when the rate limit window resets for a client.

        Args:
            client_ip: IP address of the client

        Returns:
            Unix timestamp when the window resets
        """
        if client_ip not in self.requests or not self.requests[client_ip]:
            return time.time()

        # Window resets when the oldest request expires
        oldest_request = min(self.requests[client_ip])
        return oldest_request + self.window_seconds
