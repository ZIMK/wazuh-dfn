"""Tests for wazuh_dfn.health.api.rate_limiter module."""

import time
from unittest.mock import patch

import pytest

from wazuh_dfn.health.api.rate_limiter import RateLimiter


@pytest.fixture
def rate_limiter():
    """Create a standard RateLimiter instance for testing."""
    return RateLimiter(max_requests=10, window_seconds=60)


@pytest.fixture
def small_rate_limiter():
    """Create a RateLimiter with small limits for testing."""
    return RateLimiter(max_requests=2, window_seconds=60)


@pytest.fixture
def short_window_rate_limiter():
    """Create a RateLimiter with short window for testing."""
    return RateLimiter(max_requests=3, window_seconds=1)


def test_rate_limiter_initialization():
    """Test rate limiter initialization."""
    rate_limiter = RateLimiter(max_requests=10, window_seconds=60)

    assert rate_limiter.max_requests == 10
    assert rate_limiter.window_seconds == 60
    assert isinstance(rate_limiter.requests, dict)


def test_rate_limiter_default_window():
    """Test rate limiter with default window."""
    rate_limiter = RateLimiter(max_requests=5)

    assert rate_limiter.max_requests == 5
    assert rate_limiter.window_seconds == 60  # Default


def test_is_allowed_first_request(rate_limiter):
    """Test that first request is always allowed."""
    client_ip = "192.168.1.100"

    assert rate_limiter.is_allowed(client_ip) is True
    assert len(rate_limiter.requests[client_ip]) == 1


def test_is_allowed_within_limit(small_rate_limiter):
    """Test requests within the rate limit."""
    client_ip = "192.168.1.100"

    # First 2 requests should be allowed
    for _ in range(2):
        assert small_rate_limiter.is_allowed(client_ip) is True

    assert len(small_rate_limiter.requests[client_ip]) == 2


def test_is_allowed_exceeds_limit(small_rate_limiter):
    """Test request that exceeds rate limit."""
    client_ip = "192.168.1.100"

    # First 2 requests should be allowed
    assert small_rate_limiter.is_allowed(client_ip) is True
    assert small_rate_limiter.is_allowed(client_ip) is True

    # Third request should be denied
    assert small_rate_limiter.is_allowed(client_ip) is False

    # Should still have 2 recorded requests
    assert len(small_rate_limiter.requests[client_ip]) == 2


def test_is_allowed_different_ips(small_rate_limiter):
    """Test that different IPs have separate rate limits."""
    ip1 = "192.168.1.100"
    ip2 = "192.168.1.101"

    # Use up the limit for ip1
    assert small_rate_limiter.is_allowed(ip1) is True
    assert small_rate_limiter.is_allowed(ip1) is True
    assert small_rate_limiter.is_allowed(ip1) is False

    # ip2 should still be allowed
    assert small_rate_limiter.is_allowed(ip2) is True
    assert small_rate_limiter.is_allowed(ip2) is True

    assert len(small_rate_limiter.requests[ip1]) == 2
    assert len(small_rate_limiter.requests[ip2]) == 2


def test_window_cleanup():
    """Test that old requests are cleaned up."""
    rate_limiter = RateLimiter(max_requests=2, window_seconds=1)  # 2 requests, 1 second window
    client_ip = "192.168.1.100"

    with patch("time.time") as mock_time:
        # Time = 0: First request
        mock_time.return_value = 0.0
        assert rate_limiter.is_allowed(client_ip) is True

        # Time = 0.5: Second request
        mock_time.return_value = 0.5
        assert rate_limiter.is_allowed(client_ip) is True

        # Time = 0.8: Third request (should be denied - within window)
        mock_time.return_value = 0.8
        assert rate_limiter.is_allowed(client_ip) is False

        # Time = 2.0: Request after window (should be allowed)
        mock_time.return_value = 2.0
        assert rate_limiter.is_allowed(client_ip) is True

        # Should only have 1 request recorded (old ones cleaned up)
        assert len(rate_limiter.requests[client_ip]) == 1


def test_get_remaining_requests():
    """Test remaining requests calculation."""
    rate_limiter = RateLimiter(max_requests=5, window_seconds=60)
    client_ip = "192.168.1.100"

    # Initially, all requests are available
    assert rate_limiter.get_remaining_requests(client_ip) == 5

    # After 2 requests, 3 should remain
    rate_limiter.is_allowed(client_ip)
    rate_limiter.is_allowed(client_ip)
    assert rate_limiter.get_remaining_requests(client_ip) == 3

    # After hitting the limit, 0 should remain
    rate_limiter.is_allowed(client_ip)
    rate_limiter.is_allowed(client_ip)
    rate_limiter.is_allowed(client_ip)
    assert rate_limiter.get_remaining_requests(client_ip) == 0


def test_get_remaining_requests_with_cleanup():
    """Test remaining requests calculation with window cleanup."""
    rate_limiter = RateLimiter(max_requests=3, window_seconds=1)
    client_ip = "192.168.1.100"

    with patch("time.time") as mock_time:
        # Time = 0: Make 2 requests
        mock_time.return_value = 0.0
        rate_limiter.is_allowed(client_ip)
        rate_limiter.is_allowed(client_ip)
        assert rate_limiter.get_remaining_requests(client_ip) == 1

        # Time = 2.0: Old requests expired
        mock_time.return_value = 2.0
        assert rate_limiter.get_remaining_requests(client_ip) == 3


def test_reset_client(small_rate_limiter):
    """Test resetting rate limit for a specific client."""
    client_ip = "192.168.1.100"

    # Use up the limit
    small_rate_limiter.is_allowed(client_ip)
    small_rate_limiter.is_allowed(client_ip)
    assert small_rate_limiter.is_allowed(client_ip) is False

    # Reset the client
    small_rate_limiter.reset_client(client_ip)

    # Should be removed from tracking
    assert client_ip not in small_rate_limiter.requests

    # Should be able to make requests again
    assert small_rate_limiter.is_allowed(client_ip) is True


def test_reset_client_nonexistent():
    """Test resetting rate limit for a client that doesn't exist."""
    rate_limiter = RateLimiter(max_requests=2, window_seconds=60)

    # Should not raise an exception
    rate_limiter.reset_client("nonexistent-ip")


def test_get_window_reset_time():
    """Test window reset time calculation."""
    rate_limiter = RateLimiter(max_requests=2, window_seconds=60)
    client_ip = "192.168.1.100"

    with patch("time.time") as mock_time:
        current_time = 1000.0
        mock_time.return_value = current_time

        # Make a request
        rate_limiter.is_allowed(client_ip)

        # Reset time should be current time + window
        reset_time = rate_limiter.get_window_reset_time(client_ip)
        assert abs(reset_time - (current_time + 60)) < 0.01


def test_get_window_reset_time_no_requests():
    """Test window reset time for client with no requests."""
    rate_limiter = RateLimiter(max_requests=2, window_seconds=60)
    client_ip = "192.168.1.100"

    with patch("time.time") as mock_time:
        current_time = 1000.0
        mock_time.return_value = current_time

        # Should return current time if no requests
        reset_time = rate_limiter.get_window_reset_time(client_ip)
        assert abs(reset_time - current_time) < 0.01


def test_get_window_reset_time_multiple_requests():
    """Test window reset time with multiple requests."""
    rate_limiter = RateLimiter(max_requests=3, window_seconds=60)
    client_ip = "192.168.1.100"

    with patch("time.time") as mock_time:
        # Make requests at different times
        mock_time.return_value = 1000.0
        rate_limiter.is_allowed(client_ip)

        mock_time.return_value = 1010.0
        rate_limiter.is_allowed(client_ip)

        mock_time.return_value = 1020.0
        rate_limiter.is_allowed(client_ip)

        # Reset time should be based on oldest request
        reset_time = rate_limiter.get_window_reset_time(client_ip)
        assert abs(reset_time - (1000.0 + 60)) < 0.01  # oldest + window


def test_concurrent_access_simulation():
    """Test rate limiter behavior under concurrent access simulation."""
    rate_limiter = RateLimiter(max_requests=10, window_seconds=60)
    client_ip = "192.168.1.100"

    # Simulate rapid requests
    allowed_count = 0
    denied_count = 0

    for _ in range(15):  # More than the limit
        if rate_limiter.is_allowed(client_ip):
            allowed_count += 1
        else:
            denied_count += 1

    assert allowed_count == 10  # Should allow exactly max_requests
    assert denied_count == 5  # Should deny the rest


def test_edge_case_zero_limit():
    """Test rate limiter with zero limit."""
    rate_limiter = RateLimiter(max_requests=0, window_seconds=60)
    client_ip = "192.168.1.100"

    # All requests should be denied
    assert rate_limiter.is_allowed(client_ip) is False
    assert rate_limiter.get_remaining_requests(client_ip) == 0


def test_edge_case_very_short_window():
    """Test rate limiter with very short window."""
    rate_limiter = RateLimiter(max_requests=2, window_seconds=1)
    client_ip = "192.168.1.100"

    # First request should be allowed
    assert rate_limiter.is_allowed(client_ip) is True

    # After a short sleep, should be allowed again
    time.sleep(0.2)
    assert rate_limiter.is_allowed(client_ip) is True


@pytest.mark.parametrize(
    "max_requests,window_seconds",
    [
        (1, 10),
        (5, 30),
        (100, 3600),
        (1000, 86400),
    ],
)
def test_parametrized_rate_limiter_configs(max_requests, window_seconds):
    """Test rate limiter with various configurations."""
    rate_limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
    client_ip = "192.168.1.100"

    # Should allow up to max_requests
    for _ in range(max_requests):
        assert rate_limiter.is_allowed(client_ip) is True

    # Next request should be denied
    assert rate_limiter.is_allowed(client_ip) is False


@pytest.mark.parametrize(
    "client_ip",
    [
        "127.0.0.1",
        "192.168.1.100",
        "10.0.0.1",
        "::1",
        "2001:db8::1",
    ],
)
def test_parametrized_client_ips(client_ip, rate_limiter):
    """Test rate limiter with various client IP formats."""
    # Should work with any IP format
    assert rate_limiter.is_allowed(client_ip) is True
    assert rate_limiter.get_remaining_requests(client_ip) == 9


def test_rate_limiter_state_isolation():
    """Test that multiple rate limiter instances are isolated."""
    limiter1 = RateLimiter(max_requests=2, window_seconds=60)
    limiter2 = RateLimiter(max_requests=5, window_seconds=30)
    client_ip = "192.168.1.100"

    # Use up limiter1
    limiter1.is_allowed(client_ip)
    limiter1.is_allowed(client_ip)
    assert limiter1.is_allowed(client_ip) is False

    # limiter2 should be unaffected
    assert limiter2.is_allowed(client_ip) is True
    assert limiter2.get_remaining_requests(client_ip) == 4
