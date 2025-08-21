"""Tests for wazuh_dfn.health.api.middleware module."""

from unittest.mock import MagicMock

import pytest

from wazuh_dfn.health.api.middleware import SecurityMiddleware

try:
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore


class MockAPIConfig:
    """Mock API configuration for testing."""

    def __init__(
        self,
        auth_token: str | None = None,
        allowed_ips: list[str] | None = None,
        rate_limit: int = 0,
        rate_limit_window: int = 60,
        https_enabled: bool = False,
    ):
        self.auth_token = auth_token
        self.allowed_ips = allowed_ips if allowed_ips is not None else ["127.0.0.1", "::1"]
        self.rate_limit = rate_limit
        self.rate_limit_window = rate_limit_window
        self.https_enabled = https_enabled


@pytest.fixture
def mock_api_config():
    """Create a mock API configuration for testing."""
    return MockAPIConfig()


@pytest.fixture
def mock_api_config_with_auth():
    """Create a mock API configuration with authentication."""
    return MockAPIConfig(auth_token="test-token-12345")  # noqa: S106


@pytest.fixture
def mock_api_config_with_rate_limit():
    """Create a mock API configuration with rate limiting."""
    return MockAPIConfig(rate_limit=10)


@pytest.fixture
def mock_api_config_full():
    """Create a mock API configuration with all features enabled."""
    return MockAPIConfig(
        auth_token="secure-token-xyz",  # noqa: S106
        allowed_ips=["127.0.0.1", "192.168.1.0/24"],
        rate_limit=100,
        https_enabled=True,
    )


@pytest.fixture
def security_middleware(mock_api_config):
    """Create a SecurityMiddleware instance for testing."""
    return SecurityMiddleware(mock_api_config)


def test_middleware_initialization(mock_api_config_with_rate_limit):
    """Test middleware initialization."""
    middleware = SecurityMiddleware(mock_api_config_with_rate_limit)

    assert middleware.api_config == mock_api_config_with_rate_limit
    assert middleware.rate_limiter is not None


def test_middleware_initialization_no_rate_limit(mock_api_config):
    """Test middleware initialization without rate limiting."""
    middleware = SecurityMiddleware(mock_api_config)

    assert middleware.api_config == mock_api_config
    assert middleware.rate_limiter is None


def test_get_client_ip_forwarded_for(security_middleware):
    """Test client IP extraction from X-Forwarded-For header."""
    # Mock request with X-Forwarded-For header
    request = MagicMock()
    request.headers.get.side_effect = lambda key: {"X-Forwarded-For": "192.168.1.100, 10.0.0.1"}.get(key)

    ip = security_middleware._get_client_ip(request)
    assert ip == "192.168.1.100"


def test_get_client_ip_real_ip(security_middleware):
    """Test client IP extraction from X-Real-IP header."""
    # Mock request with X-Real-IP header
    request = MagicMock()
    request.headers.get.side_effect = lambda key: {"X-Real-IP": "192.168.1.100"}.get(key)

    ip = security_middleware._get_client_ip(request)
    assert ip == "192.168.1.100"


def test_get_client_ip_remote(security_middleware):
    """Test client IP extraction from remote address."""
    # Mock request with remote address
    request = MagicMock()
    request.headers.get.return_value = None
    request.remote = "192.168.1.100"

    ip = security_middleware._get_client_ip(request)
    assert ip == "192.168.1.100"


def test_get_client_ip_fallback(security_middleware):
    """Test client IP fallback to localhost."""
    # Mock request without IP information
    request = MagicMock()
    request.headers.get.return_value = None
    request.remote = None

    ip = security_middleware._get_client_ip(request)
    assert ip == "127.0.0.1"


def test_is_ip_allowed_localhost(security_middleware):
    """Test IP allowlist with localhost."""
    assert security_middleware._is_ip_allowed("127.0.0.1") is True
    assert security_middleware._is_ip_allowed("::1") is True


def test_is_ip_allowed_cidr(mock_api_config):
    """Test IP allowlist with CIDR notation."""
    config = MockAPIConfig(allowed_ips=["192.168.1.0/24"])
    middleware = SecurityMiddleware(config)

    assert middleware._is_ip_allowed("192.168.1.100") is True
    assert middleware._is_ip_allowed("192.168.2.100") is False


def test_is_ip_allowed_invalid_ip(security_middleware):
    """Test IP allowlist with invalid IP."""
    assert security_middleware._is_ip_allowed("invalid-ip") is False


def test_is_ip_allowed_empty_list():
    """Test IP allowlist with empty allowed list."""
    config = MockAPIConfig(allowed_ips=[])
    middleware = SecurityMiddleware(config)

    # Empty list should allow all IPs
    assert middleware._is_ip_allowed("192.168.1.100") is True


def test_get_middlewares_minimal(mock_api_config):
    """Test get_middlewares with minimal configuration."""
    middleware = SecurityMiddleware(mock_api_config)
    middlewares = middleware.get_middlewares()

    # Should always have security headers
    assert len(middlewares) >= 1

    # Check that middleware functions are present
    assert all(callable(mw) for mw in middlewares)


def test_get_middlewares_full(mock_api_config_full):
    """Test get_middlewares with full configuration."""
    middleware = SecurityMiddleware(mock_api_config_full)
    middlewares = middleware.get_middlewares()

    # Should have multiple middlewares for full config
    assert len(middlewares) >= 3

    # Check that middleware functions are present
    assert all(callable(mw) for mw in middlewares)


def test_get_middlewares_auth_only(mock_api_config_with_auth):
    """Test get_middlewares with authentication only."""
    middleware = SecurityMiddleware(mock_api_config_with_auth)
    middlewares = middleware.get_middlewares()

    # Should have security headers + auth middleware
    assert len(middlewares) >= 2

    # Check that middleware functions are present
    assert all(callable(mw) for mw in middlewares)


# Integration tests using pytest-aiohttp fixtures
@pytest.fixture
def aiohttp_app():
    """Create test aiohttp application."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    config = MockAPIConfig(auth_token="test-token-12345")  # noqa: S106
    middleware = SecurityMiddleware(config)

    app = web.Application(middlewares=middleware.get_middlewares())

    async def test_handler(request):
        return web.json_response({"status": "ok"})

    app.router.add_get("/test", test_handler)
    return app


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_security_headers_middleware(aiohttp_client, aiohttp_app):
    """Test security headers middleware."""
    client = await aiohttp_client(aiohttp_app)

    resp = await client.get("/test", headers={"Authorization": "Bearer test-token-12345"})
    assert resp.status == 200

    # Check security headers
    assert "X-Content-Type-Options" in resp.headers
    assert "X-Frame-Options" in resp.headers
    assert "X-XSS-Protection" in resp.headers
    # Note: Strict-Transport-Security only added when HTTPS is enabled


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_authentication_middleware_success(aiohttp_client, aiohttp_app):
    """Test successful authentication."""
    client = await aiohttp_client(aiohttp_app)

    resp = await client.get("/test", headers={"Authorization": "Bearer test-token-12345"})
    assert resp.status == 200

    data = await resp.json()
    assert data["status"] == "ok"


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_authentication_middleware_missing_token(aiohttp_client, aiohttp_app):
    """Test authentication with missing token."""
    client = await aiohttp_client(aiohttp_app)

    resp = await client.get("/test")
    assert resp.status == 401


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_authentication_middleware_invalid_token(aiohttp_client, aiohttp_app):
    """Test authentication with invalid token."""
    client = await aiohttp_client(aiohttp_app)

    resp = await client.get("/test", headers={"Authorization": "Bearer invalid-token"})
    assert resp.status == 401


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_authentication_middleware_invalid_format(aiohttp_client, aiohttp_app):
    """Test authentication with invalid header format."""
    client = await aiohttp_client(aiohttp_app)

    resp = await client.get("/test", headers={"Authorization": "InvalidFormat"})
    assert resp.status == 401


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_ip_allowlist_middleware_allowed():
    """Test IP allowlist middleware with allowed IP."""
    config = MockAPIConfig(allowed_ips=["127.0.0.1"])
    middleware = SecurityMiddleware(config)

    app = web.Application(middlewares=middleware.get_middlewares())

    async def test_handler(request):
        return web.json_response({"status": "ok"})

    app.router.add_get("/test", test_handler)

    # This test would need a custom client setup to test IP filtering
    # For now, we'll just verify the middleware can be created
    assert len(middleware.get_middlewares()) >= 1


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_rate_limit_middleware():
    """Test rate limiting middleware."""
    config = MockAPIConfig(rate_limit=2)  # Very low limit for testing
    middleware = SecurityMiddleware(config)

    app = web.Application(middlewares=middleware.get_middlewares())

    async def test_handler(request):
        return web.json_response({"status": "ok"})

    app.router.add_get("/test", test_handler)

    # This test would need multiple rapid requests to test rate limiting
    # For now, we'll just verify the middleware can be created with rate limiting
    assert middleware.rate_limiter is not None
    assert len(middleware.get_middlewares()) >= 2


@pytest.mark.skipif(AIOHTTP_AVAILABLE, reason="Testing import error handling")
def test_import_error_handling():
    """Test that middleware gracefully handles missing aiohttp."""
    assert not AIOHTTP_AVAILABLE
