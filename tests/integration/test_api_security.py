"""Integration tests for Health API Server security features.

Tests authentication, authorization, rate limiting, and secure headers.
"""

import asyncio
import contextlib
import time
from datetime import datetime

import aiohttp
import pytest

from wazuh_dfn.config import APIConfig
from wazuh_dfn.health.api.server import HealthAPIServer
from wazuh_dfn.health.models import (
    HealthMetrics,
    HealthStatus,
    QueueHealth,
    ServiceHealth,
    SystemHealth,
    WorkerHealth,
    WorkerStatus,
)


class MockSecureHealthProvider:
    """Mock health provider for security testing."""

    def get_health_metrics(self) -> HealthMetrics:
        """Return minimal health metrics for security testing."""
        system = SystemHealth(
            process_id=12345,
            process_name="wazuh-dfn-security-test",
            cpu_percent=10.0,
            memory_percent=25.0,
            memory_usage_mb=256.0,
            open_files_count=20,
            max_open_files=1024,
            uptime_seconds=3600.0,
            threads_count=4,
            load_average=[0.5, 0.6, 0.7],
        )

        workers = {
            "test-worker": WorkerHealth(
                worker_name="test-worker",
                timestamp=datetime.now(),
                alerts_processed=100,
                processing_rate=1.0,
                avg_processing_time=0.01,
                recent_avg_processing_time=0.01,
                min_processing_time=0.005,
                max_processing_time=0.02,
                slow_alerts_count=0,
                extremely_slow_alerts_count=0,
                last_processing_time=0.01,
                last_alert_id="test-alert-1",
                status=WorkerStatus.ACTIVE,
                health_score=1.0,
            )
        }

        queues = {
            "test_queue": QueueHealth(
                queue_name="test_queue",
                current_size=5,
                max_size=100,
                config_max_size=1000,
                utilization_percentage=5.0,
                total_processed=50,
                processing_rate=2.0,
                queue_full_events=0,
                avg_wait_time=0.01,
                status=HealthStatus.HEALTHY,
                timestamp=datetime.now(),
            )
        }

        services = {
            "test_service": ServiceHealth(
                service_name="test_service",
                service_type="test",
                is_connected=True,
                connection_latency=0.001,
                last_successful_connection=datetime.now(),
                total_operations=100,
                successful_operations=100,
                failed_operations=0,
                avg_response_time=0.001,
                max_response_time=0.002,
                slow_operations_count=0,
                status=HealthStatus.HEALTHY,
                error_rate=0.0,
                timestamp=datetime.now(),
            )
        }

        return HealthMetrics(
            overall_status=HealthStatus.HEALTHY,
            health_score=100.0,
            system=system,
            workers=workers,
            queues=queues,
            services=services,
        )

    def get_health_status(self) -> dict:
        """Basic health status."""
        return {"status": HealthStatus.HEALTHY, "timestamp": datetime.now().isoformat(), "health_score": 100.0}

    def get_detailed_health_status(self) -> dict:
        """Detailed health status."""
        return {
            "overall_status": HealthStatus.HEALTHY,
            "health_score": 100.0,
            "system": {"status": HealthStatus.HEALTHY},
            "workers": {"status": HealthStatus.HEALTHY},
            "queues": {"status": HealthStatus.HEALTHY},
            "services": {"status": HealthStatus.HEALTHY},
        }

    def get_detailed_health(self) -> dict:
        """Detailed health endpoint alias."""
        return self.get_detailed_health_status()

    def get_metrics(self) -> dict:
        """Get health metrics."""
        metrics = self.get_health_metrics()
        return metrics.model_dump()

    def get_worker_status(self) -> dict:
        """Worker status."""
        return {"workers": [], "summary": {"status": HealthStatus.HEALTHY}}

    def get_queue_status(self) -> dict:
        """Queue status."""
        return {"queues": [], "summary": {"status": HealthStatus.HEALTHY}}

    def get_system_status(self) -> dict:
        """System status."""
        return {"system": {"status": HealthStatus.HEALTHY}, "timestamp": datetime.now().isoformat()}


@pytest.fixture(scope="module")
def secure_api_config():
    """Create secure API configuration for testing."""
    return APIConfig(
        enabled=True,
        host="127.0.0.1",
        port=8082,
        auth_token="test-secret-token",  # noqa: S106
        allowed_ips=["127.0.0.1", "::1", "192.168.1.0/24"],
        rate_limit=0,  # Disable rate limiting to avoid test interference
        https_enabled=False,
    )


@pytest.fixture(scope="module")
def insecure_api_config():
    """Create insecure API configuration for testing."""
    return APIConfig(
        enabled=True,
        host="127.0.0.1",
        port=8083,
        auth_token=None,
        allowed_ips=["127.0.0.1", "::1"],
        rate_limit=1000,
        https_enabled=False,
    )


@pytest.fixture(scope="module")
def secure_health_provider():
    """Create mock health provider for security testing."""
    return MockSecureHealthProvider()


@pytest.fixture(scope="module")
def rate_limited_api_config():
    """Create API configuration with rate limiting enabled for rate limiting tests."""
    return APIConfig(
        enabled=True,
        host="127.0.0.1",
        port=8084,  # Different port to avoid conflicts
        auth_token="test-secret-token",  # noqa: S106
        allowed_ips=["127.0.0.1", "::1", "192.168.1.0/24"],
        rate_limit=5,  # Small limit for testing rate limiting
        rate_limit_window=5,  # Short window for faster tests
        https_enabled=False,
    )


@pytest.fixture(scope="module")
def rate_limited_server(rate_limited_api_config, secure_health_provider, event_loop):
    """Create a separate server with rate limiting enabled for specific tests."""

    async def setup_and_run():
        shutdown_event = asyncio.Event()
        server = HealthAPIServer(secure_health_provider, rate_limited_api_config, shutdown_event)

        # Start server in background task
        server_task = asyncio.create_task(server.start())

        # Wait for server to be ready
        await _wait_for_server_ready(f"http://{rate_limited_api_config.host}:{rate_limited_api_config.port}")

        return server, shutdown_event, server_task

    server, shutdown_event, server_task = event_loop.run_until_complete(setup_and_run())

    yield server

    # Cleanup
    async def cleanup():
        shutdown_event.set()  # Signal server to stop
        try:
            await asyncio.wait_for(server_task, timeout=5.0)  # Wait for server to stop gracefully
        except TimeoutError:
            server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await server_task

    event_loop.run_until_complete(cleanup())


@pytest.fixture(scope="module")
def event_loop():
    """Create a module-scoped event loop for all security tests."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture(scope="module")
def secure_server(event_loop, secure_api_config, secure_health_provider):
    """Create and start secure health API server for all tests in the module."""

    async def setup_and_run():
        shutdown_event = asyncio.Event()
        server = HealthAPIServer(secure_health_provider, secure_api_config, shutdown_event)

        # Start server in background task
        server_task = asyncio.create_task(server.start())

        # Wait for server to be ready
        await _wait_for_server_ready(f"http://{secure_api_config.host}:{secure_api_config.port}")

        return server, shutdown_event, server_task

    server, shutdown_event, server_task = event_loop.run_until_complete(setup_and_run())

    yield server

    # Cleanup
    async def cleanup():
        shutdown_event.set()  # Signal server to stop
        try:
            await asyncio.wait_for(server_task, timeout=5.0)  # Wait for server to stop gracefully
        except TimeoutError:
            server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await server_task

    event_loop.run_until_complete(cleanup())


@pytest.fixture(scope="module")
def insecure_server(event_loop, insecure_api_config, secure_health_provider):
    """Create and start insecure health API server for all tests in the module."""

    async def setup_and_run():
        shutdown_event = asyncio.Event()
        server = HealthAPIServer(secure_health_provider, insecure_api_config, shutdown_event)

        # Start server in background task
        server_task = asyncio.create_task(server.start())

        # Wait for server to be ready
        await _wait_for_server_ready(f"http://{insecure_api_config.host}:{insecure_api_config.port}")

        return server, shutdown_event, server_task

    server, shutdown_event, server_task = event_loop.run_until_complete(setup_and_run())

    yield server

    # Cleanup
    async def cleanup():
        shutdown_event.set()  # Signal server to stop
        try:
            await asyncio.wait_for(server_task, timeout=5.0)  # Wait for server to stop gracefully
        except TimeoutError:
            server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await server_task

    event_loop.run_until_complete(cleanup())


async def _wait_for_server_ready(base_url: str, timeout: int = 10) -> bool:
    """Wait for server to become ready with timeout."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            async with aiohttp.ClientSession() as session, session.get(f"{base_url}/health") as response:
                if response.status in [200, 401]:  # 401 is expected for secure server
                    return True
        except Exception:  # noqa: S110
            pass
        await asyncio.sleep(0.1)

    raise TimeoutError(f"Server at {base_url} not ready after {timeout}s")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_authentication_required(secure_server, secure_api_config):
    """Test that authentication is required for secure endpoints."""
    base_url = f"http://{secure_api_config.host}:{secure_api_config.port}"

    async with aiohttp.ClientSession() as session, session.get(f"{base_url}/health") as response:
        assert response.status == 401
        error_text = await response.text()
        assert "Authentication required" in error_text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_authentication_wrong_token(secure_server, secure_api_config):
    """Test that wrong auth token is rejected."""
    base_url = f"http://{secure_api_config.host}:{secure_api_config.port}"

    async with aiohttp.ClientSession() as session:
        # Test with wrong auth token (should fail)
        headers = {"Authorization": "Bearer wrong-token"}
        async with session.get(f"{base_url}/health", headers=headers) as response:
            assert response.status == 401
            error_text = await response.text()
            assert "Invalid" in error_text and "token" in error_text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_authentication_correct_token(secure_server, secure_api_config):
    """Test that correct auth token is accepted."""
    base_url = f"http://{secure_api_config.host}:{secure_api_config.port}"

    async with aiohttp.ClientSession() as session:
        # Test with correct auth token (should succeed)
        headers = {"Authorization": "Bearer test-secret-token"}
        async with session.get(f"{base_url}/health", headers=headers) as response:
            assert response.status == 200
            data = await response.json()
            assert "status" in data


@pytest.mark.asyncio
@pytest.mark.integration
async def test_secure_headers(secure_server, secure_api_config):
    """Test that security headers are present in responses."""
    base_url = f"http://{secure_api_config.host}:{secure_api_config.port}"

    async with aiohttp.ClientSession() as session:
        headers = {"Authorization": "Bearer test-secret-token"}
        async with session.get(f"{base_url}/health", headers=headers) as response:
            assert response.status == 200

            # Check security headers
            expected_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Content-Security-Policy": "default-src 'self'; script-src 'none'; object-src 'none'",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }

            for header, expected_value in expected_headers.items():
                actual_value = response.headers.get(header)
                assert (
                    actual_value == expected_value
                ), f"Header {header}: expected '{expected_value}', got '{actual_value}'"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_rate_limiting(rate_limited_server, rate_limited_api_config):
    """Test that rate limiting works correctly."""
    base_url = f"http://{rate_limited_api_config.host}:{rate_limited_api_config.port}"

    async with aiohttp.ClientSession() as session:
        headers = {"Authorization": "Bearer test-secret-token"}

        # Make requests up to the limit
        success_count = 0
        rate_limited = False

        for _ in range(rate_limited_api_config.rate_limit + 5):  # Try more than the limit
            async with session.get(f"{base_url}/health", headers=headers) as response:
                if response.status == 200:
                    success_count += 1
                elif response.status == 429:
                    error_text = await response.text()
                    assert "Rate limit exceeded" in error_text
                    rate_limited = True
                    break
                else:
                    pytest.fail(f"Unexpected status: {response.status}")

        assert rate_limited, f"Rate limiting not triggered after {success_count} requests"
        assert success_count <= rate_limited_api_config.rate_limit, f"Too many requests allowed: {success_count}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_no_authentication_when_disabled(insecure_server, insecure_api_config):
    """Test that authentication is not required when disabled."""
    base_url = f"http://{insecure_api_config.host}:{insecure_api_config.port}"

    async with aiohttp.ClientSession() as session, session.get(f"{base_url}/health") as response:
        assert response.status == 200
        data = await response.json()
        assert "status" in data


@pytest.mark.asyncio
@pytest.mark.integration
async def test_all_endpoints_with_security(secure_server, secure_api_config):
    """Test all endpoints work with security enabled."""
    base_url = f"http://{secure_api_config.host}:{secure_api_config.port}"

    endpoints = ["/health", "/health/detailed", "/metrics", "/status/workers", "/status/queue", "/status/system"]

    async with aiohttp.ClientSession() as session:
        headers = {"Authorization": "Bearer test-secret-token"}

        for endpoint in endpoints:
            async with session.get(f"{base_url}{endpoint}", headers=headers) as response:
                if response.status == 200:
                    # Success - check response has content
                    if endpoint == "/metrics":
                        content = await response.text()
                        assert len(content) > 0
                    else:
                        data = await response.json()
                        assert len(data) > 0
                elif response.status == 429:
                    # Rate limited - expected after several requests
                    break
                else:
                    pytest.fail(f"Endpoint {endpoint} failed with status {response.status}")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_configuration_validation():
    """Test configuration validation features."""
    # Test invalid IP addresses
    with pytest.raises(ValueError):
        APIConfig(allowed_ips=["invalid-ip"])

    # Test invalid port
    with pytest.raises(ValueError):
        APIConfig(port=70000)

    # Test invalid rate limit
    with pytest.raises(ValueError):
        APIConfig(rate_limit=-1)

    # Test valid configuration
    config = APIConfig(
        enabled=True,
        host="127.0.0.1",
        port=8080,
        auth_token="valid-token",  # noqa: S106
        allowed_ips=["127.0.0.1", "192.168.1.0/24"],
        rate_limit=100,
    )

    assert config.auth_token == "valid-token"  # noqa: S105
    assert "127.0.0.1" in config.allowed_ips
    assert config.rate_limit == 100


@pytest.mark.asyncio
@pytest.mark.integration
async def test_https_configuration_validation():
    """Test HTTPS configuration validation."""
    # Test HTTPS enabled without cert files (should log warning but not fail)
    config = APIConfig(enabled=True, https_enabled=True, cert_file=None, key_file=None)

    assert config.https_enabled is True

    # Test HTTPS with cert files
    config = APIConfig(enabled=True, https_enabled=True, cert_file="/path/to/cert.pem", key_file="/path/to/key.pem")

    assert config.cert_file == "/path/to/cert.pem"
    assert config.key_file == "/path/to/key.pem"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_cidr_ip_allowlist():
    """Test CIDR notation in IP allowlist."""
    config = APIConfig(enabled=True, allowed_ips=["127.0.0.1", "::1", "192.168.1.0/24", "10.0.0.0/8"])

    # Verify CIDR patterns are accepted
    assert "192.168.1.0/24" in config.allowed_ips
    assert "10.0.0.0/8" in config.allowed_ips

    # Test invalid CIDR notation
    with pytest.raises(ValueError):
        APIConfig(allowed_ips=["192.168.1.0/33"])  # Invalid CIDR


@pytest.mark.asyncio
@pytest.mark.integration
async def test_bearer_token_formats(secure_server, secure_api_config):
    """Test various Bearer token formats."""
    base_url = f"http://{secure_api_config.host}:{secure_api_config.port}"

    async with aiohttp.ClientSession() as session:
        # Test case sensitivity
        test_cases = [
            ("Bearer test-secret-token", 200),  # Correct
            ("bearer test-secret-token", 401),  # Wrong case
            ("BEARER test-secret-token", 401),  # Wrong case
            ("Basic test-secret-token", 401),  # Wrong auth type
            ("test-secret-token", 401),  # Missing Bearer
            ("Bearer ", 401),  # Empty token
            ("Bearer wrong-token", 401),  # Wrong token
        ]

        for auth_header, expected_status in test_cases:
            headers = {"Authorization": auth_header}
            async with session.get(f"{base_url}/health", headers=headers) as response:
                assert (
                    response.status == expected_status
                ), f"Auth header '{auth_header}' should return {expected_status}, got {response.status}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_requests_rate_limiting(rate_limited_server, rate_limited_api_config):
    """Test rate limiting with concurrent requests."""
    # Wait for rate limit window to reset from previous tests
    await asyncio.sleep(rate_limited_api_config.rate_limit_window + 1)

    base_url = f"http://{rate_limited_api_config.host}:{rate_limited_api_config.port}"

    async def make_request():
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": "Bearer test-secret-token"}
            async with session.get(f"{base_url}/health", headers=headers) as response:
                return response.status

    # Make several concurrent requests (more than the rate limit)
    tasks = [make_request() for _ in range(rate_limited_api_config.rate_limit + 10)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Count success and rate limited responses
    success_count = sum(1 for r in results if r == 200)
    rate_limited_count = sum(1 for r in results if r == 429)

    # Should have some successes and some rate limited
    assert success_count > 0, "No successful requests"
    assert rate_limited_count > 0, "No rate limited requests"
    assert (
        success_count <= rate_limited_api_config.rate_limit + 2
    ), f"Too many successful requests: {success_count}"  # Allow some tolerance


@pytest.mark.asyncio
@pytest.mark.integration
async def test_security_integration_complete(rate_limited_server, rate_limited_api_config):
    """Complete integration test of all security features."""
    # Wait for rate limit window to reset from previous tests
    await asyncio.sleep(rate_limited_api_config.rate_limit_window + 1)

    base_url = f"http://{rate_limited_api_config.host}:{rate_limited_api_config.port}"

    async with aiohttp.ClientSession() as session:
        # 1. Test authentication
        headers = {"Authorization": "Bearer test-secret-token"}
        async with session.get(f"{base_url}/health", headers=headers) as response:
            assert response.status == 200

            # 2. Test security headers
            assert response.headers.get("X-Content-Type-Options") == "nosniff"
            assert response.headers.get("X-Frame-Options") == "DENY"

            # 3. Test response content
            data = await response.json()
            assert "status" in data
            assert "timestamp" in data

        # 4. Test rate limiting eventually kicks in
        rate_limited = False
        for _ in range(rate_limited_api_config.rate_limit + 5):
            async with session.get(f"{base_url}/health", headers=headers) as response:
                if response.status == 429:
                    rate_limited = True
                    break

        assert rate_limited, "Rate limiting should eventually trigger"
