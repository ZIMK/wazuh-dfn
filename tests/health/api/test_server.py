"""Tests for wazuh_dfn.health.api.server module."""

import asyncio
import ssl
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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
        host: str = "127.0.0.1",
        port: int = 8080,
        https_enabled: bool = False,
        cert_file: str | None = None,
        key_file: str | None = None,
        auth_token: str | None = None,
        allowed_ips: list[str] | None = None,
        rate_limit: int = 0,
    ):
        self.enabled = True
        self.host = host
        self.port = port
        self.https_enabled = https_enabled
        self.cert_file = cert_file
        self.key_file = key_file
        self.auth_token = auth_token
        self.allowed_ips = allowed_ips or ["127.0.0.1", "::1"]
        self.rate_limit = rate_limit
        self.rate_limit_window = 60


class MockHealthProvider:
    """Mock health provider for testing."""

    def get_health_status(self) -> dict:
        return {"status": HealthStatus.HEALTHY, "timestamp": "2023-01-01T00:00:00Z", "health_score": 95.5}

    def get_detailed_health_status(self) -> dict:
        return {
            "overall_status": HealthStatus.HEALTHY,
            "health_score": 95.5,
            "timestamp": "2023-01-01T00:00:00Z",
            "system": {"status": HealthStatus.HEALTHY, "cpu_percent": 10.0},
            "workers": {"status": HealthStatus.HEALTHY, "total": 1, "active": 1},
            "queues": {"status": HealthStatus.HEALTHY, "total": 1},
            "services": {"status": HealthStatus.HEALTHY, "total": 1},
        }

    def get_health_metrics(self):
        return HealthMetrics(
            overall_status=HealthStatus.HEALTHY,
            health_score=95.5,
            system=SystemHealth(
                process_id=12345,
                process_name="test",
                cpu_percent=10.0,
                memory_percent=20.0,
                memory_usage_mb=100.0,
                open_files_count=10,
                max_open_files=1024,
                uptime_seconds=3600.0,
                threads_count=4,
                load_average=[0.1, 0.2, 0.3],
            ),
            workers={
                "worker-1": WorkerHealth(
                    worker_name="worker-1",
                    timestamp=datetime.now(),
                    alerts_processed=100,
                    processing_rate=10.0,
                    avg_processing_time=0.1,
                    recent_avg_processing_time=0.1,
                    min_processing_time=0.05,
                    max_processing_time=0.2,
                    slow_alerts_count=1,
                    extremely_slow_alerts_count=0,
                    last_processing_time=0.1,
                    last_alert_id="alert-1",
                    status=WorkerStatus.ACTIVE,
                    health_score=0.95,
                )
            },
            queues={
                "queue-1": QueueHealth(
                    queue_name="queue-1",
                    current_size=5,
                    max_size=100,
                    utilization_percentage=5.0,
                    total_processed=1000,
                    processing_rate=10.0,
                    queue_full_events=0,
                    avg_wait_time=0.01,
                    status=HealthStatus.HEALTHY,
                    timestamp=datetime.now(),
                )
            },
            services={
                "service-1": ServiceHealth(
                    service_name="service-1",
                    service_type="test",
                    is_connected=True,
                    connection_latency=0.01,
                    last_successful_connection=datetime.now(),
                    total_operations=1000,
                    successful_operations=990,
                    failed_operations=10,
                    avg_response_time=0.01,
                    max_response_time=0.1,
                    slow_operations_count=5,
                    status=HealthStatus.HEALTHY,
                    error_rate=1.0,
                    timestamp=datetime.now(),
                )
            },
        )

    def get_worker_status(self) -> dict:
        return {
            "workers": {"worker-1": {"healthy": True, "processing": True}},
            "summary": {"total": 1, "healthy": 1, "processing": 1},
            "timestamp": 1234567890.0,
        }

    def get_queue_status(self) -> dict:
        return {
            "queues": {"queue-1": {"healthy": True, "current_size": 5}},
            "summary": {"total": 1, "healthy": 1},
            "timestamp": 1234567890.0,
        }

    def get_system_status(self) -> dict:
        return {
            "system": {"status": HealthStatus.HEALTHY, "cpu_percent": 10.0, "memory_percent": 20.0},
            "timestamp": "2023-01-01T00:00:00Z",
        }


@pytest.fixture
def mock_api_config():
    """Create a mock API configuration for testing."""
    return MockAPIConfig()


@pytest.fixture
def mock_api_config_with_ssl():
    """Create a mock API configuration with SSL enabled."""
    return MockAPIConfig(https_enabled=True, cert_file="/path/to/cert.pem", key_file="/path/to/key.pem")


@pytest.fixture
def mock_health_provider():
    """Create a mock health provider for testing."""
    return MockHealthProvider()


@pytest.fixture
def health_api_server(mock_api_config, mock_health_provider):
    """Create a HealthAPIServer instance for testing."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")
    return HealthAPIServer(mock_health_provider, mock_api_config)


def test_server_initialization(mock_api_config, mock_health_provider):
    """Test server initialization."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    server = HealthAPIServer(mock_health_provider, mock_api_config)

    assert server.api_config == mock_api_config
    assert server.health_provider == mock_health_provider
    assert server.app is None
    assert server.runner is None
    assert server.site is None
    assert server.is_running() is False


def test_server_initialization_no_aiohttp():
    """Test server initialization when aiohttp is not available."""
    with (
        patch.dict("sys.modules", {"aiohttp": None}),
        patch("wazuh_dfn.health.api.server.AIOHTTP_AVAILABLE", False),
        pytest.raises(ImportError, match="aiohttp is required"),
    ):
        HealthAPIServer(MockHealthProvider(), MockAPIConfig())  # type: ignore[arg-type]


@patch("ssl.create_default_context")
def test_create_ssl_context_enabled(mock_ssl_context, mock_api_config_with_ssl, mock_health_provider):
    """Test SSL context creation when HTTPS is enabled."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    mock_context = MagicMock()
    mock_ssl_context.return_value = mock_context

    server = HealthAPIServer(mock_health_provider, mock_api_config_with_ssl)
    ssl_context = server._create_ssl_context()

    assert ssl_context == mock_context
    mock_ssl_context.assert_called_once_with(ssl.Purpose.CLIENT_AUTH)
    mock_context.load_cert_chain.assert_called_once_with("/path/to/cert.pem", "/path/to/key.pem")


@patch("ssl.create_default_context")
def test_create_ssl_context_error(mock_ssl_context, mock_api_config_with_ssl, mock_health_provider):
    """Test SSL context creation error handling."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    mock_ssl_context.side_effect = Exception("SSL error")

    server = HealthAPIServer(mock_health_provider, mock_api_config_with_ssl)

    with pytest.raises(Exception, match="SSL error"):
        server._create_ssl_context()


def test_create_app(health_api_server):
    """Test application creation."""
    app = health_api_server._create_app()

    assert isinstance(app, web.Application)
    # Verify routes are registered
    assert len(app.router._resources) > 0


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_start_stop_lifecycle(health_api_server):
    """Test server start and stop lifecycle."""
    with patch("aiohttp.web.AppRunner") as mock_runner_class:
        mock_runner = AsyncMock()
        mock_runner_class.return_value = mock_runner

        with patch("aiohttp.web.TCPSite") as mock_site_class:
            mock_site = AsyncMock()
            mock_site_class.return_value = mock_site

            # Test start
            server_task = asyncio.create_task(health_api_server.start())

            await asyncio.sleep(0.2)

            assert health_api_server.is_running() is True
            assert health_api_server.runner == mock_runner
            assert health_api_server.site == mock_site

            mock_runner.setup.assert_called_once()
            mock_site.start.assert_called_once()

            health_api_server.shutdown_event.set()  # Trigger shutdown event

            await asyncio.sleep(0.2)  # Allow event loop to process

            await health_api_server.stop()

            await asyncio.sleep(0.2)

            assert health_api_server.is_running() is False
            mock_runner.cleanup.assert_called_once()

            server_task.cancel()


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_start_already_running(health_api_server):
    """Test starting server when already running."""
    # Set runner to simulate already running state
    health_api_server.runner = AsyncMock()

    with pytest.raises(RuntimeError, match="Server is already running"):
        await health_api_server.start()


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_start_with_ssl(mock_api_config_with_ssl, mock_health_provider):
    """Test server start with SSL enabled."""
    server = HealthAPIServer(mock_health_provider, mock_api_config_with_ssl)

    with (
        patch("aiohttp.web.AppRunner") as mock_runner_class,
        patch("ssl.create_default_context") as mock_ssl_create,
        patch("os.path.exists", return_value=True),
    ):
        mock_runner = AsyncMock()
        mock_runner_class.return_value = mock_runner

        # Mock SSL context creation
        mock_ssl_context = MagicMock()
        mock_ssl_create.return_value = mock_ssl_context

        with patch("aiohttp.web.TCPSite") as mock_site_class:
            mock_site = AsyncMock()
            mock_site_class.return_value = mock_site

            server_task = asyncio.create_task(server.start())

            await asyncio.sleep(0.2)

            # Verify SSL context was created and used
            mock_ssl_create.assert_called_once_with(ssl.Purpose.CLIENT_AUTH)
            mock_ssl_context.load_cert_chain.assert_called_once_with("/path/to/cert.pem", "/path/to/key.pem")
            mock_site_class.assert_called_once_with(
                mock_runner, host="127.0.0.1", port=8080, ssl_context=mock_ssl_context
            )

            server.shutdown_event.set()  # Trigger shutdown event

            await asyncio.sleep(0.2)  # Allow event loop to process

            await server.stop()

            server_task.cancel()


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_start_error_cleanup(health_api_server):
    """Test error cleanup during server start."""
    with patch("aiohttp.web.AppRunner") as mock_runner_class:
        mock_runner = AsyncMock()
        mock_runner_class.return_value = mock_runner
        mock_runner.setup.side_effect = Exception("Setup failed")

        with pytest.raises(Exception, match="Setup failed"):
            await health_api_server.start()

        # Should cleanup on error
        mock_runner.cleanup.assert_called_once()
        assert health_api_server.is_running() is False


def test_is_running(health_api_server):
    """Test is_running method."""
    assert health_api_server.is_running() is False

    # Simulate running state
    health_api_server.runner = AsyncMock()
    health_api_server.site = AsyncMock()
    assert health_api_server.is_running() is True

    # Simulate stopped state
    health_api_server.runner = None
    health_api_server.site = None
    assert health_api_server.is_running() is False


def test_get_server_info(mock_api_config, mock_health_provider):
    """Test server info generation."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    server = HealthAPIServer(mock_health_provider, mock_api_config)
    info = server.get_server_info()

    assert info["host"] == "127.0.0.1"
    assert info["port"] == 8080
    assert info["https_enabled"] is False
    assert info["is_running"] is False
    assert "authentication_enabled" in info
    assert "rate_limiting_enabled" in info
    assert "ip_allowlist_enabled" in info


def test_get_server_info_custom_allowlist():
    """Test server info with custom IP allowlist."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    config = MockAPIConfig(allowed_ips=["192.168.1.0/24", "10.0.0.1"])
    server = HealthAPIServer(MockHealthProvider(), config)  # type: ignore[arg-type]
    info = server.get_server_info()

    assert info["ip_allowlist_enabled"] is True


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_cleanup_idempotent(health_api_server):
    """Test that cleanup operations are idempotent."""
    # Multiple calls to cleanup should not cause errors
    await health_api_server.cleanup()
    await health_api_server.cleanup()
    await health_api_server.cleanup()

    # No assertions needed - just verify no exceptions are raised


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_stop_when_not_running(health_api_server):
    """Test stopping server when not running."""
    # Should not raise exception when stopping a non-running server
    await health_api_server.stop()

    assert health_api_server.is_running() is False


@pytest.mark.parametrize(
    "host,port,https",
    [
        ("0.0.0.0", 8080, False),  # noqa: S104
        ("127.0.0.1", 443, True),
        ("::1", 8443, True),
        ("localhost", 3000, False),
    ],
)
def test_parametrized_server_configs(host, port, https):
    """Test server with various configuration parameters."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    config = MockAPIConfig(host=host, port=port, https_enabled=https)
    server = HealthAPIServer(MockHealthProvider(), config)  # type: ignore[arg-type]

    assert server.api_config.host == host
    assert server.api_config.port == port
    assert server.api_config.https_enabled == https


@pytest.mark.skipif(AIOHTTP_AVAILABLE, reason="Testing import error handling")
def test_import_error_handling():
    """Test that server gracefully handles missing aiohttp."""
    assert not AIOHTTP_AVAILABLE
