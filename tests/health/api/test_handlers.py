"""Tests for wazuh_dfn.health.api.handlers module."""

from datetime import datetime
from unittest.mock import patch

import pytest

from wazuh_dfn.health.models import (
    HealthMetrics,
    OverallHealthStatus,
    QueueHealth,
    ServiceHealth,
    SystemHealth,
    WorkerHealth,
    WorkerStatus,
)

try:
    from aiohttp import web
    from aiohttp.test_utils import make_mocked_request

    from wazuh_dfn.health.api.handlers import HealthHandlers

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore
    make_mocked_request = None  # type: ignore
    HealthHandlers = None  # type: ignore


@pytest.fixture
def mock_health_provider():
    """Create a mock health provider for testing."""

    class MockHealthProvider:
        """Mock health provider for testing."""

        def __init__(self):
            self.health_metrics = self.create_mock_metrics()

        def create_mock_metrics(self) -> HealthMetrics:
            """Create comprehensive mock health metrics."""
            system = SystemHealth(
                process_id=12345,
                process_name="wazuh-dfn-test",
                cpu_percent=15.7,
                memory_percent=32.4,
                memory_usage_mb=512.8,
                open_files_count=45,
                max_open_files=1024,
                uptime_seconds=7200.5,
                threads_count=8,
                load_average=[0.8, 1.2, 1.5],
            )

            workers = {
                "worker-1": WorkerHealth(
                    worker_name="worker-1",
                    timestamp=datetime.now(),
                    alerts_processed=1250,
                    processing_rate=2.3,
                    avg_processing_time=0.015,
                    recent_avg_processing_time=0.012,
                    min_processing_time=0.005,
                    max_processing_time=0.150,
                    slow_alerts_count=3,
                    extremely_slow_alerts_count=0,
                    last_processing_time=0.018,
                    last_alert_id="alert-12345",
                    status=WorkerStatus.ACTIVE,
                    health_score=0.95,
                )
            }

            queues = {
                "alert_queue": QueueHealth(
                    queue_name="alert_queue",
                    current_size=23,
                    max_size=1000,
                    utilization_percentage=2.3,
                    total_processed=5678,
                    processing_rate=10.5,
                    queue_full_events=2,
                    avg_wait_time=0.05,
                    status=OverallHealthStatus.HEALTHY,
                    timestamp=datetime.now(),
                )
            }

            services = {
                "kafka": ServiceHealth(
                    service_name="kafka",
                    service_type="message_broker",
                    is_connected=True,
                    connection_latency=0.025,
                    last_successful_connection=datetime.now(),
                    total_operations=2340,
                    successful_operations=2335,
                    failed_operations=5,
                    avg_response_time=0.045,
                    max_response_time=0.200,
                    slow_operations_count=15,
                    status=OverallHealthStatus.HEALTHY,
                    error_rate=0.21,
                    timestamp=datetime.now(),
                )
            }

            return HealthMetrics(
                overall_status=OverallHealthStatus.HEALTHY,
                health_score=95.5,
                system=system,
                workers=workers,
                queues=queues,
                services=services,
            )

        async def get_health_status(self) -> dict:
            """Basic health status for /health endpoint."""
            return {"status": "healthy", "timestamp": datetime.now().isoformat(), "health_score": 95.5}

        async def get_detailed_health(self) -> dict:
            """Detailed health status."""
            return {
                "overall_status": "healthy",
                "health_score": 95.5,
                "system": {"status": "healthy", "cpu_usage": 15.7},
                "workers": {"status": "healthy", "active": 1},
                "queues": {"status": "healthy", "pending_tasks": 23},
                "services": {"status": "healthy", "kafka": {"status": "healthy"}},
            }

        async def get_worker_status(self) -> dict:
            """Worker status information."""
            return {
                "workers": [{"id": 1, "status": "active", "current_task": "processing"}],
                "summary": {"total_workers": 1, "active_workers": 1, "status": "healthy"},
            }

        async def get_queue_status(self) -> dict:
            """Queue status information."""
            return {
                "queues": [{"name": "alert_queue", "pending_tasks": 23, "processing_tasks": 1}],
                "summary": {"total_pending": 23, "status": "healthy"},
            }

        async def get_system_status(self) -> dict:
            """System status information."""
            return {
                "system": {"status": "healthy", "cpu_usage": 15.7, "memory_usage": 32.4},
                "timestamp": datetime.now().isoformat(),
            }

        async def get_metrics(self) -> dict:
            """Get metrics for the metrics endpoint."""
            return {
                "health_score": 95.5,
                "system": {"cpu_usage": 15.7, "memory_usage": 32.4},
                "workers": {"active": 1, "total": 1},
                "queues": {"alert_queue": {"size": 23, "max_size": 1000}},
                "services": {"kafka": {"operations_per_sec": 1000}},
            }

    return MockHealthProvider()


@pytest.fixture
def aiohttp_app(mock_health_provider):
    """Create test aiohttp application."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    app = web.Application()
    handlers = HealthHandlers(mock_health_provider)
    handlers.register_routes(app)
    return app


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_api_info_handler(aiohttp_client, aiohttp_app):
    """Test API info endpoint."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/api/info")
    assert resp.status == 200

    data = await resp.json()
    assert data["api_version"] == "2.1"
    assert data["server"] == "Wazuh DFN Health API"
    assert "capabilities" in data


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_health_basic_handler(aiohttp_client, aiohttp_app):
    """Test basic health endpoint."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/health")
    assert resp.status == 200

    data = await resp.json()
    assert data["status"] == "healthy"
    assert "health_score" in data


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_health_detailed_handler(aiohttp_client, aiohttp_app):
    """Test detailed health endpoint."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/health/detailed")
    assert resp.status == 200

    data = await resp.json()
    assert data["overall_status"] == "healthy"
    assert "system" in data
    assert "workers" in data
    assert "queues" in data


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_worker_status_handler(aiohttp_client, aiohttp_app):
    """Test worker status endpoint."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/status/workers")
    assert resp.status == 200

    data = await resp.json()
    assert "workers" in data
    assert "summary" in data


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_queue_status_handler(aiohttp_client, aiohttp_app):
    """Test queue status endpoint."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/status/queue")
    assert resp.status == 200

    data = await resp.json()
    assert "queues" in data
    assert "summary" in data


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_system_status_handler(aiohttp_client, aiohttp_app):
    """Test system status endpoint."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/status/system")
    assert resp.status == 200

    data = await resp.json()
    assert "system" in data
    assert "timestamp" in data


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_metrics_handler(aiohttp_client, aiohttp_app):
    """Test metrics endpoint (Prometheus format)."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/metrics")
    assert resp.status == 200

    content = await resp.text()
    assert "wazuh_dfn_health_score" in content
    assert "95.5" in content


def test_handlers_initialization(mock_health_provider):
    """Test HealthHandlers initialization."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    assert handlers.health_provider is mock_health_provider


def test_register_routes(mock_health_provider):
    """Test route registration."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    app = web.Application()
    handlers = HealthHandlers(mock_health_provider)
    handlers.register_routes(app)

    assert len(app.router._resources) > 0


def test_format_prometheus_metrics(mock_health_provider):
    """Test Prometheus metrics formatting."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)

    metrics_data = {
        "health_score": 95.5,
        "system": {"cpu_usage": 15.7, "memory_usage": 32.4},
        "workers": {"active": 1, "total": 1},
    }

    prometheus_output = handlers._format_prometheus_metrics(metrics_data)

    assert "wazuh_dfn_health_score 95.5" in prometheus_output
    assert 'wazuh_dfn_system{type="cpu_usage"} 15.7' in prometheus_output
    assert 'wazuh_dfn_system{type="memory_usage"} 32.4' in prometheus_output
    assert 'wazuh_dfn_workers{type="active"} 1' in prometheus_output
    assert 'wazuh_dfn_workers{type="total"} 1' in prometheus_output


@pytest.mark.asyncio
async def test_handler_error_handling(mock_health_provider):
    """Test error handling in handlers."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/health")

    with patch.object(mock_health_provider, "get_health_status", side_effect=Exception("Test error")):
        response = await handlers.health_basic_handler(request)
        assert response.status == 500


@pytest.mark.skipif(AIOHTTP_AVAILABLE, reason="Testing import error handling")
def test_import_error_handling():
    """Test that handlers gracefully handle missing aiohttp."""
    assert not AIOHTTP_AVAILABLE
