"""Tests for wazuh_dfn.health.api.handlers module."""

from datetime import datetime
from unittest.mock import patch

import pytest

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

        def get_health_metrics(self) -> HealthMetrics:
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
                    max_size=100,
                    config_max_size=1000,
                    utilization_percentage=2.3,
                    total_processed=5678,
                    processing_rate=10.5,
                    queue_full_events=2,
                    avg_wait_time=0.05,
                    status=HealthStatus.HEALTHY,
                    timestamp=datetime.now(),
                )
            }

            services: dict[str, ServiceHealth] = {
                "kafka": {
                    "service_name": "kafka",
                    "service_type": "message_broker",
                    "is_healthy": True,
                    "status": HealthStatus.HEALTHY,
                    "is_connected": True,
                    "connection_latency": 0.025,
                    "last_successful_connection": datetime.now().isoformat(),
                    "total_operations": 2340,
                    "successful_operations": 2335,
                    "failed_operations": 5,
                    "avg_response_time": 0.045,
                    "max_response_time": 0.200,
                    "slow_operations_count": 15,
                    "error_rate": 0.21,
                    "timestamp": datetime.now().isoformat(),
                }
            }

            return HealthMetrics(
                overall_status=HealthStatus.HEALTHY,
                health_score=95.5,
                system=system,
                workers=workers,
                queues=queues,
                services=services,
            )

        def get_health_status(self) -> dict:
            """Basic health status for /health endpoint."""
            return {"status": HealthStatus.HEALTHY, "timestamp": datetime.now().isoformat(), "health_score": 95.5}

        def get_detailed_health_status(self) -> dict:
            """Detailed health status for /health/detailed endpoint."""
            return {
                "overall_status": HealthStatus.HEALTHY,
                "health_score": 95.5,
                "system": {
                    "status": HealthStatus.HEALTHY,
                    "cpu_usage": 15.7,
                    "memory_usage": 32.4,
                    "uptime_seconds": 7200.5,
                },
                "workers": {"status": HealthStatus.HEALTHY, "active": 2, "idle": 1, "total": 3},
                "queues": {"status": HealthStatus.HEALTHY, "pending_tasks": 12, "processing_tasks": 3},
                "services": {
                    "status": HealthStatus.HEALTHY,
                    "database": {"status": HealthStatus.HEALTHY, "response_time": 0.05},
                    "monitoring": {"status": HealthStatus.HEALTHY},
                },
            }

        def get_readiness_status(self) -> dict:
            """Readiness status for /health/ready endpoint."""
            return {
                "ready": True,
                "timestamp": datetime.now().isoformat(),
                "checks": {"database_connection": True, "queue_accessible": True},
            }

        def get_liveness_status(self) -> dict:
            """Liveness status for /health/live endpoint."""
            return {"alive": True, "timestamp": datetime.now().isoformat(), "uptime": 7200.5}

        def get_metrics(self) -> dict:
            """Performance metrics for /health/metrics endpoint."""
            return {
                "timestamp": datetime.now().isoformat(),
                "metrics": {
                    "requests_total": 12345,
                    "errors_total": 23,
                    "response_time_avg": 0.125,
                    "cpu_usage": 15.7,
                    "memory_usage": 512.8,
                },
            }

        def get_detailed_health(self) -> dict:
            """Alias for get_detailed_health_status for compatibility."""
            return self.get_detailed_health_status()

        def get_worker_status(self) -> dict:
            """Worker status information."""
            return {
                "workers": [
                    {"id": 1, "status": "active", "current_task": "processing"},
                    {"id": 2, "status": "active", "current_task": "monitoring"},
                    {"id": 3, "status": "idle", "current_task": None},
                    {"id": 4, "status": "idle", "current_task": None},
                ],
                "summary": {"total_workers": 4, "active_workers": 2, "idle_workers": 2, "status": HealthStatus.HEALTHY},
            }

        def get_queue_status(self) -> dict:
            """Queue status information."""
            return {
                "queues": [
                    {
                        "name": "main_queue",
                        "pending_tasks": 12,
                        "processing_tasks": 3,
                        "completed_tasks": 1245,
                        "failed_tasks": 8,
                    },
                    {
                        "name": "priority_queue",
                        "pending_tasks": 2,
                        "processing_tasks": 1,
                        "completed_tasks": 334,
                        "failed_tasks": 1,
                    },
                ],
                "summary": {
                    "total_pending": 14,
                    "total_processing": 4,
                    "total_completed": 1579,
                    "total_failed": 9,
                    "status": HealthStatus.HEALTHY,
                },
            }

        def get_system_status(self) -> dict:
            """System status information."""
            return {
                "system": {
                    "status": HealthStatus.HEALTHY,
                    "cpu_usage": 15.7,
                    "memory_usage": 32.4,
                    "disk_usage": 45.2,
                    "network_connections": 23,
                    "system_load": [0.8, 1.2, 1.5],
                    "uptime_seconds": 7200.5,
                },
                "timestamp": datetime.now().isoformat(),
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
    assert data["status"] == HealthStatus.HEALTHY
    assert "health_score" in data


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_health_detailed_handler(aiohttp_client, aiohttp_app):
    """Test detailed health endpoint."""
    client = await aiohttp_client(aiohttp_app)
    resp = await client.get("/health/detailed")
    assert resp.status == 200

    data = await resp.json()
    assert data["overall_status"] == HealthStatus.HEALTHY
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
    assert "health_score" in content
    assert "95.5" in content


def test_handlers_initialization(mock_health_provider):
    """Test HealthHandlers initialization."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    assert handlers.health_service is mock_health_provider


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

    metrics_data = mock_health_provider.get_health_metrics()

    prometheus_output = handlers._format_prometheus_metrics(metrics_data)

    assert "health_score 95.5" in prometheus_output
    assert "system_cpu_percent 15.7" in prometheus_output
    assert "system_memory_percent 32.4" in prometheus_output
    assert 'worker_alerts_processed{worker="worker-1"} 1250' in prometheus_output
    assert 'worker_health_score{worker="worker-1"} 0.95' in prometheus_output


@pytest.mark.asyncio
async def test_handler_error_handling(mock_health_provider):
    """Test error handling in handlers."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/health")

    with patch.object(mock_health_provider, "get_health_status", side_effect=Exception("Test error")):
        response = handlers.health_basic_handler(request)
        assert response.status == 500


@pytest.mark.skipif(AIOHTTP_AVAILABLE, reason="Testing import error handling")
def test_import_error_handling():
    """Test that handlers gracefully handle missing aiohttp."""
    assert not AIOHTTP_AVAILABLE
