"""Tests for wazuh_dfn.health.api.handlers module."""

import json
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


@pytest.mark.asyncio
async def test_health_basic_handler_exception(mock_health_provider):
    """Test health basic handler exception handling."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/health")

    # Test exception in get_health_status
    with patch.object(mock_health_provider, "get_health_status", side_effect=Exception("Health check failed")):
        response = handlers.health_basic_handler(request)
        assert response.status == 500
        data = json.loads(str(response.text))
        assert "message" in data
        assert data["status"] == HealthStatus.ERROR


@pytest.mark.asyncio
async def test_health_detailed_handler_exception(mock_health_provider):
    """Test health detailed handler exception handling."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/health/detailed")

    # Test exception in get_detailed_health_status
    with patch.object(
        mock_health_provider, "get_detailed_health_status", side_effect=Exception("Detailed health check failed")
    ):
        response = handlers.health_detailed_handler(request)
        assert response.status == 500
        data = json.loads(str(response.text))
        assert "message" in data
        assert data["status"] == HealthStatus.ERROR


@pytest.mark.asyncio
async def test_health_detailed_degraded_status(mock_health_provider):
    """Test detailed health endpoint with degraded status."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)

    # Mock degraded health status for detailed endpoint
    degraded_status = {
        "overall_status": HealthStatus.DEGRADED,
        "health_score": 65.0,
        "timestamp": datetime.now().isoformat(),
        "system": {
            "status": HealthStatus.DEGRADED,
            "cpu_usage": 85.7,
            "memory_usage": 92.4,
            "uptime_seconds": 7200.5,
        },
        "workers": {"status": HealthStatus.DEGRADED, "active": 1, "idle": 2, "total": 3},
        "queues": {"status": HealthStatus.HEALTHY, "pending_tasks": 12, "processing_tasks": 3},
        "services": {
            "status": HealthStatus.DEGRADED,
            "database": {"status": HealthStatus.DEGRADED, "response_time": 2.5},
            "monitoring": {"status": HealthStatus.HEALTHY},
        },
    }

    with patch.object(mock_health_provider, "get_detailed_health_status", return_value=degraded_status):
        request = make_mocked_request("GET", "/health/detailed")
        response = handlers.health_detailed_handler(request)
        assert response.status == 200  # Still 200 for degraded status
        data = json.loads(str(response.text))
        assert data["overall_status"] == HealthStatus.DEGRADED


@pytest.mark.asyncio
async def test_health_detailed_error_status(mock_health_provider):
    """Test detailed health endpoint with error status."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)

    # Mock error health status for detailed endpoint
    error_status = {
        "overall_status": HealthStatus.ERROR,
        "health_score": 15.0,
        "timestamp": datetime.now().isoformat(),
        "system": {
            "status": HealthStatus.ERROR,
            "cpu_usage": 95.7,
            "memory_usage": 98.4,
            "uptime_seconds": 7200.5,
        },
        "workers": {"status": HealthStatus.ERROR, "active": 0, "idle": 0, "total": 3},
        "queues": {"status": HealthStatus.ERROR, "pending_tasks": 500, "processing_tasks": 0},
        "services": {
            "status": HealthStatus.ERROR,
            "database": {"status": HealthStatus.ERROR, "response_time": 10.0},
            "monitoring": {"status": HealthStatus.ERROR},
        },
    }

    with patch.object(mock_health_provider, "get_detailed_health_status", return_value=error_status):
        request = make_mocked_request("GET", "/health/detailed")
        response = handlers.health_detailed_handler(request)
        assert response.status == 503  # Service unavailable for error status
        data = json.loads(str(response.text))
        assert data["overall_status"] == HealthStatus.ERROR


@pytest.mark.asyncio
async def test_readiness_handler_exception(mock_health_provider):
    """Test readiness handler exception handling."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/ready")

    # Test exception in get_readiness_status
    with patch.object(mock_health_provider, "get_readiness_status", side_effect=Exception("Readiness check failed")):
        response = handlers.readiness_handler(request)
        assert response.status == 500
        data = json.loads(str(response.text))
        assert "ready" in data
        assert data["ready"] is False


@pytest.mark.asyncio
async def test_liveness_handler_exception(mock_health_provider):
    """Test liveness handler exception handling."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/live")

    # Test exception in get_liveness_status
    with patch.object(mock_health_provider, "get_liveness_status", side_effect=Exception("Liveness check failed")):
        response = handlers.liveness_handler(request)
        assert response.status == 500
        data = json.loads(str(response.text))
        assert "alive" in data
        assert data["alive"] is False


@pytest.mark.asyncio
async def test_health_degraded_status(mock_health_provider):
    """Test health endpoints with degraded status."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)

    # Mock degraded health status
    degraded_status = {
        "status": HealthStatus.DEGRADED,
        "health_score": 65.0,
        "timestamp": datetime.now().isoformat(),
        "message": "System degraded",
    }

    with patch.object(mock_health_provider, "get_health_status", return_value=degraded_status):
        request = make_mocked_request("GET", "/health")
        response = handlers.health_basic_handler(request)
        assert response.status == 200  # Still 200 but with degraded status
        data = json.loads(str(response.text))
        assert data["status"] == HealthStatus.DEGRADED


@pytest.mark.asyncio
async def test_health_error_status(mock_health_provider):
    """Test health endpoints with error status."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)

    # Mock error health status
    error_status = {
        "status": HealthStatus.ERROR,
        "health_score": 25.0,
        "timestamp": datetime.now().isoformat(),
        "message": "System error",
    }

    with patch.object(mock_health_provider, "get_health_status", return_value=error_status):
        request = make_mocked_request("GET", "/health")
        response = handlers.health_basic_handler(request)
        assert response.status == 503  # Service unavailable for error status
        data = json.loads(str(response.text))
        assert data["status"] == HealthStatus.ERROR


@pytest.mark.asyncio
async def test_readiness_not_ready(mock_health_provider):
    """Test readiness endpoint when not ready."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/ready")

    # Mock not ready status
    not_ready_status = {
        "ready": False,
        "timestamp": datetime.now().isoformat(),
        "checks": {"database_connection": False, "queue_accessible": True},
    }

    with patch.object(mock_health_provider, "get_readiness_status", return_value=not_ready_status):
        response = handlers.readiness_handler(request)
        assert response.status == 503  # Service unavailable when not ready
        data = json.loads(str(response.text))
        assert data["ready"] is False


@pytest.mark.asyncio
async def test_liveness_not_alive(mock_health_provider):
    """Test liveness endpoint when not alive."""
    if not AIOHTTP_AVAILABLE:
        pytest.skip("aiohttp not available")

    handlers = HealthHandlers(mock_health_provider)
    request = make_mocked_request("GET", "/live")

    # Mock not alive status
    not_alive_status = {"alive": False, "timestamp": datetime.now().isoformat(), "uptime": 7200.5}

    with patch.object(mock_health_provider, "get_liveness_status", return_value=not_alive_status):
        response = handlers.liveness_handler(request)
        assert response.status == 503  # Service unavailable when not alive
        data = json.loads(str(response.text))
        assert data["alive"] is False


@pytest.mark.skipif(AIOHTTP_AVAILABLE, reason="Testing import error handling")
def test_import_error_handling():
    """Test that handlers gracefully handle missing aiohttp."""
    assert not AIOHTTP_AVAILABLE
