"""Integration tests for Health API Server background operation.

Tests the complete server lifecycle with real HTTP requests to all endpoints.
"""

import asyncio
import time
from datetime import datetime

import aiohttp
import pytest

from wazuh_dfn.config import APIConfig
from wazuh_dfn.health.api.server import HealthAPIServer
from wazuh_dfn.health.models import (
    HealthMetrics,
    OverallHealthStatus,
    QueueHealth,
    ServiceHealth,
    SystemHealth,
    WorkerHealth,
    WorkerStatus,
)


class MockHealthProvider:
    """Mock health provider for integration testing."""

    async def get_health_metrics(self) -> HealthMetrics:
        """Return properly structured mock health data."""
        # System health
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

        # Worker health with all required fields
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
            ),
            "worker-2": WorkerHealth(
                worker_name="worker-2",
                timestamp=datetime.now(),
                alerts_processed=890,
                processing_rate=1.1,
                avg_processing_time=0.125,
                recent_avg_processing_time=0.180,
                min_processing_time=0.010,
                max_processing_time=0.500,
                slow_alerts_count=12,
                extremely_slow_alerts_count=2,
                last_processing_time=0.250,
                last_alert_id="alert-11890",
                status=WorkerStatus.STALLED,
                health_score=0.45,
            ),
        }

        # Queue health with all required fields
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
            ),
            "priority_queue": QueueHealth(
                queue_name="priority_queue",
                current_size=750,
                max_size=1000,
                utilization_percentage=75.0,
                total_processed=1234,
                processing_rate=3.2,
                queue_full_events=15,
                avg_wait_time=2.5,
                status=OverallHealthStatus.DEGRADED,
                timestamp=datetime.now(),
            ),
        }

        # Service health with all required fields
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
            ),
            "file_monitor": ServiceHealth(
                service_name="file_monitor",
                service_type="file_system",
                is_connected=True,
                connection_latency=0.001,
                last_successful_connection=datetime.now(),
                total_operations=890,
                successful_operations=882,
                failed_operations=8,
                avg_response_time=0.120,
                max_response_time=1.500,
                slow_operations_count=25,
                status=OverallHealthStatus.DEGRADED,
                error_rate=0.90,
                timestamp=datetime.now(),
            ),
        }

        return HealthMetrics(
            overall_status=OverallHealthStatus.DEGRADED,
            health_score=72.5,
            system=system,
            workers=workers,
            queues=queues,
            services=services,
        )

    async def get_health_status(self) -> dict:
        """Basic health status for /health endpoint."""
        return {"status": "healthy", "timestamp": datetime.now().isoformat(), "health_score": 95.5}

    async def get_detailed_health_status(self) -> dict:
        """Detailed health status for /health/detailed endpoint."""
        return {
            "overall_status": "healthy",
            "health_score": 95.5,
            "system": {"status": "healthy", "cpu_usage": 15.7, "memory_usage": 32.4, "uptime_seconds": 7200.5},
            "workers": {"status": "healthy", "active": 2, "idle": 1, "total": 3},
            "queues": {"status": "healthy", "pending_tasks": 12, "processing_tasks": 3},
            "services": {
                "status": "healthy",
                "database": {"status": "healthy", "response_time": 0.05},
                "monitoring": {"status": "healthy"},
            },
        }

    async def get_readiness_status(self) -> dict:
        """Readiness status for /health/ready endpoint."""
        return {
            "ready": True,
            "timestamp": datetime.now().isoformat(),
            "checks": {"database_connection": True, "queue_accessible": True},
        }

    async def get_liveness_status(self) -> dict:
        """Liveness status for /health/live endpoint."""
        return {"alive": True, "timestamp": datetime.now().isoformat(), "uptime": 7200.5}

    async def get_metrics(self) -> dict:
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

    async def get_detailed_health(self) -> dict:
        """Alias for get_detailed_health_status for compatibility."""
        return await self.get_detailed_health_status()

    async def get_worker_status(self) -> dict:
        """Worker status information."""
        return {
            "workers": [
                {"id": 1, "status": "active", "current_task": "processing"},
                {"id": 2, "status": "active", "current_task": "monitoring"},
                {"id": 3, "status": "idle", "current_task": None},
                {"id": 4, "status": "idle", "current_task": None},
            ],
            "summary": {"total_workers": 4, "active_workers": 2, "idle_workers": 2, "status": "healthy"},
        }

    async def get_queue_status(self) -> dict:
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
                "status": "healthy",
            },
        }

    async def get_system_status(self) -> dict:
        """System status information."""
        return {
            "system": {
                "status": "healthy",
                "cpu_usage": 15.7,
                "memory_usage": 32.4,
                "disk_usage": 45.2,
                "network_connections": 23,
                "system_load": [0.8, 1.2, 1.5],
                "uptime_seconds": 7200.5,
            },
            "timestamp": datetime.now().isoformat(),
        }


@pytest.fixture(scope="module")
def api_config():
    """Create API configuration for testing."""
    return APIConfig(
        enabled=True, host="127.0.0.1", port=8081, auth_token=None, allowed_ips=["127.0.0.1", "::1"], rate_limit=1000
    )


@pytest.fixture(scope="module")
def health_provider():
    """Create mock health provider for testing."""
    return MockHealthProvider()


@pytest.fixture(scope="module")
def event_loop():
    """Create a module-scoped event loop for all tests."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture(scope="module")
def running_server(event_loop, api_config, health_provider):
    """Create and start health API server for all tests in the module."""

    async def setup_and_run():
        server = HealthAPIServer(health_provider, api_config)
        await server.start()
        await _wait_for_server_ready(f"http://{api_config.host}:{api_config.port}")
        return server

    server = event_loop.run_until_complete(setup_and_run())

    yield server

    # Cleanup
    async def cleanup():
        await server.stop()

    event_loop.run_until_complete(cleanup())


async def _wait_for_server_ready(base_url: str, timeout: int = 10) -> bool:
    """Wait for server to become ready with timeout."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            async with aiohttp.ClientSession() as session, session.get(f"{base_url}/health") as response:
                if response.status == 200:
                    return True
        except Exception:  # noqa: S110
            pass
        await asyncio.sleep(0.1)

    raise TimeoutError(f"Server at {base_url} not ready after {timeout}s")


async def _test_endpoint(
    session: aiohttp.ClientSession, base_url: str, endpoint: str, expected_keys: list[str] | None = None
) -> dict:
    """Test a single endpoint and validate response structure."""
    if expected_keys is None:
        expected_keys = []
    url = f"{base_url}{endpoint}"
    start_time = time.time()

    try:
        async with session.get(url) as response:
            response_time = round((time.time() - start_time) * 1000, 2)

            if response.status == 200:
                content_type = response.headers.get("content-type", "")

                if endpoint == "/metrics":
                    # Prometheus format is plain text
                    content = await response.text()
                    return {
                        "endpoint": endpoint,
                        "status": response.status,
                        "success": True,
                        "time_ms": response_time,
                        "size": len(content),
                        "content_type": content_type,
                        "content": content[:200],  # First 200 chars for validation
                    }
                else:
                    # JSON response
                    data = await response.json()

                    # Validate expected keys if provided
                    if expected_keys:
                        missing_keys = [key for key in expected_keys if key not in data]
                        if missing_keys:
                            return {
                                "endpoint": endpoint,
                                "status": response.status,
                                "success": False,
                                "time_ms": response_time,
                                "error": f"Missing keys: {missing_keys}",
                                "size": len(str(data)),
                                "content_type": content_type,
                            }

                    return {
                        "endpoint": endpoint,
                        "status": response.status,
                        "success": True,
                        "time_ms": response_time,
                        "size": len(str(data)),
                        "content_type": content_type,
                        "data": data,
                    }
            else:
                error_text = await response.text()
                return {
                    "endpoint": endpoint,
                    "status": response.status,
                    "success": False,
                    "time_ms": response_time,
                    "error": error_text,
                    "size": len(error_text),
                    "content_type": response.headers.get("content-type", ""),
                }

    except Exception as e:
        return {
            "endpoint": endpoint,
            "status": None,
            "success": False,
            "time_ms": round((time.time() - start_time) * 1000, 2),
            "error": str(e),
            "size": 0,
            "content_type": "error",
        }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_health_endpoint(running_server, api_config):
    """Test basic health endpoint."""
    base_url = f"http://{api_config.host}:{api_config.port}"

    async with aiohttp.ClientSession() as session:
        result = await _test_endpoint(session, base_url, "/health", ["status", "timestamp", "health_score"])

        assert result["success"], f"Health endpoint failed: {result.get('error')}"
        assert result["status"] == 200
        assert "status" in result["data"]
        assert "timestamp" in result["data"]
        assert "health_score" in result["data"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_detailed_health_endpoint(running_server, api_config):
    """Test detailed health endpoint."""
    base_url = f"http://{api_config.host}:{api_config.port}"

    async with aiohttp.ClientSession() as session:
        result = await _test_endpoint(
            session,
            base_url,
            "/health/detailed",
            ["overall_status", "health_score", "system", "workers", "queues", "services"],
        )

        assert result["success"], f"Detailed health endpoint failed: {result.get('error')}"
        assert result["status"] == 200
        assert "overall_status" in result["data"]
        assert "system" in result["data"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_metrics_endpoint(running_server, api_config):
    """Test Prometheus metrics endpoint."""
    base_url = f"http://{api_config.host}:{api_config.port}"

    async with aiohttp.ClientSession() as session:
        result = await _test_endpoint(session, base_url, "/metrics")

        assert result["success"], f"Metrics endpoint failed: {result.get('error')}"
        assert result["status"] == 200
        assert "text/plain" in result["content_type"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_worker_status_endpoint(running_server, api_config):
    """Test worker status endpoint."""
    base_url = f"http://{api_config.host}:{api_config.port}"

    async with aiohttp.ClientSession() as session:
        result = await _test_endpoint(session, base_url, "/status/workers", ["workers", "summary"])

        assert result["success"], f"Worker status endpoint failed: {result.get('error')}"
        assert result["status"] == 200
        assert "workers" in result["data"]
        assert "summary" in result["data"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_queue_status_endpoint(running_server, api_config):
    """Test queue status endpoint."""
    base_url = f"http://{api_config.host}:{api_config.port}"

    async with aiohttp.ClientSession() as session:
        result = await _test_endpoint(session, base_url, "/status/queue", ["queues", "summary"])

        assert result["success"], f"Queue status endpoint failed: {result.get('error')}"
        assert result["status"] == 200
        assert "queues" in result["data"]
        assert "summary" in result["data"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_system_status_endpoint(running_server, api_config):
    """Test system status endpoint."""
    base_url = f"http://{api_config.host}:{api_config.port}"

    async with aiohttp.ClientSession() as session:
        result = await _test_endpoint(session, base_url, "/status/system", ["system", "timestamp"])

        assert result["success"], f"System status endpoint failed: {result.get('error')}"
        assert result["status"] == 200
        assert "system" in result["data"]
        assert "timestamp" in result["data"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_all_endpoints_performance(running_server, api_config):
    """Test all endpoints for performance and correctness."""
    base_url = f"http://{api_config.host}:{api_config.port}"

    endpoint_specs = [
        {
            "path": "/health",
            "expected_keys": ["status", "timestamp", "health_score"],
            "description": "Basic health status",
        },
        {
            "path": "/health/detailed",
            "expected_keys": ["overall_status", "health_score", "system", "workers", "queues", "services"],
            "description": "Detailed health metrics",
        },
        {"path": "/metrics", "expected_keys": None, "description": "Prometheus metrics"},  # Prometheus format, not JSON
        {"path": "/status/workers", "expected_keys": ["workers", "summary"], "description": "Worker status"},
        {"path": "/status/queue", "expected_keys": ["queues", "summary"], "description": "Queue status"},
        {"path": "/status/system", "expected_keys": ["system", "timestamp"], "description": "System status"},
    ]

    async with aiohttp.ClientSession() as session:
        results = []

        for spec in endpoint_specs:
            result = await _test_endpoint(session, base_url, spec["path"], spec["expected_keys"])
            results.append(result)

            # All endpoints should succeed
            assert result["success"], f"Endpoint {spec['path']} failed: {result.get('error')}"
            assert result["status"] == 200

            # Performance check - should respond within 1000ms
            assert result["time_ms"] < 1000, f"Endpoint {spec['path']} too slow: {result['time_ms']}ms"

    # Summary checks
    successful = sum(1 for r in results if r["success"])
    total = len(results)

    assert successful == total, f"Only {successful}/{total} endpoints succeeded"

    avg_response_time = sum(r["time_ms"] for r in results) / total
    assert avg_response_time < 500, f"Average response time too high: {avg_response_time:.1f}ms"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_server_lifecycle(health_provider):
    """Test server start and stop lifecycle using a different port."""
    # Use a different port to avoid conflict with running_server fixture
    lifecycle_config = APIConfig(
        enabled=True,
        host="127.0.0.1",
        port=8082,  # Different port
        auth_token=None,
        allowed_ips=["127.0.0.1", "::1"],
        rate_limit=1000,
    )

    server = HealthAPIServer(health_provider, lifecycle_config)

    # Test initial state
    assert not server.is_running()

    # Test start
    await server.start()
    assert server.is_running()

    # Test server responds
    base_url = f"http://{lifecycle_config.host}:{lifecycle_config.port}"
    await _wait_for_server_ready(base_url)

    async with aiohttp.ClientSession() as session, session.get(f"{base_url}/health") as response:
        assert response.status == 200

    # Test stop
    await server.stop()
    assert not server.is_running()

    # Test server no longer responds
    with pytest.raises((aiohttp.ClientError, OSError)):  # Connection error expected
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base_url}/health", timeout=aiohttp.ClientTimeout(total=1)) as response:
                pass
