"""Test configuration and fixtures."""

import asyncio
import logging
import shutil
import tempfile
from contextlib import suppress
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from wazuh_dfn.config import Config, DFNConfig, KafkaConfig, LogConfig, MiscConfig, WazuhConfig
from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue
from wazuh_dfn.services.wazuh_service import WazuhService


@pytest.fixture(autouse=True)
def disable_path_validation():
    """Disable path validation for all tests."""
    # Update: With Pydantic we need to modify the skip_path_validation attribute
    config = Config()
    config.dfn.skip_path_validation = True
    yield
    config.dfn.skip_path_validation = False


@pytest.fixture(autouse=True)
def setup_logging():
    """Configure logging for tests."""
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


@pytest.fixture
def alerts_dir():
    """Create a temporary alerts directory."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_config(tmp_path):
    """Create a sample configuration for testing."""
    alerts_file = tmp_path / "alerts.json"
    alerts_file.touch()  # Create the file

    config = Config(
        dfn=DFNConfig(
            dfn_id="test-id",
            dfn_broker="test:9092",
            dfn_ca="ca.pem",
            dfn_cert="cert.pem",
            dfn_key="key.pem",
            skip_path_validation=True,  # Update reference here
        ),
        wazuh=WazuhConfig(
            json_alert_file=str(alerts_file),
            unix_socket_path="/var/ossec/queue/sockets/queue",
            max_event_size=65535,
            json_alert_prefix="{",
            json_alert_suffix="}",
            json_alert_file_poll_interval=1.0,
            max_retries=5,
            retry_interval=5,
        ),
        kafka=KafkaConfig(
            timeout=60,
            retry_interval=5,
            connection_max_retries=5,
            send_max_retries=5,
            max_wait_time=60,
            admin_timeout=10,
            producer_config={},
        ),
        log=LogConfig(
            console=True,
            file_path=str(tmp_path / "wazuh-dfn.log"),
            interval=1,
            level="DEBUG",
        ),
        misc=MiscConfig(
            num_workers=1,
        ),
    )
    return config


@pytest.fixture(scope="session")
def test_data_dir():
    """Provide a temporary directory for test data that persists for the test session."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname


@pytest.fixture
def sample_alert():
    """Return a sample valid alert for testing."""
    return {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "description": "Test alert"},
        "agent": {"name": "test-agent", "id": "001"},
        "location": "test",
        "full_log": "Test alert message",
        "alert": {
            "id": "test-1",
            "timestamp": "2024-01-01T00:00:00.000Z",
            "data": {"field1": "value1", "field2": "value2"},
        },
    }


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def shutdown_event():
    """Create a shutdown event for testing."""
    return asyncio.Event()


@pytest.fixture
def event_loop():
    """Create and yield a new event loop for each test."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop

    # Close all pending tasks before closing the loop
    pending = asyncio.all_tasks(loop)
    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    # Make sure to properly clean up the loop
    loop.run_until_complete(loop.shutdown_asyncgens())

    # Close the loop and ensure it's really closed
    loop.close()

    # Set the event loop policy's event loop to None to prevent warnings
    asyncio.set_event_loop(None)


@pytest.fixture
def mock_producer(event_loop):
    """Create a mock Kafka producer."""
    with patch("aiokafka.AIOKafkaProducer") as mock:
        producer_mock = AsyncMock()

        # Create a future for start
        start_future = asyncio.Future(loop=event_loop)
        start_future.set_result(None)
        producer_mock.start.return_value = start_future

        # Create a future for stop
        stop_future = asyncio.Future(loop=event_loop)
        stop_future.set_result(None)
        producer_mock.stop.return_value = stop_future

        mock.return_value = producer_mock
        yield mock


@pytest.fixture
def mock_socket(monkeypatch):
    """Mock socket for testing."""
    mock_socket = AsyncMock()
    # The socket class itself is mocked with MagicMock since it's not an async class
    mock_socket_class = MagicMock(return_value=mock_socket)

    # Define an async connect method that will be used by the instance
    async def mock_connect(addr):
        # Always treat connections as AF_INET for testing
        if isinstance(addr, str):
            # Convert Unix socket path to a tuple for Windows testing
            addr = ("127.0.0.1", 1514)  # Default Wazuh port NOSONAR

    # Assign the async functions
    mock_socket.connect = mock_connect
    mock_socket.send = AsyncMock()
    mock_socket.recv = AsyncMock(return_value=b"")
    # Non-async methods can still use MagicMock
    mock_socket.settimeout = MagicMock()

    # Mock socket creation
    monkeypatch.setattr("socket.socket", mock_socket_class)
    monkeypatch.setattr("socket.AF_INET", 2)
    monkeypatch.setattr("socket.SOCK_DGRAM", 2)

    return mock_socket


@pytest_asyncio.fixture
async def wazuh_service(sample_config):
    """Create a WazuhService instance with mocked socket."""
    service = WazuhService(config=sample_config.wazuh)

    # Mock error handling methods - using AsyncMock for async methods
    service.send_error = AsyncMock()
    service._send_event = AsyncMock()
    service.connect = AsyncMock()
    return service


@pytest_asyncio.fixture
async def kafka_service(sample_config, mock_producer, wazuh_service, shutdown_event):
    """Create a KafkaService instance with mocked dependencies."""
    from wazuh_dfn.services.kafka_service import KafkaService

    service = KafkaService(
        config=sample_config.kafka,
        dfn_config=sample_config.dfn,
        wazuh_service=wazuh_service,
        shutdown_event=shutdown_event,
    )
    return service


@pytest_asyncio.fixture
async def alerts_service(sample_config, kafka_service, wazuh_service):
    """Create an AlertsService instance with mocked dependencies."""
    from wazuh_dfn.services.alerts_service import AlertsService

    return AlertsService(sample_config.misc, kafka_service, wazuh_service)


@pytest.fixture
def alert_queue():
    """Create an alert queue for testing."""
    return AsyncMaxSizeQueue()


@pytest_asyncio.fixture
async def alerts_worker_service(sample_config, alert_queue, alerts_service, shutdown_event):
    """Create an AlertsWorkerService instance with mocked dependencies."""
    from wazuh_dfn.services.alerts_worker_service import AlertsWorkerService

    return AlertsWorkerService(sample_config.misc, alert_queue, alerts_service, shutdown_event)


@pytest_asyncio.fixture
async def alerts_watcher_service(sample_config, alert_queue, shutdown_event):
    """Create an AlertsWatcherService instance for testing."""
    from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService

    # Create the service
    service = AlertsWatcherService(sample_config.wazuh, alert_queue, shutdown_event)
    yield service

    # Cleanup
    with suppress(Exception):
        await service.stop()
