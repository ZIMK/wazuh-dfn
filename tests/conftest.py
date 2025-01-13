"""Test configuration and fixtures."""

import logging
import os
import shutil
import tempfile
import threading
from unittest.mock import MagicMock, patch

import pytest

from wazuh_dfn.config import Config, DFNConfig, KafkaConfig, LogConfig, MiscConfig, WazuhConfig
from wazuh_dfn.services.max_size_queue import MaxSizeQueue
from wazuh_dfn.services.wazuh_service import WazuhService
from wazuh_dfn.validators import ConfigValidator


@pytest.fixture(autouse=True)
def disable_path_validation():
    """Disable path validation for all tests."""
    ConfigValidator.skip_path_validation = True
    yield
    ConfigValidator.skip_path_validation = False


@pytest.fixture(autouse=True)
def setup_logging():
    """Configure logging for tests."""
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s"
    )


@pytest.fixture
def alerts_dir():
    """Create a temporary alerts directory."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_config(tmp_path):
    """Create a sample configuration for testing."""
    config = Config()
    config.dfn = DFNConfig(
        dfn_id="test-id", dfn_broker="test:9092", dfn_ca="ca.pem", dfn_cert="cert.pem", dfn_key="key.pem"
    )
    alerts_file = tmp_path / "alerts.json"
    alerts_file.touch()  # Create the file
    config.wazuh = WazuhConfig(
        json_alert_file=str(alerts_file),
        unix_socket_path="/var/ossec/queue/sockets/queue",
        max_event_size=65535,
        json_alert_prefix="{",
        json_alert_suffix="}",
        json_alert_file_poll_interval=1.0,
        max_retries=5,
        retry_interval=5,
    )
    config.kafka = KafkaConfig(
        timeout=60,
        retry_interval=5,
        connection_max_retries=5,
        send_max_retries=5,
        max_wait_time=60,
        admin_timeout=10,
        producer_config={},
    )
    config.log = LogConfig(
        console=True,
        file_path=str(tmp_path / "wazuh-dfn.log"),
        interval=1,
        level="DEBUG",
    )
    config.misc = MiscConfig(
        num_workers=1,
    )
    return config


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing."""
    return {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "description": "Test alert"},
        "agent": {"name": "test-agent", "id": "001"},
        "location": "test",
        "full_log": "Test alert message",
    }


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def shutdown_event():
    """Create a shutdown event for testing."""
    return threading.Event()


@pytest.fixture
def cleanup_threads():
    """Fixture to ensure threads are cleaned up after tests."""
    yield
    for thread in threading.enumerate():
        if thread != threading.current_thread():
            thread.join(timeout=1.0)


@pytest.fixture
def mock_producer():
    """Create a mock Kafka producer."""
    with patch("confluent_kafka.Producer") as mock:
        mock.return_value = MagicMock()
        yield mock


@pytest.fixture
def mock_socket(monkeypatch):
    """Mock socket for testing."""
    mock_socket = MagicMock()
    mock_socket_class = MagicMock(return_value=mock_socket)

    def mock_connect(addr):
        # Always treat connections as AF_INET for testing
        if isinstance(addr, str):
            # Convert Unix socket path to a tuple for Windows testing
            addr = ("127.0.0.1", 1514)  # Default Wazuh port NOSONAR
        return None

    mock_socket.connect = mock_connect
    mock_socket.close = MagicMock()
    mock_socket.send = MagicMock()
    mock_socket.recv = MagicMock(return_value=b"")
    mock_socket.settimeout = MagicMock()

    # Mock socket creation
    monkeypatch.setattr("socket.socket", mock_socket_class)
    monkeypatch.setattr("socket.AF_INET", 2)
    monkeypatch.setattr("socket.SOCK_DGRAM", 2)

    return mock_socket


@pytest.fixture
def wazuh_service(sample_config, mock_socket):
    """Create a WazuhService instance with mocked socket."""
    service = WazuhService(config=sample_config.wazuh)
    service._socket = mock_socket
    # Mock error handling methods
    service.send_error = MagicMock()
    service._send_event = MagicMock()
    service.connect = MagicMock()
    return service


@pytest.fixture
def kafka_service(sample_config, mock_producer, wazuh_service, shutdown_event):
    """Create a KafkaService instance with mocked dependencies."""
    from wazuh_dfn.services.kafka_service import KafkaService

    service = KafkaService(
        config=sample_config.kafka,
        dfn_config=sample_config.dfn,
        wazuh_handler=wazuh_service,
        shutdown_event=shutdown_event,
    )

    # Mock the producer to avoid actual Kafka connections
    service.producer = mock_producer
    return service


@pytest.fixture
def alerts_service(sample_config, kafka_service, wazuh_service):
    """Create an AlertsService instance with mocked dependencies."""
    from wazuh_dfn.services.alerts_service import AlertsService

    return AlertsService(sample_config.misc, kafka_service, wazuh_service)


@pytest.fixture
def alert_queue():
    """Create an alert queue for testing."""
    return MaxSizeQueue()


@pytest.fixture
def alerts_worker_service(sample_config, alert_queue, alerts_service, shutdown_event):
    """Create an AlertsWorkerService instance with mocked dependencies."""
    from wazuh_dfn.services.alerts_worker_service import AlertsWorkerService

    return AlertsWorkerService(sample_config.misc, alert_queue, alerts_service, shutdown_event)


@pytest.fixture
def alerts_watcher_service(sample_config, alert_queue, shutdown_event):
    """Create an AlertsWatcherService instance for testing."""
    from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService

    # Create the alerts directory if it doesn't exist
    os.makedirs(sample_config.wazuh.alerts_directory, exist_ok=True)

    # Create the service
    service = AlertsWatcherService(sample_config.wazuh, alert_queue, shutdown_event)
    yield service

    # Cleanup
    try:
        service.stop()
    except Exception:
        pass
