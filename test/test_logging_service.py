"""Test module for Logging Service."""

import logging
import queue
import threading
import time
from unittest.mock import MagicMock, patch

import psutil
import pytest

from wazuh_dfn.config import LogConfig
from wazuh_dfn.exceptions import ConfigValidationError
from wazuh_dfn.services.logging_service import LoggingService


@pytest.fixture
def mock_services():
    """Create mock services for testing."""
    return {
        "alert_queue": queue.Queue(),
        "kafka_service": MagicMock(),
        "alerts_watcher_service": MagicMock(),
        "alerts_worker_service": MagicMock(),
        "shutdown_event": threading.Event(),
    }


@pytest.fixture
def sample_log_config(tmp_path, monkeypatch):
    """Create a sample log configuration."""
    # Use a temporary file path but don't create it
    log_file = tmp_path / "test.log"
    log_file.touch()
    return LogConfig(console=True, file_path=str(log_file), level="INFO", interval=1)


@pytest.fixture
def logging_service(sample_log_config, mock_services):
    """Create a LoggingService instance for testing."""
    return LoggingService(
        config=sample_log_config,
        alert_queue=mock_services["alert_queue"],
        kafka_service=mock_services["kafka_service"],
        alerts_watcher_service=mock_services["alerts_watcher_service"],
        alerts_worker_service=mock_services["alerts_worker_service"],
        shutdown_event=mock_services["shutdown_event"],
    )


def test_logging_service_initialization(logging_service, sample_log_config, mock_services):
    """Test LoggingService initialization."""
    assert logging_service.config == sample_log_config
    assert logging_service.alert_queue == mock_services["alert_queue"]
    assert logging_service.kafka_service == mock_services["kafka_service"]
    assert logging_service.alerts_watcher_service == mock_services["alerts_watcher_service"]
    assert logging_service.alerts_worker_service == mock_services["alerts_worker_service"]
    assert logging_service.shutdown_event == mock_services["shutdown_event"]
    assert isinstance(logging_service.process, psutil.Process)


def test_logging_service_invalid_config(tmp_path):
    """Test LoggingService initialization with invalid config."""
    # Create a temporary valid log file
    valid_log_file = tmp_path / "test.log"
    valid_log_file.touch()

    # Test invalid level
    with pytest.raises(ConfigValidationError):
        LogConfig(console=True, file_path=str(valid_log_file), level="INVALID_LEVEL", interval=1)  # Invalid level

    # Test invalid interval
    with pytest.raises(ConfigValidationError):
        LogConfig(console=True, file_path=str(valid_log_file), level="INFO", interval=-1)  # Invalid interval


def test_logging_service_log_stats(logging_service, caplog):
    """Test LoggingService statistics logging."""
    with caplog.at_level(logging.INFO):
        # Mock observer service monitor
        logging_service.alerts_watcher_service.monitor = MagicMock()
        current_time = time.time()
        from datetime import datetime

        logging_service.alerts_watcher_service.monitor.latest_queue_put = datetime.fromtimestamp(current_time)

        # Mock kafka service attributes
        logging_service.kafka_service.producer = MagicMock()

        # Call log stats
        logging_service._log_stats()

        # Verify logs
        assert "Monitoring: Number of objects in alert queue" in caplog.text
        assert "Current memory usage" in caplog.text
        assert "Current open files" in caplog.text
        assert "Kafka producer is alive" in caplog.text
        assert "Alerts worker service is running" in caplog.text
        assert "Last alert queued at" in caplog.text


def test_logging_service_log_stats_no_observer(logging_service, caplog):
    """Test LoggingService statistics logging without observer."""
    with caplog.at_level(logging.INFO):
        # Set monitor to None
        logging_service.alerts_watcher_service.monitor = None

        # Call log stats
        logging_service._log_stats()

        # Verify only basic stats are logged
        assert "Monitoring: Number of objects in alert queue" in caplog.text
        assert "Current memory usage" in caplog.text
        assert "Current open files" in caplog.text
        assert "Last alert queued at" not in caplog.text


def test_logging_service_start_stop(logging_service):
    """Test LoggingService start and stop functionality."""
    # Start service in a separate thread
    service_thread = threading.Thread(target=logging_service.start)
    service_thread.daemon = True
    service_thread.start()

    # Let it run for a bit
    time.sleep(2)

    # Signal shutdown
    logging_service.shutdown_event.set()

    # Stop service
    logging_service.stop()

    # Wait for thread to finish
    service_thread.join(timeout=5)
    assert not service_thread.is_alive()


@patch("psutil.Process")
def test_logging_service_memory_error(mock_process, logging_service, caplog):
    """Test LoggingService handling of memory access errors."""
    with caplog.at_level(logging.ERROR):
        # Mock process to raise error
        mock_process_instance = mock_process.return_value
        mock_process_instance.memory_percent.side_effect = psutil.AccessDenied("Test error")
        mock_process_instance.open_files.return_value = []  # Prevent additional errors
        logging_service.process = mock_process_instance

        # Call log stats
        logging_service._log_stats()

        # Verify error handling
        assert "Error getting memory usage" in caplog.text
        assert "Test error" in caplog.text


def test_logging_service_error_handling(logging_service, caplog):
    """Test LoggingService error handling during operation."""
    with caplog.at_level(logging.ERROR):
        # Mock _log_stats to raise an error
        with patch.object(logging_service, "_log_stats") as mock_log_stats:
            # Set up the mock to raise an exception
            mock_log_stats.side_effect = Exception("Test error")

            try:
                # Start the service which should trigger the error
                logging_service.start()
            except Exception:
                pass  # Expected exception

            # Verify the error was logged
            assert any("Error in logging service: Test error" in record.message for record in caplog.records)
