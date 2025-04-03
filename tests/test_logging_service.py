"""Test module for Logging Service."""

import asyncio
import contextlib
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import psutil
import pytest
from pydantic import ValidationError

from wazuh_dfn.config import LogConfig
from wazuh_dfn.services.logging_service import LoggingService


@pytest.fixture
def mock_services():
    """Create mock services for testing."""
    return {
        "alert_queue": MagicMock(),
        "kafka_service": MagicMock(),
        "alerts_watcher_service": MagicMock(),
        "alerts_worker_service": MagicMock(),
        "shutdown_event": asyncio.Event(),
    }


@pytest.fixture
def sample_log_config(tmp_path, monkeypatch):
    """Create a sample log configuration."""
    # Use a temporary file path but don't create it
    log_file = tmp_path / "test.log"
    log_file.touch()
    return LogConfig(console=True, file_path=str(log_file), level="INFO", interval=1, keep_files=7)


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


@pytest.mark.asyncio
async def test_logging_service_initialization(logging_service, sample_log_config, mock_services):
    """Test LoggingService initialization."""
    assert logging_service.config == sample_log_config
    assert logging_service.alert_queue == mock_services["alert_queue"]
    assert logging_service.kafka_service == mock_services["kafka_service"]
    assert logging_service.alerts_watcher_service == mock_services["alerts_watcher_service"]
    assert logging_service.alerts_worker_service == mock_services["alerts_worker_service"]
    assert logging_service.shutdown_event == mock_services["shutdown_event"]
    assert isinstance(logging_service.process, psutil.Process)


@pytest.mark.asyncio
async def test_logging_service_invalid_config(tmp_path):
    """Test LoggingService initialization with invalid config."""
    # Create a temporary valid log file
    valid_log_file = tmp_path / "test.log"
    valid_log_file.touch()

    # Test invalid level - use try/except instead of pytest.raises
    try:
        LogConfig(console=True, file_path=str(valid_log_file), level="INVALID", interval=1, keep_files=7)
        pytest.fail("ValidationError not raised")  # Should not reach here
    except ValidationError:
        pass  # Test passed as expected

    # Test invalid interval - use try/except instead of pytest.raises
    try:
        LogConfig(console=True, file_path=str(valid_log_file), level="INFO", interval=-1, keep_files=7)
        pytest.fail("ValidationError not raised")  # Should not reach here
    except ValidationError:
        pass  # Test passed as expected


@pytest.mark.asyncio
async def test_logging_service_log_stats(logging_service, caplog):
    """Test LoggingService statistics logging."""
    # Patch the logging module to ensure we capture all logs
    with patch("logging.Logger.info") as mock_info, patch("logging.Logger.error"):
        # Setup required mocks for the alerts_watcher_service
        from datetime import datetime

        current_time = time.time()

        # Create a file_monitor mock with the necessary attributes
        file_monitor_mock = MagicMock()
        file_monitor_mock.latest_queue_put = datetime.fromtimestamp(current_time)
        file_monitor_mock.log_stats = AsyncMock(return_value=(1.0, 0.5, 10, 0, 0))

        # Attach file_monitor to alerts_watcher_service
        logging_service.alerts_watcher_service.file_monitor = file_monitor_mock

        # Mock alerts_worker_service
        logging_service.alerts_worker_service.last_processed_time = current_time

        # Mock kafka service attributes
        logging_service.kafka_service.producer = MagicMock()

        # Call the async log_stats method
        await logging_service._log_stats()

        # Verify logs were called via mocked functions
        call_args_list = [args[0][0] for args in mock_info.call_args_list if args[0]]

        # Print call args for debugging if needed
        # print("INFO calls:", call_args_list)

        assert any("Number of objects in alert queue" in arg for arg in call_args_list)
        assert any("Current memory usage" in arg for arg in call_args_list)
        assert any("Current open files" in arg for arg in call_args_list)
        assert any("Kafka producer is alive" in arg for arg in call_args_list)
        assert any("Alerts worker service is running" in arg for arg in call_args_list)
        assert any("Latest queue put:" in arg for arg in call_args_list)
        assert any("FileMonitor (current interval)" in arg for arg in call_args_list)
        assert any("Last processed:" in arg for arg in call_args_list)


@pytest.mark.asyncio
async def test_logging_service_log_stats_no_observer(logging_service, caplog):
    """Test LoggingService statistics logging without observer."""
    # Patch the logging module to ensure we capture all logs
    with patch("logging.Logger.info") as mock_info:
        # Setup required mocks

        current_time = time.time()

        # Set file_monitor to None to test that branch
        logging_service.alerts_watcher_service.file_monitor = None

        # Mock alerts_worker_service
        logging_service.alerts_worker_service.last_processed_time = current_time

        # Call log stats (async method)
        await logging_service._log_stats()

        # Verify logs were called via mocked functions
        call_args_list = [args[0][0] for args in mock_info.call_args_list if args[0]]

        # Print call args for debugging if needed
        # print("INFO calls:", call_args_list)

        assert any("Number of objects in alert queue" in arg for arg in call_args_list)
        assert any("Current memory usage" in arg for arg in call_args_list)
        assert any("Current open files" in arg for arg in call_args_list)
        assert any("No alerts have been queued yet" in arg for arg in call_args_list)


@pytest.mark.asyncio
async def test_logging_service_start_stop(logging_service):
    """Test LoggingService start and stop functionality."""
    # Patch the _log_stats method to avoid actual logging
    with patch.object(logging_service, "_log_stats", AsyncMock()):
        # Start service in a task
        service_task = asyncio.create_task(logging_service.start())

        # Let it run for a bit
        await asyncio.sleep(0.2)

        # Signal shutdown
        logging_service.shutdown_event.set()

        # Stop service
        await logging_service.stop()

        # Wait for task to finish
        try:
            await asyncio.wait_for(service_task, timeout=1)
        except TimeoutError:
            service_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await service_task

        # Verify _log_stats was called
        assert logging_service._log_stats.called


@pytest.mark.asyncio
@patch("psutil.Process")
async def test_logging_service_memory_error(mock_process, logging_service, caplog):
    """Test LoggingService handling of memory access errors."""
    # Patch the logging module to ensure we capture all logs
    with patch("logging.Logger.error") as mock_error, patch("logging.Logger.info"):
        # Setup required mocks

        current_time = time.time()

        # Mock alerts_worker_service
        logging_service.alerts_worker_service.last_processed_time = current_time

        # Mock process to raise error
        mock_process_instance = mock_process.return_value
        mock_process_instance.memory_percent.side_effect = psutil.AccessDenied("Test error")
        mock_process_instance.open_files.return_value = []  # Prevent additional errors
        logging_service.process = mock_process_instance

        # Call log stats (async method)
        await logging_service._log_stats()

        # Verify error handling through mocked function
        error_calls = [args[0][0] for args in mock_error.call_args_list if args[0]]

        # Print call args for debugging if needed
        # print("ERROR calls:", error_calls)

        assert any("Error getting memory usage" in arg for arg in error_calls)
        assert any("Test error" in arg for arg in error_calls)


@pytest.mark.asyncio
async def test_logging_service_error_handling(logging_service, caplog):
    """Test LoggingService error handling during operation."""
    # Set the logger to capture
    caplog.set_level(logging.ERROR, logger="wazuh_dfn.services.logging_service")

    with patch.object(logging_service, "_log_stats") as mock_log_stats:
        # Setup mock to raise an error
        mock_log_stats.side_effect = Exception("Test error")

        # Start service in a task
        service_task = asyncio.create_task(logging_service.start())

        # Let it run for a bit
        await asyncio.sleep(0.2)

        # Signal shutdown
        logging_service.shutdown_event.set()

        # Wait for task to finish
        try:
            await asyncio.wait_for(service_task, timeout=1)
        except TimeoutError:
            service_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await service_task
        except Exception:  # noqa: S110
            # The exception is expected due to the mock
            pass

        # Verify error was logged - give time for logging to happen
        await asyncio.sleep(0.1)
        assert any("Error in logging service" in record.message for record in caplog.records)
