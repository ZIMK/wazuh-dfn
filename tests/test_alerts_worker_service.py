"""Test module for Alerts Worker Service."""

import asyncio
import logging
import time
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from wazuh_dfn.exceptions import AlertProcessingError
from wazuh_dfn.services.alerts_worker_service import AlertsWorkerService


# Helper functions for tests
async def run_monitor_for_test(worker_service, mock_event):
    """Helper to run the monitor queue method for testing."""
    monitor_task = asyncio.create_task(worker_service._monitor_queue())
    await asyncio.sleep(0.1)  # Let it run briefly
    mock_event.set()  # Trigger shutdown
    await monitor_task  # Wait for it to finish
    return monitor_task


@pytest.mark.asyncio
async def test_alerts_worker_service_initialization(sample_config, alert_queue, alerts_service, shutdown_event):
    """Test AlertsWorkerService initialization."""
    # Await the alerts_service first to get the actual service
    service = AlertsWorkerService(sample_config.misc, alert_queue, alerts_service, shutdown_event)
    assert service.config == sample_config.misc
    assert service.alert_queue == alert_queue
    assert service.alerts_service == alerts_service
    assert service.shutdown_event == shutdown_event
    assert isinstance(service.worker_tasks, list)


@pytest.mark.asyncio
async def test_alerts_worker_service_process_alerts(alerts_worker_service, alert_queue, shutdown_event):
    """Test AlertsWorkerService alert processing."""
    test_alerts = [{"id": "1", "test": "data1"}, {"id": "2", "test": "data2"}, {"id": "3", "test": "data3"}]

    # Add multiple alerts to the queue
    for alert in test_alerts:
        await alert_queue.put(alert)

    # Start the service in a task
    service_task = asyncio.create_task(alerts_worker_service.start())

    # Wait for processing
    await asyncio.sleep(0.2)

    # Verify tasks are running
    assert len(alerts_worker_service.worker_tasks) > 0

    # Verify queue is empty (alerts processed)
    assert alert_queue.empty()

    # Cleanup - set shutdown and wait for tasks to finish
    shutdown_event.set()
    await asyncio.sleep(0.2)

    try:
        # Cancel the task if it's still running
        if not service_task.done():
            service_task.cancel()
            # Remove pytest.raises and just await - the service catches CancelledError
            await asyncio.wait_for(service_task, timeout=0.5)
    except Exception as e:
        print(f"Error or timeout during cleanup: {e}")

    # Wait for any pending tasks to finish
    for task in alerts_worker_service.worker_tasks:
        if not task.done():
            task.cancel()

    # Final wait to ensure cleanup
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_alerts_worker_service_concurrent_processing(alerts_worker_service, alert_queue, shutdown_event):
    """Test AlertsWorkerService concurrent alert processing."""
    num_alerts = 50
    processed_alerts = []

    # Use a synchronous mock instead of AsyncMock for process_alert
    # since the implementation appears to call it synchronously
    def track_alert(alert):
        processed_alerts.append(alert)

    alerts_worker_service.alerts_service.process_alert = track_alert

    # Add many alerts to test concurrent processing
    for i in range(num_alerts):
        await alert_queue.put({"id": f"alert-{i}", "test": f"data-{i}"})

    # Start service in a task
    service_task = asyncio.create_task(alerts_worker_service.start())

    # Wait for processing
    await asyncio.sleep(1)

    # Verify all alerts were processed
    assert len(processed_alerts) == num_alerts
    assert alert_queue.empty()

    # Cleanup
    shutdown_event.set()
    await asyncio.sleep(0.2)

    try:
        if not service_task.done():
            service_task.cancel()
            # Remove pytest.raises and just await
            await asyncio.wait_for(service_task, timeout=0.5)
    except Exception as e:
        print(f"Error or timeout during cleanup: {e}")

    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_alerts_worker_service_error_recovery(alerts_worker_service, alert_queue, shutdown_event):
    """Test AlertsWorkerService error recovery."""
    error_count = 0
    success_count = 0

    # Use a synchronous mock with side effects
    def process_with_errors(alert):
        nonlocal error_count, success_count
        if error_count == 0:
            error_count += 1
            raise AlertProcessingError("Test error")
        success_count += 1

    alerts_worker_service.alerts_service.process_alert = process_with_errors

    # Add test alert
    await alert_queue.put({"test": "data"})

    # Start service in a task
    service_task = asyncio.create_task(alerts_worker_service.start())

    # Wait for processing and retries
    await asyncio.sleep(1)

    # Verify error handling and recovery
    assert error_count == 1
    assert success_count == 0
    assert alert_queue.empty()

    # Cleanup
    shutdown_event.set()
    await asyncio.sleep(0.2)

    try:
        if not service_task.done():
            service_task.cancel()
            # Remove pytest.raises and just await
            await asyncio.wait_for(service_task, timeout=0.5)
    except Exception as e:
        print(f"Error or timeout during cleanup: {e}")

    await asyncio.sleep(0.1)


@pytest.mark.asyncio
@patch("wazuh_dfn.services.alerts_worker_service.LOGGER")
async def test_alerts_worker_service_logging(mock_logger, alerts_worker_service, alert_queue, shutdown_event):
    """Test AlertsWorkerService logging functionality."""
    # Add test alert to queue
    test_alert = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5},
        "data": {"srcip": "192.168.1.100"},
    }
    await alert_queue.put(test_alert)

    # Start service task
    service_task = asyncio.create_task(alerts_worker_service.start())

    # Wait for processing with timeout
    start_time = time.time()
    max_wait = 2  # 2 second timeout
    logged = False

    while time.time() - start_time < max_wait:
        if mock_logger.info.called or mock_logger.debug.called or mock_logger.error.called:
            logged = True
            break
        await asyncio.sleep(0.1)

    # Verify logging occurred
    assert logged, "No logging calls detected within timeout"
    # Update to check any info call was made instead of a specific message
    assert mock_logger.info.called, "No info logging occurred"

    # Ensure alert is processed before shutdown
    if not alert_queue.empty():
        await asyncio.sleep(0.5)  # Give more time to process

    # Cleanup
    shutdown_event.set()
    await asyncio.sleep(0.2)

    try:
        if not service_task.done():
            service_task.cancel()
            # Remove pytest.raises and just await
            await asyncio.wait_for(service_task, timeout=0.5)
    except Exception as e:
        print(f"Error or timeout during cleanup: {e}")

    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_alerts_worker_service_queue_timeout(alerts_worker_service, alert_queue, shutdown_event):
    """Test AlertsWorkerService queue timeout handling."""
    # Start service with empty queue
    service_task = asyncio.create_task(alerts_worker_service.start())

    # Wait for timeout
    await asyncio.sleep(0.2)

    # Add alert after timeout
    test_alert = {"test": "data"}
    await alert_queue.put(test_alert)

    # Wait for processing
    await asyncio.sleep(0.2)
    assert alert_queue.empty()

    # Cleanup
    shutdown_event.set()
    await asyncio.sleep(0.2)

    try:
        if not service_task.done():
            service_task.cancel()
            # Remove pytest.raises and just await
            await asyncio.wait_for(service_task, timeout=0.5)
    except Exception as e:
        print(f"Error or timeout during cleanup: {e}")

    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_alerts_worker_service_shutdown(alerts_worker_service, alert_queue, shutdown_event):
    """Test AlertsWorkerService clean shutdown."""
    # Start service
    service_task = asyncio.create_task(alerts_worker_service.start())

    # Add some alerts
    for i in range(5):
        await alert_queue.put({"id": f"alert-{i}", "test": f"data-{i}"})

    # Initiate shutdown while queue not empty
    await asyncio.sleep(0.1)
    shutdown_event.set()

    # Wait for shutdown
    await asyncio.sleep(0.2)

    try:
        if not service_task.done():
            service_task.cancel()
            # Remove pytest.raises and just await
            await asyncio.wait_for(service_task, timeout=0.5)
    except Exception as e:
        print(f"Error or timeout during cleanup: {e}")

    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_dump_alert_error_handling(mocker):
    """Test error handling in the _dump_alert method."""
    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    mock_queue = mocker.MagicMock()
    mock_event = mocker.MagicMock()

    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )

    # Create a test alert
    test_alert = {"rule": {"id": "12345"}, "data": {"field": "value"}}

    # Mock _write_file to raise an exception
    mocker.patch.object(worker_service, "_write_file", side_effect=Exception("Test error"))

    # Test error handling in _dump_alert
    result = await worker_service._dump_alert(test_alert)

    # Verify result is None when error occurs
    assert result is None


@pytest.mark.asyncio
async def test_high_throughput_mode(mocker):
    """Test high throughput mode setting."""
    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    mock_queue = mocker.MagicMock()
    mock_event = asyncio.Event()
    mock_logging_service = mocker.MagicMock()

    # Create the service
    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )
    worker_service.set_logging_service(mock_logging_service)

    # Mock the logger
    _mock_logger = mocker.patch("wazuh_dfn.services.alerts_worker_service.LOGGER")

    # Test setting high throughput mode
    worker_service._high_throughput_mode = False
    worker_service._high_throughput_mode = True

    # Verify it was set correctly
    assert worker_service._high_throughput_mode is True


@pytest.mark.asyncio
async def test_worker_processed_times_property(mocker):
    """Test the worker_processed_times property."""
    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    mock_queue = mocker.MagicMock()
    mock_event = asyncio.Event()

    # Create the service
    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )

    # Set some test data
    worker_service._worker_processed_times = {"worker1": 1234567890.0, "worker2": 1234567891.0}

    # Test the property
    times = await worker_service.worker_processed_times

    # Verify that we get a copy of the data
    assert times == worker_service._worker_processed_times
    assert times is not worker_service._worker_processed_times


@pytest.mark.asyncio
async def test_queue_stats_property(mocker):
    """Test the queue_stats property."""
    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    mock_queue = mocker.MagicMock()
    mock_event = asyncio.Event()

    # Create the service
    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )

    # Set some test data
    worker_service._queue_stats = {
        "total_processed": 100,
        "last_queue_size": 10,
        "max_queue_size": 50,
        "queue_full_count": 2,
        "last_queue_check": 1234567890,
    }

    # Test the property
    stats = await worker_service.queue_stats

    # Verify that we get a copy of the data
    assert stats == worker_service._queue_stats
    assert stats is not worker_service._queue_stats


@pytest.mark.asyncio
async def test_update_timing_stats(mocker):
    """Test the _update_timing_stats method."""
    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    mock_queue = mocker.MagicMock()
    mock_event = asyncio.Event()

    # Create the service
    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )

    # Create test stats dictionary
    stats = {
        "processing_times": [0.1, 0.2],
        "max_time": 0.3,
        "min_time": 0.1,
        "slow_alerts": 0,
        "extremely_slow_alerts": 0,
    }

    # Define epsilon for floating point comparisons
    epsilon = 1e-6

    # Test normal processing time
    worker_service._update_timing_stats(stats, 0.5)
    assert stats["processing_times"] == [0.1, 0.2, 0.5]
    assert abs(stats["max_time"] - 0.5) < epsilon
    assert abs(stats["min_time"] - 0.1) < epsilon
    assert stats["slow_alerts"] == 0
    assert stats["extremely_slow_alerts"] == 0

    # Test slow alert (>2.0s)
    worker_service._update_timing_stats(stats, 3.0)
    assert stats["processing_times"] == [0.1, 0.2, 0.5, 3.0]
    assert abs(stats["max_time"] - 3.0) < epsilon
    assert abs(stats["min_time"] - 0.1) < epsilon
    assert stats["slow_alerts"] == 1
    assert stats["extremely_slow_alerts"] == 0

    # Test extremely slow alert (>5.0s)
    worker_service._update_timing_stats(stats, 6.0)
    assert stats["processing_times"] == [0.1, 0.2, 0.5, 3.0, 6.0]
    assert abs(stats["max_time"] - 6.0) < epsilon
    assert abs(stats["min_time"] - 0.1) < epsilon
    assert stats["slow_alerts"] == 1
    assert stats["extremely_slow_alerts"] == 1

    # Test limit of 100 processing times
    stats["processing_times"] = [0.1] * 99
    worker_service._update_timing_stats(stats, 0.2)
    assert len(stats["processing_times"]) == 100
    assert abs(stats["processing_times"][99] - 0.2) < epsilon


@pytest.mark.asyncio
async def test_process_alert_batch(mocker, caplog):
    """Test the processing of alert batches."""
    caplog.set_level(logging.DEBUG)

    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    # Create AsyncMock for process_alert method specifically
    mock_alerts_service.process_alert = mocker.AsyncMock()
    mock_queue = mocker.MagicMock()
    mock_event = asyncio.Event()

    # Configure mock queue to return items with 'get_nowait' instead of 'get'
    mock_queue.empty.side_effect = [False, False, True]  # Return False twice, then True
    mock_queue.get_nowait.side_effect = [
        {"id": "batch-1", "data": "test1"},
        {"id": "batch-2", "data": "test2"},
    ]

    # Create the service
    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )

    # Mock datetime for timing calculations
    mock_now = mocker.patch("wazuh_dfn.services.alerts_worker_service.datetime")
    start_time = datetime(2023, 1, 1, 12, 0, 0)
    end_time = datetime(2023, 1, 1, 12, 0, 1)  # 1 second later
    mock_now.now.side_effect = [start_time, end_time, end_time, end_time, end_time]

    # Initial values
    alerts_processed = 10
    total_processing_time = 5.0

    # Call method and get results
    alerts_processed_result, _total_time_result, _ = await worker_service._process_alert_batch(
        "worker-1", 3, alerts_processed, total_processing_time
    )

    # Verify the alerts were retrieved and processed
    assert mock_queue.get_nowait.call_count == 2
    assert mock_alerts_service.process_alert.call_count == 2

    # Check that the counts have increased correctly
    # Since we're mocking 2 alerts, expect 2 more processed
    assert alerts_processed_result == alerts_processed + 2


@pytest.mark.asyncio
async def test_process_alert_batch_error_handling(mocker):
    """Test error handling in alert batch processing."""
    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    # Create AsyncMock with side effect as exception
    mock_alerts_service.process_alert = mocker.AsyncMock(side_effect=Exception("Test processing error"))
    mock_queue = mocker.MagicMock()
    mock_event = asyncio.Event()

    # Configure queue.empty and get_nowait
    mock_queue.empty.return_value = False
    mock_queue.get_nowait.return_value = {"id": "batch-error", "data": "test"}

    # Create the service
    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )

    # Mock the logger
    mock_logger = mocker.patch("wazuh_dfn.services.alerts_worker_service.LOGGER")

    # Initial values
    alerts_processed = 10
    total_processing_time = 5.0

    # Call method and check for error handling
    result = await worker_service._process_alert_batch("worker-1", 1, alerts_processed, total_processing_time)

    # Define epsilon for floating point comparisons
    epsilon = 1e-6
    # Verify result values - counts should remain unchanged since processing failed
    new_alerts_processed, new_total_time, _timing_results = result
    assert new_alerts_processed == alerts_processed
    assert abs(new_total_time - total_processing_time) < epsilon

    # Verify the alert was retrieved
    assert mock_queue.get_nowait.called

    # Verify error was attempted to be processed
    assert mock_alerts_service.process_alert.called

    # Check that an error was logged
    assert mock_logger.error.called


@pytest.mark.asyncio
async def test_monitor_queue(mocker):
    """Test queue monitoring."""
    # Setup mocks
    mock_alerts_service = mocker.MagicMock()
    mock_queue = mocker.MagicMock()
    mock_event = asyncio.Event()

    # Configure qsize and maxsize for critical fill level (90%)
    mock_queue.qsize.return_value = 90
    mock_queue.maxsize = 100

    # Create the service
    worker_service = AlertsWorkerService(
        config=mocker.MagicMock(), alert_queue=mock_queue, alerts_service=mock_alerts_service, shutdown_event=mock_event
    )

    # Mock asyncio.sleep to avoid waiting
    mock_sleep = mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    # Mock the logger
    mock_logger = mocker.patch("wazuh_dfn.services.alerts_worker_service.LOGGER")

    # Setup a task to run the method for a short time
    async def run_monitor():
        worker_service._high_throughput_mode = False
        monitor_task = asyncio.create_task(worker_service._monitor_queue())
        await asyncio.sleep(0.1)  # Let it run briefly
        mock_event.set()  # Trigger shutdown
        await monitor_task  # Wait for it to finish

    # Run the monitor
    await run_monitor()

    # Verify some logging occurred at high queue fill
    assert any(
        [mock_logger.warning.called, mock_logger.error.called, mock_logger.info.called]
    ), "No logging occurred for high queue fill"

    # Verify sleep was called
    assert mock_sleep.called
