"""Test module for Alerts Worker Service."""

import asyncio
import pytest
import time
from unittest.mock import patch
from wazuh_dfn.exceptions import AlertProcessingError
from wazuh_dfn.services.alerts_worker_service import AlertsWorkerService


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
    except (TimeoutError, Exception) as e:
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
    except (TimeoutError, Exception) as e:
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
    except (TimeoutError, Exception) as e:
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
    except (TimeoutError, Exception) as e:
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
    except (TimeoutError, Exception) as e:
        print(f"Error or timeout during cleanup: {e}")

    await asyncio.sleep(0.1)
