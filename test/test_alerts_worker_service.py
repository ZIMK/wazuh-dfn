"""Test module for Alerts Worker Service."""

import threading
import time
from unittest.mock import MagicMock, patch

from wazuh_dfn.exceptions import AlertProcessingError
from wazuh_dfn.services.alerts_worker_service import AlertsWorkerService


def test_alerts_worker_service_initialization(sample_config, alert_queue, alerts_service, shutdown_event):
    """Test AlertsWorkerService initialization."""
    service = AlertsWorkerService(sample_config.misc, alert_queue, alerts_service, shutdown_event)
    assert service.config == sample_config.misc
    assert service.alert_queue == alert_queue
    assert service.alerts_service == alerts_service
    assert service.shutdown_event == shutdown_event
    assert isinstance(service.workers, list)


def test_alerts_worker_service_process_alerts(alerts_worker_service, alert_queue, shutdown_event, cleanup_threads):
    """Test AlertsWorkerService alert processing."""
    test_alerts = [{"id": "1", "test": "data1"}, {"id": "2", "test": "data2"}, {"id": "3", "test": "data3"}]

    # Add multiple alerts to the queue
    for alert in test_alerts:
        alert_queue.put(alert)

    # Start the service
    service_thread = threading.Thread(target=alerts_worker_service.start)
    service_thread.daemon = True
    service_thread.start()

    # Wait for processing
    time.sleep(0.2)

    # Verify workers are running
    assert len(alerts_worker_service.workers) > 0
    assert any(worker.is_alive() for worker in alerts_worker_service.workers if worker)

    # Verify queue is empty (alerts processed)
    assert alert_queue.empty()

    # Cleanup
    shutdown_event.set()
    time.sleep(1)
    assert all(not worker.is_alive() for worker in alerts_worker_service.workers if worker)


def test_alerts_worker_service_concurrent_processing(
    alerts_worker_service, alert_queue, shutdown_event, cleanup_threads
):
    """Test AlertsWorkerService concurrent alert processing."""
    num_alerts = 50
    processed_alerts = []

    # Mock the alerts_service to track processed alerts
    alerts_worker_service.alerts_service.process_alert = MagicMock(side_effect=lambda x: processed_alerts.append(x))

    # Add many alerts to test concurrent processing
    for i in range(num_alerts):
        alert_queue.put({"id": str(i), "data": f"test_{i}"})

    # Start service
    service_thread = threading.Thread(target=alerts_worker_service.start)
    service_thread.daemon = True
    service_thread.start()

    # Wait for processing
    time.sleep(1)

    # Verify all alerts were processed
    assert len(processed_alerts) == num_alerts
    assert alert_queue.empty()

    # Cleanup
    shutdown_event.set()
    time.sleep(0.2)


def test_alerts_worker_service_error_recovery(alerts_worker_service, alert_queue, shutdown_event, cleanup_threads):
    """Test AlertsWorkerService error recovery."""
    error_count = 0
    success_count = 0

    def process_with_errors(alert):
        nonlocal error_count, success_count
        if error_count < 2:  # Fail first two attempts
            error_count += 1
            raise AlertProcessingError("Test error")
        success_count += 1
        return None

    alerts_worker_service.alerts_service.process_alert = MagicMock(side_effect=process_with_errors)

    # Add test alert
    alert_queue.put({"test": "data"})

    # Start service
    service_thread = threading.Thread(target=alerts_worker_service.start)
    service_thread.daemon = True
    service_thread.start()

    # Wait for processing and retries
    time.sleep(1)

    # Verify error handling and recovery
    assert error_count == 1
    assert success_count == 0
    assert alert_queue.empty()

    # Cleanup
    shutdown_event.set()
    time.sleep(1)


@patch("wazuh_dfn.services.alerts_worker_service.LOGGER")
def test_alerts_worker_service_logging(
    mock_logger, alerts_worker_service, alert_queue, shutdown_event, cleanup_threads
):
    """Test AlertsWorkerService logging functionality."""
    # Add test alert to queue
    test_alert = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5},
        "data": {"srcip": "192.168.1.100"},
    }
    alert_queue.put(test_alert)

    # Start service thread
    service_thread = threading.Thread(target=alerts_worker_service.start)
    service_thread.daemon = True
    service_thread.start()

    # Wait for processing with timeout
    start_time = time.time()
    max_wait = 2  # 2 second timeout
    logged = False
    while time.time() - start_time < max_wait:
        if mock_logger.info.called:
            logged = True
            break
        time.sleep(0.1)

    # Verify logging occurred
    assert logged, "No logging calls detected within timeout"
    mock_logger.info.assert_called_with("Starting 1 alert worker threads")

    # Ensure alert is processed before shutdown
    alert_queue.join()
    time.sleep(0.1)  # Give a small grace period
    shutdown_event.set()
    time.sleep(1)  # Allow shutdown to propagate
    assert not service_thread.is_alive(), "Service thread did not shut down properly"


def test_alerts_worker_service_queue_timeout(alerts_worker_service, alert_queue, shutdown_event, cleanup_threads):
    """Test AlertsWorkerService queue timeout handling."""
    # Start service with empty queue
    service_thread = threading.Thread(target=alerts_worker_service.start)
    service_thread.daemon = True
    service_thread.start()

    # Wait for timeout
    time.sleep(0.2)

    # Verify service is still running
    assert any(worker.is_alive() for worker in alerts_worker_service.workers if worker)

    # Add alert after timeout
    test_alert = {"test": "data"}
    alert_queue.put(test_alert)

    # Wait for processing
    time.sleep(0.2)
    assert alert_queue.empty()

    # Cleanup
    shutdown_event.set()
    time.sleep(0.2)


def test_alerts_worker_service_shutdown(alerts_worker_service, alert_queue, shutdown_event, cleanup_threads):
    """Test AlertsWorkerService clean shutdown."""
    # Start service
    service_thread = threading.Thread(target=alerts_worker_service.start)
    service_thread.daemon = True
    service_thread.start()

    # Add some alerts
    for i in range(5):
        alert_queue.put({"id": str(i)})

    # Initiate shutdown while queue not empty
    time.sleep(0.1)
    shutdown_event.set()

    # Wait for shutdown
    time.sleep(1)

    # Verify clean shutdown
    assert all(not worker.is_alive() for worker in alerts_worker_service.workers if worker)
    assert not service_thread.is_alive()
