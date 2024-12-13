"""Test module for Observer Service."""

import logging
import os
import queue
import tempfile
import threading
import time

import pytest

from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.exceptions import ConfigValidationError
from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService, FileMonitor

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)


def test_alerts_watcher_service_init():
    """Test AlertsWatcherService initialization."""
    config = WazuhConfig()
    config.json_alert_file = "/test/path/alerts.json"
    config.json_alert_prefix = '{"timestamp"'
    config.json_alert_suffix = "}"
    config.json_alert_file_poll_interval = 1.0

    alert_queue = queue.Queue()
    shutdown_event = threading.Event()

    observer = AlertsWatcherService(config, alert_queue, shutdown_event)

    assert observer.file_path == "/test/path/alerts.json"
    assert observer.config.json_alert_file_poll_interval == pytest.approx(1.0)
    assert observer.monitor is None


def test_file_monitor_process_valid_alert():
    """Test FileMonitor processing of valid alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        shutdown_event = threading.Event()

        monitor = FileMonitor(
            file_path=file_path,
            alert_queue=alert_queue,
            alert_prefix='{"timestamp"',
            alert_suffix="}",
            shutdown_event=shutdown_event,
        )

        # Write valid alert
        alert = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
        tf.write(alert)
        tf.flush()

        # Process the file
        monitor.check_file()

        # Verify alert was queued
        assert not alert_queue.empty()
        queued_alert = alert_queue.get()
        assert queued_alert["rule"]["level"] == 5
        assert queued_alert["timestamp"] == "2024-01-01 00:00:00"

    os.unlink(file_path)


def test_file_monitor_inode_change(tmp_path, monkeypatch):
    """Test file monitor handling of inode changes."""
    # Mock os.name to always return 'posix' (Linux)
    monkeypatch.setattr("os.name", "posix")

    # Create initial file
    file_path = tmp_path / "test.json"
    with open(file_path, "w") as f:
        f.write('{"timestamp": "2021-01-01"}\n')

    # Initialize monitor
    alert_queue = queue.Queue()
    shutdown_event = threading.Event()
    monitor = FileMonitor(
        file_path=str(file_path),
        alert_queue=alert_queue,
        alert_prefix='{"timestamp"',
        alert_suffix="}",
        shutdown_event=shutdown_event,
    )

    # Get initial position
    monitor._get_initial_position()
    initial_inode = monitor.current_inode

    # Remove and recreate file to simulate rotation
    os.unlink(str(file_path))
    with open(file_path, "w") as f:
        f.write('{"timestamp": "2021-01-02"}\n')

    # Check inode change
    assert monitor._check_inode() is True
    assert monitor.current_inode != initial_inode
    assert monitor.file_position == 0


def test_alerts_watcher_service_start_stop():
    """Test AlertsWatcherService start and stop."""
    config = WazuhConfig()
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        config.json_alert_file = tf.name
        tf.write(b"")  # Write empty bytes

    service = AlertsWatcherService(config, queue.Queue(), threading.Event())

    try:
        service_thread = threading.Thread(target=service.start)
        service_thread.start()
        time.sleep(0.5)

        assert service.monitor is not None

        service.shutdown_event.set()
        service_thread.join(timeout=2)
        assert not service_thread.is_alive()

    finally:
        if os.path.exists(config.json_alert_file):
            os.unlink(config.json_alert_file)


def test_alerts_watcher_service_config_validation():
    """Test AlertsWatcherService configuration validation."""
    invalid_config = WazuhConfig()
    invalid_config.json_alert_file = ""  # Invalid empty path

    with pytest.raises(ConfigValidationError):
        AlertsWatcherService(invalid_config, queue.Queue(), threading.Event())


def test_file_monitor_decode_error_recovery():
    """Test FileMonitor handling of decode errors and recovery."""
    # Set up logging to capture debug messages
    log_messages = []

    class LogHandler(logging.Handler):
        def emit(self, record):
            log_messages.append(record.getMessage())

    logger = logging.getLogger("wazuh_dfn.services.alerts_watcher_service")
    logger.setLevel(logging.DEBUG)
    handler = LogHandler()
    logger.addHandler(handler)

    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
            file_path = tf.name

            # Write test content: invalid UTF-8 and valid alert as separate lines
            invalid_data = b"\xFF\xFE\xFD\r\n"  # Invalid UTF-8
            valid_alert = b'{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\r\n'

            # Write both to file
            tf.write(invalid_data)
            tf.flush()  # Ensure first line is written

            # Create monitor and process first line (invalid UTF-8)
            alert_queue = queue.Queue()
            shutdown_event = threading.Event()
            monitor = FileMonitor(
                file_path=file_path,
                alert_queue=alert_queue,
                alert_prefix='{"timestamp"',
                alert_suffix="}",
                shutdown_event=shutdown_event,
            )

            # Process the invalid UTF-8 line
            monitor.file_position = 0
            monitor.check_file()
            time.sleep(0.1)

            # Now append the valid alert
            with open(file_path, "ab") as f:
                f.write(valid_alert)
                f.flush()

            # Get the file size for verification
            file_size = os.path.getsize(file_path)
            LOGGER.debug(f"File size after writing both lines: {file_size}")
            LOGGER.debug(f"Content lengths - invalid: {len(invalid_data)}, valid: {len(valid_alert)}")

            # Process file multiple times to get the valid alert
            max_attempts = 5
            success = False
            for attempt in range(max_attempts):
                # Start from the end of the invalid data
                monitor.file_position = len(invalid_data)
                LOGGER.debug(f"Attempt {attempt + 1}: Reset position to {monitor.file_position}")

                monitor.check_file()
                time.sleep(0.1)

                # Check if we got the alert
                if not alert_queue.empty():
                    alert = alert_queue.get()
                    assert alert["rule"]["level"] == 5
                    success = True
                    break

            if not success:
                # If we get here, we didn't find the alert
                with open(file_path, "rb") as f:
                    content = f.read()
                    raise AssertionError(
                        f"Alert was not processed after {max_attempts} attempts.\n"
                        f"File position: {monitor.file_position}\n"
                        f"Total file size: {file_size}\n"
                        f"Total file content: {content!r}\n"
                        f"Invalid data length: {len(invalid_data)}\n"
                        f"Valid alert length: {len(valid_alert)}\n"
                        f"Monitor state: latest_event='{monitor.latest_event}', "
                        f"decode_errors={monitor._consecutive_decode_errors}\n"
                        f"Debug logs:\n" + "\n".join(log_messages)
                    )

            # Verify no more alerts
            assert alert_queue.empty()

        try:
            os.unlink(file_path)
        except PermissionError:
            pass

    finally:
        # Clean up logging
        logger.removeHandler(handler)


def test_file_monitor_incomplete_json():
    """Test FileMonitor handling of incomplete JSON alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        shutdown_event = threading.Event()

        monitor = FileMonitor(
            file_path=file_path,
            alert_queue=alert_queue,
            alert_prefix='{"timestamp"',
            alert_suffix="}",
            shutdown_event=shutdown_event,
        )

        # Write incomplete JSON
        tf.write('{"timestamp":"2024-01-01 00:00:00","rule":{"level":5')
        tf.flush()
        monitor.check_file()

        # Verify incomplete JSON not queued
        assert alert_queue.empty()

        # Complete the JSON
        tf.write("}}\n")
        tf.flush()
        monitor.check_file()

        # Verify complete JSON is queued
        assert not alert_queue.empty()
        queued_alert = alert_queue.get()
        assert queued_alert["rule"]["level"] == 5

    os.unlink(file_path)


def test_file_monitor_read_chunk_until_newline():
    """Test FileMonitor's _read_chunk_until_newline method."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        shutdown_event = threading.Event()

        monitor = FileMonitor(
            file_path=file_path,
            alert_queue=alert_queue,
            alert_prefix='{"timestamp"',
            alert_suffix="}",
            shutdown_event=shutdown_event,
        )

        # Write long line exceeding MAX_LINE_SIZE
        long_data = "x" * 70000
        alert = f'{{"timestamp":"2024-01-01","data":"{long_data}"}}\n'
        tf.write(alert)
        tf.flush()

        monitor.check_file()

        # Verify long line was processed correctly
        assert not alert_queue.empty()
        queued_alert = alert_queue.get()
        assert queued_alert["data"] == long_data

    os.unlink(file_path)


def test_file_monitor_consecutive_errors():
    """Test FileMonitor handling of consecutive read errors."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        shutdown_event = threading.Event()

        # Write valid alert
        alert = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
        tf.write(alert)
        tf.flush()
        tf.close()  # Close file to avoid Windows file locking issues

        monitor = FileMonitor(
            file_path=file_path,
            alert_queue=alert_queue,
            alert_prefix='{"timestamp"',
            alert_suffix="}",
            shutdown_event=shutdown_event,
        )

        # Mock file operations to simulate errors without file access
        original_open = open

        def mock_open(*args, **kwargs):
            raise PermissionError("Access denied")

        try:
            # Replace built-in open with our mock
            import builtins

            builtins.open = mock_open

            # Process file multiple times to accumulate errors
            for _ in range(6):
                monitor.check_file()
                time.sleep(0.1)

            # Verify error count threshold was reached
            assert monitor._consecutive_read_errors > 5

        finally:
            # Restore original open function
            builtins.open = original_open
            try:
                os.unlink(file_path)
            except PermissionError:
                pass  # Ignore Windows file locking errors during cleanup


def test_file_monitor_file_deletion_recreation():
    """Test FileMonitor handling of file deletion and recreation."""
    file_path = os.path.join(tempfile.gettempdir(), "test_monitor.json")
    alert_queue = queue.Queue()
    shutdown_event = threading.Event()

    monitor = FileMonitor(
        file_path=file_path,
        alert_queue=alert_queue,
        alert_prefix='{"timestamp"',
        alert_suffix="}",
        shutdown_event=shutdown_event,
    )

    try:
        # Write initial alert
        with open(file_path, "w") as f:
            alert1 = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
            f.write(alert1)

        monitor.check_file()
        time.sleep(0.1)  # Give some time for processing

        # Delete file
        os.unlink(file_path)
        monitor.check_file()  # Should handle missing file gracefully
        time.sleep(0.1)

        # Recreate file with new alert
        with open(file_path, "w") as f:
            alert2 = '{"timestamp":"2024-01-01 00:01:00","rule":{"level":6}}\n'
            f.write(alert2)

        monitor.check_file()
        time.sleep(0.1)

        # Verify alerts were processed
        assert not alert_queue.empty(), "First alert was not processed"
        alert1_data = alert_queue.get()
        assert alert1_data["rule"]["level"] == 5

        assert not alert_queue.empty(), "Second alert was not processed"
        alert2_data = alert_queue.get()
        assert alert2_data["rule"]["level"] == 6

    finally:
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
        except PermissionError:
            pass  # Ignore Windows file locking errors during cleanup


def test_file_monitor_malformed_json():
    """Test FileMonitor handling of malformed JSON alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        shutdown_event = threading.Event()

        monitor = FileMonitor(
            file_path=file_path,
            alert_queue=alert_queue,
            alert_prefix='{"timestamp"',
            alert_suffix="}",
            shutdown_event=shutdown_event,
        )

        # Write malformed JSON alerts
        malformed_alerts = [
            '{"timestamp":"2024-01-01", bad_json}\n',
            '{"timestamp":"2024-01-01" "missing":,}\n',
            '{"timestamp":"2024-01-01", "extra": }}}\n',
        ]

        for alert in malformed_alerts:
            tf.write(alert)
            tf.flush()
            monitor.check_file()

        # Write valid alert
        valid_alert = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
        tf.write(valid_alert)
        tf.flush()
        monitor.check_file()

        # Verify only valid alert was queued
        assert not alert_queue.empty()
        queued_alert = alert_queue.get()
        assert queued_alert["rule"]["level"] == 5
        assert alert_queue.empty()  # No malformed alerts should be queued

    os.unlink(file_path)
