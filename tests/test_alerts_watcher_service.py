"""Tests for the AlertsWatcherService module.

This module contains comprehensive tests for the AlertsWatcherService, including:
- Alert file monitoring and processing
- JSON parsing and validation
- File system event handling
- Edge cases and error conditions
"""

import json
import logging
import os
import queue
import tempfile
import threading
import time

import pytest

from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.exceptions import ConfigValidationError
from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService
from wazuh_dfn.services.file_monitor import CHUNK_SIZE, FileMonitor

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)


def write_alert(f, alert_data: dict, binary: bool = False) -> None:
    """Write alert data to a file with consistent newlines.

    Args:
        f: File object to write to
        alert_data: Dictionary containing alert data
        binary: Whether to write in binary mode
    """
    alert_str = json.dumps(alert_data) + "\n"
    if binary:
        f.write(alert_str.encode("utf-8"))
    else:
        f.write(alert_str)
    f.flush()
    os.fsync(f.fileno())


def safe_cleanup(reader: FileMonitor, file_path: str, max_retries: int = 5, delay: float = 0.1) -> None:
    """Safely cleanup test resources.

    Args:
        reader: FileMonitor instance to close
        file_path: Path to file to remove
        max_retries: Maximum number of retries
        delay: Delay between retries in seconds
    """
    if reader:
        try:
            reader.close()
        except Exception as e:
            LOGGER.warning(f"Error closing reader: {e}")
        reader = None

    time.sleep(delay)  # Always wait before attempting to remove file

    if not os.path.exists(file_path):
        return

    for i in range(max_retries):
        try:
            os.unlink(file_path)
            return
        except OSError as e:
            if i < max_retries - 1:
                time.sleep(delay)
                continue
            LOGGER.warning(f"Failed to remove file {file_path} after {max_retries} attempts: {e}")


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


def test_file_monitor_process_valid_alert():
    """Test FileMonitor processing of valid alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        tf.close()  # Close file to ensure it's written

        # Write valid alert
        with open(file_path, "w") as f:
            alert = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
            f.write(alert)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk

        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()  # Add explicit open
        reader.check_file()

        # Verify alert was queued
        assert alert_queue.qsize() == 1, "Expected one alert in queue after processing"
        queued_alert = alert_queue.get()
        assert (
            queued_alert["rule"]["level"] == 5
        ), f"Alert level mismatch. Expected 5, got {queued_alert['rule']['level']}"
        assert (
            queued_alert["timestamp"] == "2024-01-01 00:00:00"
        ), f"Alert timestamp mismatch. Expected 2024-01-01 00:00:00, got {queued_alert['timestamp']}"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_inode_change(tmp_path, monkeypatch):
    """Test file monitor handling of inode changes."""
    # Mock os.name to always return 'posix' (Linux)
    monkeypatch.setattr("os.name", "posix")

    alert_queue = queue.Queue()
    file_path = tmp_path / "test.json"

    # Create initial file
    with open(file_path, "w") as f:
        alert1 = '{"timestamp": "2021-01-01", "rule": {"level": 1}}\n'
        f.write(alert1)
        f.flush()
        os.fsync(f.fileno())

    # Open reader and process initial file
    reader = FileMonitor(str(file_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
    reader.open()  # Add explicit open
    reader.check_file()

    # Verify first alert was read
    assert alert_queue.qsize() == 1
    alert = alert_queue.get()
    assert alert["rule"]["level"] == 1

    # Store initial inode
    initial_inode = os.stat(file_path).st_ino

    # Close and remove original file
    reader.close()
    os.unlink(str(file_path))

    # Create new file (this will have a different inode)
    with open(file_path, "w") as f:
        alert2 = '{"timestamp": "2021-01-02", "rule": {"level": 2}}\n'
        f.write(alert2)
        f.flush()
        os.fsync(f.fileno())

    # Process the new file
    reader.check_file()

    # Verify new alert was read
    assert alert_queue.qsize() == 1
    alert = alert_queue.get()
    assert alert["rule"]["level"] == 2

    # Verify inode changed
    new_inode = os.stat(file_path).st_ino
    assert new_inode != initial_inode

    reader.close()
    os.unlink(str(file_path))


def test_alerts_watcher_service_start_stop():
    """Test AlertsWatcherService start and stop."""
    config = WazuhConfig()
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        config.json_alert_file = tf.name
        tf.write(b"")  # Write empty bytes

    alert_queue = queue.Queue()
    shutdown_event = threading.Event()
    service = AlertsWatcherService(config, alert_queue, shutdown_event)

    try:
        service_thread = threading.Thread(target=service.start)
        service_thread.start()
        time.sleep(0.5)

        assert service.file_monitor is not None
        assert os.path.exists(service.file_path)

        shutdown_event.set()
        service_thread.join(timeout=2)

        assert not service_thread.is_alive()

    finally:
        if os.path.exists(config.json_alert_file):
            if service.file_monitor:
                service.file_monitor.close()
            os.unlink(config.json_alert_file)


def test_alerts_watcher_service_config_validation():
    """Test AlertsWatcherService configuration validation."""
    invalid_config = WazuhConfig()
    invalid_config.json_alert_file = ""  # Invalid empty path

    with pytest.raises(ConfigValidationError):
        AlertsWatcherService(invalid_config, queue.Queue(), threading.Event())


def test_file_monitor_incomplete_json(caplog):
    """Test FileMonitor handling of incomplete JSON alerts."""
    caplog.set_level(logging.DEBUG)
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        tf.close()  # Close file to ensure it's written

        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()  # Add explicit open

        # Write incomplete JSON
        with open(file_path, "w") as f:
            f.write('{"timestamp":"2024-01-01 00:00:00","rule":{"level":5')
            f.flush()
            os.fsync(f.fileno())

        reader.check_file()
        assert alert_queue.qsize() == 0

        # Complete the JSON
        with open(file_path, "a") as f:
            f.write("}}\n")
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()

        assert alert_queue.qsize() == 1
        alert = alert_queue.get()
        assert alert["rule"]["level"] == 5

        reader.close()
    os.unlink(file_path)


def test_file_monitor_file_deletion_recreation(caplog):
    """Test FileMonitor handling of file deletion and recreation."""
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    file_path = os.path.join(tempfile.gettempdir(), "test_monitor.json")
    alert_queue = queue.Queue()
    logger.debug("Test starting with file path: %s", file_path)

    # Create initial file and write first alert
    logger.debug("Creating initial file with first alert")
    with open(file_path, "w") as f:
        alert1 = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
        f.write(alert1)
        f.flush()
        os.fsync(f.fileno())

    logger.debug("Opening FileMonitor with tail=True")
    reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
    reader.open()  # Explicitly open the file

    try:
        logger.debug("Reading first alert")
        reader.check_file()

        logger.debug("Checking queue size")
        assert alert_queue.qsize() == 1, "First alert should be in queue"

        first_alert = alert_queue.get()
        logger.debug("First read result: %s", first_alert)
        assert first_alert["rule"]["level"] == 5, "First alert should have level 5"

        # Delete file
        logger.debug("Closing reader before deletion")
        reader.close()
        logger.debug("Deleting file")
        os.unlink(file_path)
        time.sleep(0.1)

        logger.debug("Reading after deletion")
        reader.check_file()
        assert alert_queue.empty(), "Queue should be empty after file deletion"

        # Recreate file with new alert
        logger.debug("Recreating file with second alert")
        with open(file_path, "w") as f:
            alert2 = '{"timestamp":"2024-01-01 00:01:00","rule":{"level":6}}\n'
            f.write(alert2)
            f.flush()
            os.fsync(f.fileno())

        logger.debug("Reading after recreation")
        time.sleep(0.1)
        reader.check_file()

        assert alert_queue.qsize() == 1, "Second alert should be in queue"
        second_alert = alert_queue.get()
        logger.debug("Second read result: %s", second_alert)
        assert second_alert["rule"]["level"] == 6, "Second alert should have level 6"

    finally:
        logger.debug("Cleaning up")
        reader.close()
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
        except PermissionError:
            pass


def test_file_monitor_malformed_json():
    """Test FileMonitor handling of malformed JSON alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        tf.close()  # Close file to ensure it's written

        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()  # Add explicit open

        # Write malformed JSON alerts
        malformed_alerts = [
            '{"timestamp":"2024-01-01", bad_json}\n',
            '{"timestamp":"2024-01-01" "missing":,}\n',
            '{"timestamp":"2024-01-01", "extra": }}}\n',
        ]

        # Write each malformed alert
        with open(file_path, "w") as f:
            for alert in malformed_alerts:
                f.write(alert)
                f.flush()
                os.fsync(f.fileno())

            # Write valid alert
            valid_alert = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
            f.write(valid_alert)
            f.flush()
            os.fsync(f.fileno())

        reader.check_file()
        assert alert_queue.qsize() == 1
        valid_alert = alert_queue.get()
        assert valid_alert["rule"]["level"] == 5
        reader.close()
    os.unlink(file_path)


def test_file_monitor_split_json_alert():
    """Test FileMonitor handling of JSON alerts split across multiple reads."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        tf.close()  # Close file to ensure it's written

        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()  # Add explicit open

        # Write first part
        with open(file_path, "w") as f:
            f.write('{"timestamp')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()
        assert alert_queue.empty()

        # Write second part
        with open(file_path, "a") as f:
            f.write('":"2025-01-09T10:44:45.948+0100","rule":{"level":3,"description":"Test"}}\n')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()
        assert alert_queue.qsize() == 1
        alert = alert_queue.get()
        assert alert["rule"]["level"] == 3

        reader.close()
    os.unlink(file_path)


def test_file_monitor_multiple_consecutive_alerts():
    """Test FileMonitor handling of multiple consecutive alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"')
        reader.open()  # Add explicit open

        # Create 5 different alerts
        alerts = [
            '{"timestamp":"2024-01-01 00:00:00","rule":{"level":1},"id":"1"}\n',
            '{"timestamp":"2024-01-01 00:00:01","rule":{"level":2},"id":"2"}\n',
            '{"timestamp":"2024-01-01 00:00:02","rule":{"level":3},"id":"3"}\n',
            '{"timestamp":"2024-01-01 00:00:03","rule":{"level":4},"id":"4"}\n',
            '{"timestamp":"2024-01-01 00:00:04","rule":{"level":5},"id":"5"}\n',
        ]

        # Write all alerts at once
        tf.writelines(alerts)
        tf.flush()
        time.sleep(0.1)

        # Process the file
        reader.check_file()

        # Verify all alerts were processed correctly
        assert alert_queue.qsize() == 5
        found_alerts = []
        while not alert_queue.empty():
            found_alerts.append(alert_queue.get())

        assert len(found_alerts) == 5, "Should process all 5 alerts"
        for i, alert in enumerate(found_alerts, 1):
            assert alert["rule"]["level"] == i, f"Alert {i} has incorrect level"
            assert alert["id"] == str(i), f"Alert {i} has incorrect id"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_large_json_alert():
    """Test FileMonitor handling of very large JSON alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Create a moderate-sized alert
        multiplier = 3 * CHUNK_SIZE  # 100B of data
        large_data = {"data": "x" * multiplier}  # 100B of data
        large_alert = {"timestamp": "2024-01-01 00:00:00", "rule": {"level": 1}, "large_field": large_data}

        # Write alert and force flush
        with open(file_path, "w") as f:
            json.dump(large_alert, f)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        # Add a small delay and check multiple times
        max_attempts = 5
        alert_found = False
        for _ in range(max_attempts):
            reader.check_file()
            if not alert_queue.empty():
                alert_found = True
                break
            time.sleep(0.5)

        assert alert_found, f"Alert not found in queue after {max_attempts} attempts"
        assert alert_queue.qsize() == 1, "Expected exactly one alert in queue"
        alert = alert_queue.get()
        assert alert["rule"]["level"] == 1, f"Alert level mismatch. Expected 1, got {alert['rule']['level']}"
        assert (
            len(alert["large_field"]["data"]) == multiplier
        ), f"Alert data size mismatch. Expected 102400, got {len(alert['large_field']['data'])}"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_unicode_alerts():
    """Test FileMonitor handling of Unicode characters in alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"')
        reader.open()

        # Create alerts with various Unicode characters
        alerts = [
            '{"timestamp":"2024-01-01 00:00:00","rule":{"level":1},"message":"Hello 你好 👋"}\n',
            '{"timestamp":"2024-01-01 00:00:01","rule":{"level":2},"message":"Über café"}\n',
            '{"timestamp":"2024-01-01 00:00:02","rule":{"level":3},"message":"растительное масло"}\n',
        ]

        for alert in alerts:
            tf.write(alert)
        tf.flush()
        time.sleep(0.1)

        reader.check_file()
        assert alert_queue.qsize() == 3
        found_alerts = []
        while not alert_queue.empty():
            found_alerts.append(alert_queue.get())

        assert found_alerts[0]["message"] == "Hello 你好 👋"
        assert found_alerts[1]["message"] == "Über café"
        assert found_alerts[2]["message"] == "растительное масло"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_nested_prefix_alerts():
    """Test FileMonitor handling of nested JSON with similar prefixes."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()  # Add queue definition
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()  # Add explicit open

        # Create alert with nested timestamp objects
        nested_alert = {
            "timestamp": "2024-01-01 00:00:00",
            "nested": {"timestamp": "2024-01-01 00:00:01", "data": {"timestamp": "2024-01-01 00:00:02"}},
            "rule": {"level": 1},
        }

        tf.write(json.dumps(nested_alert) + "\n")
        tf.flush()
        time.sleep(0.1)

        reader.check_file()
        assert alert_queue.qsize() == 1
        found_alerts = alert_queue.get()
        assert found_alerts["nested"]["data"]["timestamp"] == "2024-01-01 00:00:02"
        assert found_alerts["rule"]["level"] == 1

        reader.close()
    os.unlink(file_path)


def test_file_monitor_multiple_incomplete_alerts():
    """Test FileMonitor handling of multiple incomplete alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()  # Add queue definition
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write complete alert and ensure it's flushed
        valid = '{"timestamp":"2024-01-01 00:00:01","rule":{"level":2}}\n'
        tf.write(valid)
        tf.flush()
        os.fsync(tf.fileno())  # Force write to disk
        time.sleep(0.2)  # Wait longer for file operations

        # Process and verify the complete alert
        reader.check_file()
        assert alert_queue.qsize() == 1
        found_alerts = alert_queue.get()
        assert found_alerts["rule"]["level"] == 2, "Should have correct alert level"

        # Write both incomplete alerts together
        tf.write('{"timestamp":"2024-01-01 00:00:02","rule":{"level":3')  # Incomplete
        tf.flush()
        os.fsync(tf.fileno())
        time.sleep(0.2)  # Wait for file operations

        # Check that incomplete alert is not processed
        reader.check_file()
        assert alert_queue.empty(), "Should not process incomplete alert"

        # Complete the alert
        tf.write("}}\n")  # Complete the alert
        tf.flush()
        os.fsync(tf.fileno())
        time.sleep(0.2)  # Wait for file operations

        # Now check for the completed alert
        reader.check_file()
        assert alert_queue.qsize() == 1
        found_alerts = alert_queue.get()
        assert found_alerts["rule"]["level"] == 3, "Should have correct alert level"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_race_condition():
    """Test FileMonitor handling of rapid writes and rotations."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()  # Add queue definition
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        def write_alerts():
            for i in range(100):
                with open(file_path, "a") as f:
                    f.write(f'{{"timestamp":"2024-01-01 00:00:{i:02d}","rule":{{"level":{i}}}}}\n')
                    f.flush()
                    os.fsync(f.fileno())
                time.sleep(0.001)  # Small delay to simulate rapid writes

        # Start writing alerts in a separate thread
        write_thread = threading.Thread(target=write_alerts)
        write_thread.start()

        # Read alerts while they're being written
        all_alerts = []
        start_time = time.time()
        while write_thread.is_alive() or time.time() - start_time < 2:
            reader.check_file()
            while not alert_queue.empty():
                all_alerts.append(alert_queue.get())
            time.sleep(0.01)

        write_thread.join()

        # Verify all alerts were captured
        assert len(all_alerts) == 100
        levels = sorted(alert["rule"]["level"] for alert in all_alerts)
        assert levels == list(range(100))

        reader.close()
    os.unlink(file_path)


def test_file_monitor_memory_limits():
    """Test FileMonitor handling of memory limits with large number of alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        num_alerts = 1000
        alerts_written = 0
        alerts_processed = []
        batch_size = 100

        for batch in range(0, num_alerts, batch_size):
            batch_alerts = []
            for i in range(batch, min(batch + batch_size, num_alerts)):
                alert = {"timestamp": f"2024-01-01 00:00:{i:02d}", "rule": {"level": i}}
                batch_alerts.append(json.dumps(alert) + "\n")
                alerts_written += 1

            with open(file_path, "a") as f:
                f.writelines(batch_alerts)
                f.flush()
                os.fsync(f.fileno())

            timeout = time.time() + 5
            while len(alerts_processed) < alerts_written and time.time() < timeout:
                reader.check_file()
                while not alert_queue.empty():
                    alerts_processed.append(alert_queue.get())
                time.sleep(0.01)

            if len(alerts_processed) < alerts_written:
                assert (
                    False
                ), f"Timeout while processing batch. Expected {alerts_written} alerts, got {len(alerts_processed)}"

        assert (
            len(alerts_processed) == num_alerts
        ), f"Total alerts mismatch. Expected {num_alerts}, got {len(alerts_processed)}"

        assert (
            alerts_processed[0]["rule"]["level"] == 0
        ), f"First alert level mismatch. Expected 0, got {alerts_processed[0]['rule']['level']}"
        assert (
            alerts_processed[-1]["rule"]["level"] == num_alerts - 1
        ), f"Last alert level mismatch. Expected {num_alerts-1}, got {alerts_processed[-1]['rule']['level']}"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_invalid_utf8():
    """Test FileMonitor handling of invalid UTF-8 bytes.

    This test ensures that the FileMonitor can properly handle files containing
    both valid JSON alerts and invalid UTF-8 byte sequences.
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        alerts = [
            b'{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n',
            b"\xfe\xff" + b'{"timestamp":"2024-01-01 00:00:01",' + b'"rule":{"level":2}}\n',
            b'{"timestamp":"2024-01-01 00:00:02","rule":{"level":3}}\n',
        ]

        with open(file_path, "wb") as f:
            for alert in alerts:
                f.write(alert)
                f.flush()
                os.fsync(f.fileno())

        timeout = time.time() + 5
        processed = []
        while len(processed) < 3 and time.time() < timeout:
            reader.check_file()
            while not alert_queue.empty():
                processed.append(alert_queue.get())
            time.sleep(0.1)

        assert (
            len(processed) == 3
        ), f"Alert count mismatch. Expected 3 alerts, got {len(processed)}.\nProcessed alerts: {processed}"

        expected_levels = [1, 2, 3]
        actual_levels = [a["rule"]["level"] for a in processed]
        assert (
            actual_levels == expected_levels
        ), f"Alert levels mismatch.\nExpected: {expected_levels}\nGot: {actual_levels}"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_mixed_encoding():
    """Test FileMonitor handling of mixed valid and invalid encodings."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        test_data = (
            b'{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n'
            b"\xfe\xff\n"
            b'{"timestamp":"2024-01-01 00:00:02","rule":{"level":3}}\n'
        )

        with open(file_path, "wb") as f:
            f.write(test_data)
            f.flush()
            os.fsync(f.fileno())

        timeout = time.time() + 5
        processed = []
        while len(processed) < 2 and time.time() < timeout:
            reader.check_file()
            while not alert_queue.empty():
                processed.append(alert_queue.get())
            time.sleep(0.1)

        assert len(processed) == 2, (
            f"Valid alert count mismatch. Expected 2 valid alerts, got {len(processed)}.\n"
            f"Processed alerts: {processed}"
        )

        expected_levels = [1, 3]
        actual_levels = [a["rule"]["level"] for a in processed]
        assert (
            actual_levels == expected_levels
        ), f"Alert levels mismatch.\nExpected: {expected_levels}\nGot: {actual_levels}"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_utf8_byte_scanning():
    """Test FileMonitor handling of UTF-8 byte sequences.

    Verifies correct processing of UTF-8 sequences of varying lengths,
    including multi-byte characters and emojis.
    """
    file_path = os.path.join(tempfile.gettempdir(), "test_utf8.json")
    alert_queue = queue.Queue()
    reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
    reader.open()

    try:
        # Write each alert and verify immediately
        alerts = [
            (b'{"timestamp":"2024-01-01","message":"ABC"}\n', "ABC"),
            (b'{"timestamp":"2024-01-02","message":"\xc3\xa9"}\n', "é"),  # é
            (b'{"timestamp":"2024-01-03","message":"\xe2\x82\xac"}\n', "€"),  # €
            (b'{"timestamp":"2024-01-04","message":"\xf0\x9f\x8c\x9f"}\n', "🌟"),  # 🌟
        ]

        for i, (raw_alert, expected_message) in enumerate(alerts):
            # Write single alert
            with open(file_path, "wb" if i == 0 else "ab") as f:
                f.write(raw_alert)
                f.flush()
                os.fsync(f.fileno())

            # Verify file content
            with open(file_path, "rb") as f:
                content = f.read()
                LOGGER.debug(f"File content for alert {i}: {content!r}")

            time.sleep(0.1)
            reader.check_file()

            assert not alert_queue.empty(), f"Alert {i} ({expected_message!r}) should be in queue but queue is empty"
            alert = alert_queue.get()
            assert (
                alert["message"] == expected_message
            ), f"Alert {i} message mismatch.\nExpected: {expected_message!r}\nGot: {alert['message']!r}"

    finally:
        reader.close()
        if os.path.exists(file_path):
            os.unlink(file_path)


def test_file_monitor_utf8_boundary():
    """Test handling of UTF-8 sequences split across buffer boundaries.

    Ensures that UTF-8 characters split between read operations are
    properly reconstructed and processed.
    """
    file_path = os.path.join(tempfile.gettempdir(), "test_utf8_boundary.json")
    alert_queue = queue.Queue()
    reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
    reader.open()

    try:
        # First complete alert
        with open(file_path, "wb") as f:
            f.write(b'{"timestamp":"2024-01-01","text":"start"}\n')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        LOGGER.debug("Checking first alert")
        reader.check_file()
        assert alert_queue.qsize() == 1, "First alert ('start') should be in queue but queue is empty"
        assert alert_queue.get()["text"] == "start", "First alert should have text 'start'"

        LOGGER.debug("Writing split alert part 1")
        with open(file_path, "ab") as f:
            f.write(b'{"timestamp":"2024-01-02","text":"split\xf0\x9f')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()
        assert alert_queue.empty(), "Incomplete UTF-8 sequence should not be processed"

        LOGGER.debug("Completing split alert")
        with open(file_path, "ab") as f:
            f.write(b'\x8c\x9f end"}\n')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()
        assert alert_queue.qsize() == 1, "Completed split alert should be in queue"
        alert = alert_queue.get()
        assert (
            alert["text"] == "split🌟 end"
        ), f"Split UTF-8 alert text mismatch.\nExpected: 'split🌟 end'\nGot: {alert['text']!r}"

        # Write final alert
        with open(file_path, "ab") as f:
            f.write(b'{"timestamp":"2024-01-03","text":"done"}\n')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()
        assert alert_queue.qsize() == 1, "Final alert should be processed"
        assert alert_queue.get()["text"] == "done"

    finally:
        reader.close()
        if os.path.exists(file_path):
            os.unlink(file_path)


def test_file_monitor_partial_alert_boundaries():
    """Test handling of alerts split at buffer boundaries.

    Verifies that partially written alerts are properly processed once
    completed, even when split across multiple read operations.
    """
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name

    alert_queue = queue.Queue()
    reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
    reader.open()

    try:
        # Write initial complete alerts
        with open(file_path, "w") as f:
            f.write('{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n')
            f.write('{"timestamp":"2024-01-01 00:00:01","rule":{"level":2}}\n')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        LOGGER.debug("Checking initial alerts")
        reader.check_file()

        found_alerts = []
        while not alert_queue.empty():
            found_alerts.append(alert_queue.get())

        assert (
            len(found_alerts) == 2
        ), f"Expected 2 initial alerts, got {len(found_alerts)}.\nFound alerts: {found_alerts}"

        assert [a["rule"]["level"] for a in found_alerts] == [1, 2], (
            "Initial alerts have incorrect levels.\n"
            f"Expected: [1, 2]\n"
            f"Got: {[a['rule']['level'] for a in found_alerts]}"
        )

        LOGGER.debug("Writing partial alert")
        with open(file_path, "a") as f:
            f.write('{"timestamp":"2024-01-01 00:00:02",')
            f.write('"rule":{"level":3},"data":"test"')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()
        assert alert_queue.empty(), "Incomplete alert should not be processed"

        LOGGER.debug("Completing alert and adding final")
        with open(file_path, "a") as f:
            f.write("}\n")
            f.write('{"timestamp":"2024-01-01 00:00:03","rule":{"level":4}}\n')
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        reader.check_file()

        found_alerts = []
        while not alert_queue.empty():
            found_alerts.append(alert_queue.get())

        assert (
            len(found_alerts) == 2
        ), f"Expected 2 additional alerts, got {len(found_alerts)}.\nFound alerts: {found_alerts}"

        levels = [a["rule"]["level"] for a in found_alerts]
        assert levels == [3, 4], f"Additional alerts have incorrect levels.\nExpected: [3, 4]\nGot: {levels}"

    finally:
        reader.close()
        os.unlink(file_path)


def test_file_monitor_newline_handling():
    """Test handling of different newline types.

    Ensures proper processing of alerts with different line endings:
    - Unix (LF)
    - Windows (CRLF)
    - Old Mac (CR)
    """
    file_path = os.path.join(tempfile.gettempdir(), "test_newlines.json")
    alert_queue = queue.Queue()
    reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
    reader.open()

    try:
        # Test different newline variations
        alerts = [
            (b'{"timestamp":"2024-01-01","rule":{"level":1}}\n', 1),  # Unix (LF)
            (b'{"timestamp":"2024-01-02","rule":{"level":2}}\r\n', 2),  # Windows (CRLF)
            (b'{"timestamp":"2024-01-03","rule":{"level":3}}\r', 3),  # Old Mac (CR)
        ]

        # Write and verify each alert
        for i, (alert, level) in enumerate(alerts):
            with open(file_path, "wb" if i == 0 else "ab") as f:
                f.write(alert)
                f.flush()
                os.fsync(f.fileno())

            time.sleep(0.1)
            reader.check_file()

            assert not alert_queue.empty(), f"Alert {i} should be processed"
            processed_alert = alert_queue.get()
            assert processed_alert["rule"]["level"] == level, f"Alert {i} has incorrect level"

    finally:
        reader.close()
        if os.path.exists(file_path):
            os.unlink(file_path)


def test_file_monitor_read_then_process():
    """Test FileMonitor's two-phase read-then-process behavior."""
    tf = None
    reader = None
    file_path = None

    try:
        tf = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        file_path = tf.name
        tf.close()  # Close immediately to avoid handle conflicts

        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write several alerts in different states
        alerts = [
            '{"timestamp":"2024-01-01","rule":{"level":1}}\n',  # Complete alert
            '{"timestamp":"2024-01-02","rule":{"level":2}}\n',  # Complete alert
            '{"timestamp":"2024-01-03","rule":',  # Partial alert
        ]

        # Write initial content
        with open(file_path, "w") as f:
            f.writelines(alerts)
            f.flush()
            os.fsync(f.fileno())

        # First check should process complete alerts and maintain position
        initial_position = reader.last_complete_position
        reader.check_file()

        # Verify two complete alerts were processed
        assert alert_queue.qsize() == 2, "Should process exactly two complete alerts"
        assert all(alert_queue.get()["rule"]["level"] == i for i in [1, 2])

        # Verify position was updated correctly
        assert reader.last_complete_position > initial_position
        last_good_position = reader.last_complete_position

        # Complete the partial alert
        with open(file_path, "a") as f:
            f.write('{"level":3}}\n')
            f.flush()
            os.fsync(f.fileno())

        # Check again
        reader.check_file()
        assert alert_queue.qsize() == 1, "Should process the completed alert"
        assert alert_queue.get()["rule"]["level"] == 3

        # Verify position was updated
        assert reader.last_complete_position > last_good_position

        # Write some invalid content followed by valid alert
        with open(file_path, "a") as f:
            f.write('invalid json\n{"timestamp":"2024-01-04","rule":{"level":4}}\n')
            f.flush()
            os.fsync(f.fileno())

        reader.check_file()
        assert alert_queue.qsize() == 1, "Should skip invalid JSON and process valid alert"
        assert alert_queue.get()["rule"]["level"] == 4

    finally:
        if reader:
            try:
                reader.close()
            except Exception:
                pass
        time.sleep(0.1)  # Give OS time to release handles
        if file_path and os.path.exists(file_path):
            safe_cleanup(None, file_path)  # Reader already closed NOSONAR


def safe_unlink(file_path: str, max_retries: int = 5, delay: float = 0.1) -> None:
    """Safely unlink a file with retries.

    Args:
        file_path: Path to file to remove
        max_retries: Maximum number of retries
        delay: Delay between retries in seconds
    """
    for i in range(max_retries):
        try:
            os.unlink(file_path)
            return
        except PermissionError:
            if i < max_retries - 1:
                time.sleep(delay)
            else:
                raise


def test_file_monitor_position_reversion():
    """Test FileMonitor's position reversion behavior."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        alert_queue = queue.Queue()
        reader = FileMonitor(file_path, alert_queue, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        try:
            # Write initial complete alert
            with open(file_path, "w") as f:
                f.write('{"timestamp":"2024-01-01","rule":{"level":1}}\n')
                f.flush()
                os.fsync(f.fileno())

            # Process initial alert and store position
            reader.check_file()
            assert alert_queue.qsize() == 1, "Should process initial alert"
            assert alert_queue.get()["rule"]["level"] == 1
            initial_good_position = reader.last_complete_position

            # Write incomplete alert
            with open(file_path, "a") as f:
                f.write('{"timestamp":"2024-01-02","rule":{"level":2}')  # No closing brace or newline
                f.flush()
                os.fsync(f.fileno())

            # Check file - should revert position as no complete alerts found
            reader.check_file()
            assert alert_queue.empty(), "Should not process incomplete alert"
            assert reader.last_complete_position == initial_good_position, "Should revert to last known good position"

            # Write more incomplete data
            with open(file_path, "a") as f:
                f.write(',"extra":"data"')  # Still incomplete
                f.flush()
                os.fsync(f.fileno())

            # Check again - should still revert
            reader.check_file()
            assert alert_queue.empty(), "Should still not process incomplete alert"
            assert reader.last_complete_position == initial_good_position, "Should maintain last known good position"

            # Complete the alert and add a new one
            with open(file_path, "a") as f:
                f.write("}\n")  # Complete previous alert
                f.write('{"timestamp":"2024-01-03","rule":{"level":3}}\n')  # Add new alert
                f.flush()
                os.fsync(f.fileno())

            # Check file - should process both alerts
            reader.check_file()
            assert alert_queue.qsize() == 2, "Should process both completed alerts"

            alerts = [alert_queue.get() for _ in range(2)]
            assert [a["rule"]["level"] for a in alerts] == [2, 3], "Should process alerts in correct order"
            assert (
                reader.last_complete_position > initial_good_position
            ), "Should update position after processing complete alerts"

        finally:
            safe_cleanup(reader, file_path)
