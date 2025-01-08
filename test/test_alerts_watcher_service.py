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
from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService
from wazuh_dfn.services.json_reader import JSONReader

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


def test_file_monitor_process_valid_alert():
    """Test FileMonitor processing of valid alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name

        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write valid alert
        alert = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
        tf.write(alert)
        tf.flush()
        time.sleep(0.1)

        # Process the file
        alerts = reader.next_alerts()

        # Verify alert was queued
        assert len(alerts) == 1
        assert alerts[0]["rule"]["level"] == 5
        assert alerts[0]["timestamp"] == "2024-01-01 00:00:00"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_inode_change(tmp_path, monkeypatch):
    """Test file monitor handling of inode changes."""
    # Mock os.name to always return 'posix' (Linux)
    monkeypatch.setattr("os.name", "posix")

    # Create initial file
    file_path = tmp_path / "test.json"
    with open(file_path, "w") as f:
        f.write('{"timestamp": "2021-01-01"}\n')

    # Open reader
    reader = JSONReader(str(file_path), alert_prefix='{"timestamp"', tail=True, check_interval=0)
    reader.open()
    reader.next_alerts()

    reader.file_queue.f_status.st_ino

    # Get initial position
    initial_inode = reader.file_queue.f_status.st_ino

    # Remove and recreate file to simulate rotation
    reader.file_queue.fp.close()  # On windows it needs to be closed before deletion

    os.unlink(str(file_path))

    with open(file_path, "x") as f:
        f.write('{"timestamp": "2021-01-02"}\n')

    time.sleep(1)

    alerts = reader.next_alerts()
    assert alerts is not None

    # Check inode change
    assert reader.file_queue.f_status.st_ino != initial_inode


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

        assert service.json_reader.is_active()

        service.shutdown_event.set()
        service.json_reader.close()
        time.sleep(0.5)

        service_thread.join(timeout=2)

        assert not service.json_reader.is_active()
        assert not service_thread.is_alive()

    finally:
        if os.path.exists(config.json_alert_file):
            service.json_reader.file_queue.close()
            os.unlink(config.json_alert_file)


def test_alerts_watcher_service_config_validation():
    """Test AlertsWatcherService configuration validation."""
    invalid_config = WazuhConfig()
    invalid_config.json_alert_file = ""  # Invalid empty path

    with pytest.raises(ConfigValidationError):
        AlertsWatcherService(invalid_config, queue.Queue(), threading.Event())


def test_file_monitor_incomplete_json():
    """Test FileMonitor handling of incomplete JSON alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name

        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write incomplete JSON
        tf.write('{"timestamp":"2024-01-01 00:00:00","rule":{"level":5')
        tf.flush()
        alerts = reader.next_alerts()

        # Verify incomplete JSON not queued
        assert len(alerts) == 0

        # Complete the JSON
        tf.write("}}\n")
        tf.flush()

        time.sleep(0.1)

        alerts = reader.next_alerts()

        # Verify complete JSON is queued
        assert len(alerts) == 1
        assert alerts[0]["rule"]["level"] == 5

        reader.close()
    os.unlink(file_path)


def test_file_monitor_read_chunk_until_newline(caplog):
    """Test FileMonitor's _read_chunk_until_newline method."""
    with caplog.at_level(logging.INFO):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
            file_path = tf.name

            reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
            reader.open()

            # Write long line exceeding MAX_LINE_SIZE
            long_data = "x" * 70000
            alert = f'{{"timestamp":"2024-01-01","data":"{long_data}"}}\n'
            tf.write(alert)
            tf.flush()

            reader.next_alerts()

            # Verify long line was not processed correctly
            assert "Buffer would exceed max size" in caplog.text

            reader.close()
    os.unlink(file_path)


def test_file_monitor_file_deletion_recreation(caplog):
    """Test FileMonitor handling of file deletion and recreation."""
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    file_path = os.path.join(tempfile.gettempdir(), "test_monitor.json")
    logger.debug("Test starting with file path: %s", file_path)

    with open(file_path, "w") as f:
        logger.debug("Creating initial empty file")
        f.write("")
        f.flush()
        os.fsync(f.fileno())

    logger.debug("Opening JSONReader")
    reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
    reader.open()

    try:
        # Write initial alert
        logger.debug("Writing first alert")
        with open(file_path, "w") as f:
            alert1 = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
            f.write(alert1)
            f.flush()
            os.fsync(f.fileno())

        time.sleep(0.1)
        logger.debug("Reading first alert")
        alerts1 = reader.next_alerts()
        logger.debug("First read result: %s", alerts1)

        # Delete file
        logger.debug("Closing file before deletion")
        reader.file_queue.close()
        logger.debug("Deleting file")
        os.unlink(file_path)
        time.sleep(0.1)

        logger.debug("Reading after deletion")
        alerts2 = reader.next_alerts()
        logger.debug("Second read result: %s", alerts2)

        # Recreate file with new alert
        logger.debug("Recreating file with second alert")
        with open(file_path, "w") as f:
            alert2 = '{"timestamp":"2024-01-01 00:01:00","rule":{"level":6}}\n'
            f.write(alert2)
            f.flush()
            os.fsync(f.fileno())

        time.sleep(1)
        logger.debug("Reading after recreation")
        alerts3 = reader.next_alerts()
        logger.debug("Third read result: %s", alerts3)

        # Verify alerts were processed
        assert alerts1 is not None, "First alert was not processed"
        assert len(alerts1) == 1, "First alert was not properly read"
        assert alerts1[0]["rule"]["level"] == 5

        assert len(alerts2) == 0, "Deleted file was not handled correctly"

        assert alerts3 is not None, "Second alert was not processed"
        assert alerts3[0]["rule"]["level"] == 6

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

        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write malformed JSON alerts
        malformed_alerts = [
            '{"timestamp":"2024-01-01", bad_json}\n',
            '{"timestamp":"2024-01-01" "missing":,}\n',
            '{"timestamp":"2024-01-01", "extra": }}}\n',
        ]

        found_mal_alerts = []
        for alert in malformed_alerts:
            tf.write(alert)
            tf.flush()
            alerts = reader.next_alerts()
            found_mal_alerts.extend(alerts)

        # Write valid alert
        valid_alert = '{"timestamp":"2024-01-01 00:00:00","rule":{"level":5}}\n'
        tf.write(valid_alert)
        tf.flush()
        found_valid_alerts = reader.next_alerts()

        # Verify only valid alert was queued
        assert len(found_mal_alerts) == 0

        assert len(found_valid_alerts) == 1
        assert found_valid_alerts[0]["rule"]["level"] == 5
        reader.close()
    os.unlink(file_path)
