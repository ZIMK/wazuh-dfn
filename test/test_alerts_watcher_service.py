"""Test module for Observer Service."""

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

    reader.f_status.st_ino

    # Get initial position
    initial_inode = reader.f_status.st_ino

    # Remove and recreate file to simulate rotation
    reader.fp.close()  # On windows it needs to be closed before deletion

    os.unlink(str(file_path))

    with open(file_path, "x") as f:
        f.write('{"timestamp": "2021-01-02"}\n')

    time.sleep(1)

    alerts = reader.next_alerts()
    assert alerts is not None

    # Check inode change
    assert reader.f_status.st_ino != initial_inode


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
            service.json_reader.close()
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
        reader.fp.close()
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


def test_file_monitor_split_json_alert():
    """Test FileMonitor handling of JSON alerts split across multiple reads."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name

        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write first part of the alert
        first_part = '{"timestamp'
        tf.write(first_part)
        tf.flush()
        time.sleep(0.1)

        # Process first part - should keep it in buffer
        alerts1 = reader.next_alerts()
        assert len(alerts1) == 0, "Partial alert should not be processed"

        # Write second part of the alert
        second_part = (
            '":"2025-01-09T10:44:45.948+0100","rule":{"level":3,"description":"PAM: Login session closed.",'
            '"id":"5502","firedtimes":19098,"mail":false,"groups":["pam","syslog"],"pci_dss":["10.2.5"],'
            '"gpg13":["7.8","7.9"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],'
            '"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"116","name":"elite81","ip":"136.199.63.81",'
            '"labels":{"os":"Linux"}},"manager":{"name":"wazuhm"},"id":"1736415885.1569576225",'
            '"cluster":{"name":"wazuh","node":"master-node"},"full_log":"Jan  9 10:44:44 elite81 sudo: '
            'pam_unix(sudo:session): session closed for user root","predecoder":{"program_name":"sudo",'
            '"timestamp":"Jan  9 10:44:44","hostname":"elite81"},"decoder":{"parent":"pam","name":"pam"},'
            '"data":{"dstuser":"root"},"location":"/var/log/auth.log"}\n'
        )

        tf.write(second_part)
        tf.flush()
        time.sleep(0.1)

        # Process complete alert
        alerts2 = reader.next_alerts()

        # Verify complete alert was processed correctly
        assert len(alerts2) == 1, "Complete alert should be processed"
        assert alerts2[0]["rule"]["level"] == 3
        assert alerts2[0]["rule"]["id"] == "5502"
        assert alerts2[0]["id"] == "1736415885.1569576225"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_multiple_consecutive_alerts():
    """Test FileMonitor handling of multiple consecutive alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name

        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

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
        found_alerts = reader.next_alerts()

        # Verify all alerts were processed correctly
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
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Create a large alert with nested data
        large_data = {"data": "x" * 1024 * 1024}  # 1MB of data
        large_alert = {"timestamp": "2024-01-01 00:00:00", "rule": {"level": 1}, "large_field": large_data}

        tf.write(json.dumps(large_alert) + "\n")
        tf.flush()
        time.sleep(0.1)

        found_alerts = reader.next_alerts()
        assert len(found_alerts) == 1
        assert found_alerts[0]["rule"]["level"] == 1
        assert len(found_alerts[0]["large_field"]["data"]) == 1024 * 1024

        reader.close()
    os.unlink(file_path)


def test_file_monitor_unicode_alerts():
    """Test FileMonitor handling of Unicode characters in alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
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

        found_alerts = reader.next_alerts()
        assert len(found_alerts) == 3
        assert found_alerts[0]["message"] == "Hello 你好 👋"
        assert found_alerts[1]["message"] == "Über café"
        assert found_alerts[2]["message"] == "растительное масло"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_nested_prefix_alerts():
    """Test FileMonitor handling of nested JSON with similar prefixes."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Create alert with nested timestamp objects
        nested_alert = {
            "timestamp": "2024-01-01 00:00:00",
            "nested": {"timestamp": "2024-01-01 00:00:01", "data": {"timestamp": "2024-01-01 00:00:02"}},
            "rule": {"level": 1},
        }

        tf.write(json.dumps(nested_alert) + "\n")
        tf.flush()
        time.sleep(0.1)

        found_alerts = reader.next_alerts()
        assert len(found_alerts) == 1
        assert found_alerts[0]["nested"]["data"]["timestamp"] == "2024-01-01 00:00:02"
        assert found_alerts[0]["rule"]["level"] == 1

        reader.close()
    os.unlink(file_path)


def test_file_monitor_multiple_incomplete_alerts():
    """Test FileMonitor handling of multiple incomplete alerts."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write complete alert and ensure it's flushed
        valid = '{"timestamp":"2024-01-01 00:00:01","rule":{"level":2}}\n'
        tf.write(valid)
        tf.flush()
        os.fsync(tf.fileno())  # Force write to disk
        time.sleep(0.2)  # Wait longer for file operations

        # Process and verify the complete alert
        found_alerts = reader.next_alerts()
        assert len(found_alerts) == 1, "Should find one complete alert"
        assert found_alerts[0]["rule"]["level"] == 2, "Should have correct alert level"

        # Write both incomplete alerts together
        tf.write('{"timestamp":"2024-01-01 00:00:02","rule":{"level":3')  # Incomplete
        tf.flush()
        os.fsync(tf.fileno())
        time.sleep(0.2)  # Wait for file operations

        # Check that incomplete alert is not processed
        found_alerts = reader.next_alerts()
        assert len(found_alerts) == 0, "Should not process incomplete alert"

        # Complete the alert
        tf.write("}}\n")  # Complete the alert
        tf.flush()
        os.fsync(tf.fileno())
        time.sleep(0.2)  # Wait for file operations

        # Now check for the completed alert
        found_alerts = reader.next_alerts()
        assert len(found_alerts) == 1, "Should find the completed alert"
        assert found_alerts[0]["rule"]["level"] == 3, "Should have correct alert level"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_race_condition():
    """Test FileMonitor handling of rapid writes and rotations."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        def write_alerts():
            for i in range(100):
                with open(file_path, "a") as f:
                    f.write(f'{{"timestamp":"2024-01-01 00:00:{i:02d}","rule":{{"level":{i}}}}}\n')
                    f.flush()
                time.sleep(0.001)  # Small delay to simulate rapid writes

        # Start writing alerts in a separate thread
        write_thread = threading.Thread(target=write_alerts)
        write_thread.start()

        # Read alerts while they're being written
        all_alerts = []
        start_time = time.time()
        while write_thread.is_alive() or time.time() - start_time < 2:
            alerts = reader.next_alerts()
            if alerts:
                all_alerts.extend(alerts)
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
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write a large number of small alerts
        num_alerts = 10000
        alert_template = '{"timestamp":"2024-01-01 00:00:%d","rule":{"level":%d}}\n'

        # Write alerts in batches to avoid memory issues during test setup
        batch_size = 1000
        for batch in range(0, num_alerts, batch_size):
            alerts = "".join(alert_template % (i, i) for i in range(batch, min(batch + batch_size, num_alerts)))
            tf.write(alerts)
            tf.flush()
            time.sleep(0.01)

        # Read and verify alerts in batches
        found_alerts = []
        while len(found_alerts) < num_alerts:
            batch = reader.next_alerts()
            if batch:
                found_alerts.extend(batch)
            time.sleep(0.01)

        assert len(found_alerts) == num_alerts
        assert all(alert["rule"]["level"] == i for i, alert in enumerate(found_alerts))

        reader.close()
    os.unlink(file_path)


def test_file_monitor_invalid_utf8():
    """Test FileMonitor handling of invalid UTF-8 bytes."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write valid alert
        valid_alert = b'{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n'

        # Create some invalid UTF-8 bytes
        invalid_bytes = b"\xfe\xff\xfe\xff"

        # Write another valid alert after invalid bytes
        valid_alert2 = b'{"timestamp":"2024-01-01 00:00:01","rule":{"level":2}}\n'

        # Write sequence of valid -> invalid -> valid data
        tf.write(valid_alert)
        tf.write(invalid_bytes)
        tf.write(valid_alert2)
        tf.flush()
        time.sleep(0.1)

        # Process the file
        found_alerts = reader.next_alerts()

        # Verify both valid alerts were processed
        assert len(found_alerts) == 2, "Should process both valid alerts"
        assert found_alerts[0]["rule"]["level"] == 1, "First alert should be processed"
        assert found_alerts[1]["rule"]["level"] == 2, "Second alert should be processed"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_mixed_encoding():
    """Test FileMonitor handling of mixed valid and invalid encodings."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Create test data with mixed encodings - write complete alerts separately
        test_data = [
            b'{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n',  # Valid JSON
            b"\xfe\xff",  # Invalid UTF-8
            b'{"timestamp":"2024-01-01 00:00:02","rule":{"level":3}}\n',  # Valid JSON
        ]

        # Write each part separately
        for data in test_data:
            tf.write(data)
            tf.flush()
            time.sleep(0.1)  # Give time for processing

        # Process the file
        found_alerts = reader.next_alerts()

        # Verify valid alerts were processed
        assert len(found_alerts) == 2, "Should process first and last alerts"
        assert found_alerts[0]["rule"]["level"] == 1, "First alert should be processed"
        assert found_alerts[1]["rule"]["level"] == 3, "Last alert should be processed"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_utf8_byte_scanning():
    """Test FileMonitor handling of UTF-8 byte sequences of different lengths."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write complete alert with UTF-8 sequences separately
        alert1 = b'{"timestamp":"2024-01-01","message":"ABC"}\n'
        alert2 = b'{"timestamp":"2024-01-02","message":"\xc3\xa9"}\n'  # é
        alert3 = b'{"timestamp":"2024-01-03","message":"\xe2\x82\xac"}\n'  # €
        alert4 = b'{"timestamp":"2024-01-04","message":"\xf0\x9f\x8c\x9f"}\n'  # 🌟

        # Write each alert separately
        for alert in [alert1, alert2, alert3, alert4]:
            tf.write(alert)
            tf.flush()
            time.sleep(0.1)  # Give time for processing

        # Read and verify alerts
        alerts = reader.next_alerts()
        assert len(alerts) == 4, "Should process all alerts"
        assert alerts[0]["message"] == "ABC", "ASCII alert should be processed"
        assert alerts[1]["message"] == "é", "2-byte UTF-8 should be processed"
        assert alerts[2]["message"] == "€", "3-byte UTF-8 should be processed"
        assert alerts[3]["message"] == "🌟", "4-byte UTF-8 should be processed"

        reader.close()
    os.unlink(file_path)


def test_file_monitor_utf8_boundary():
    """Test FileMonitor handling of UTF-8 sequences split across buffer boundaries."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf:
        file_path = tf.name
        reader = JSONReader(file_path, alert_prefix='{"timestamp"', tail=True)
        reader.open()

        # Write a sequence of valid->partial->completion->valid
        sequences = [
            # Valid complete alert
            b'{"timestamp":"2024-01-01","text":"start"}\n',
            # Alert with UTF-8 split across writes (🌟 = f0 9f 8c 9f)
            b'{"timestamp":"2024-01-02","text":"split\xf0\x9f',  # First half
            b'\x8c\x9f end"}\n',  # Second half
            # Final complete alert
            b'{"timestamp":"2024-01-03","text":"done"}\n',
        ]

        for seq in sequences:
            tf.write(seq)
            tf.flush()
            time.sleep(0.1)  # Allow time for processing

        alerts = reader.next_alerts()
        assert len(alerts) == 3, "Should process all three alerts"
        assert alerts[0]["text"] == "start", "First alert should be processed"
        assert alerts[1]["text"] == "split🌟 end", "Split UTF-8 should be correctly assembled"
        assert alerts[2]["text"] == "done", "Final alert should be processed"

        reader.close()
    os.unlink(file_path)
