"""Tests for the AlertsWatcherService module.

This module contains comprehensive tests for the AlertsWatcherService, including:
- Alert file monitoring and processing
- JSON parsing and validation
- File system event handling
- Edge cases and error conditions
"""

import asyncio
import json
import logging
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService
from wazuh_dfn.services.file_monitor import CHUNK_SIZE, FileMonitor
from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)


async def write_alert(f, alert_data: dict, binary: bool = False) -> None:
    """Write alert data to a file with consistent newlines.

    Args:
        binary: Whether to write in binary mode
    """
    alert_str = json.dumps(alert_data) + "\n"
    if binary:
        f.write(alert_str.encode("utf-8"))
    else:
        f.write(alert_str)
    f.flush()
    await asyncio.sleep(0.01)  # Give a small delay to ensure write completes


async def safe_cleanup(reader: FileMonitor | None, file_path: str | Path) -> None:
    """Safely close the reader and remove the file."""
    if reader:
        await reader.close()
    await asyncio.sleep(0.2)  # Give time for file handles to be released
    try:
        Path(reader.file_path).unlink(missing_ok=True)
        Path(file_path).unlink(missing_ok=True)
    except Exception as e:
        LOGGER.exception(f"Error during cleanup: {e}", exc_info=True)


@pytest.mark.asyncio
async def test_alerts_watcher_service_init():
    """Test AlertsWatcherService initialization."""
    config = WazuhConfig()
    config.json_alert_file = "/test/path/alerts.json"
    config.json_alert_prefix = '{"timestamp"'
    config.json_alert_suffix = "}"
    config.json_alert_file_poll_interval = 1.0

    alert_queue = AsyncMaxSizeQueue()
    shutdown_event = asyncio.Event()

    observer = AlertsWatcherService(config, alert_queue, shutdown_event)

    assert observer.file_path == "/test/path/alerts.json"
    assert observer.config.json_alert_file_poll_interval == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_file_monitor_process_valid_alert():
    """Test FileMonitor processing of valid alerts."""
    # Using NamedTemporaryFile instead of mktemp
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        # Create file monitor
        reader = FileMonitor(temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False)

        try:
            # Open and write an alert
            await reader.open()

            # Write a valid alert to the file
            with Path(temp_path).open("w") as f:
                await write_alert(f, {"timestamp": "2021-01-01", "rule": {"level": 5}})

            # Check the file for alerts
            await reader.check_file()

            # Verify alert was processed
            assert alert_queue.qsize() == 1
            alert = await alert_queue.get()
            assert alert["timestamp"] == "2021-01-01"
            assert alert["rule"]["level"] == 5

        finally:
            await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_inode_change(tmp_path):
    """Test file monitor handling of inode changes."""

    alert_queue = AsyncMaxSizeQueue()
    file_path = Path(tmp_path / "test.json")

    # Create initial file
    file_path.write_text('{"timestamp": "2021-01-01", "rule": {"level": 1}}\n')

    # Open reader and process initial file
    reader = FileMonitor(str(file_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
    await reader.open()  # Add explicit open
    await reader.check_file()

    # Verify first alert was read
    assert alert_queue.qsize() == 1
    alert = await alert_queue.get()
    assert alert["rule"]["level"] == 1

    # Store initial inode
    initial_inode = file_path.stat().st_ino

    # Close and remove original file
    await reader.close()
    file_path.unlink()

    # Create new file (this will have a different inode)
    file_path.write_text('{"timestamp": "2021-01-02", "rule": {"level": 2}}\n')

    # Process the new file
    await reader.open()
    await reader.check_file()

    # Verify new alert was read
    assert alert_queue.qsize() == 1
    alert = await alert_queue.get()
    assert alert["rule"]["level"] == 2

    # Verify inode changed
    new_inode = file_path.stat().st_ino
    assert new_inode != initial_inode

    await safe_cleanup(reader, str(file_path))


@pytest.mark.asyncio
async def test_alerts_watcher_service_start_stop():
    """Test AlertsWatcherService start and stop."""
    config = WazuhConfig()
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        config.json_alert_file = temp_path
        config.json_alert_file_poll_interval = 0.1  # Reduce poll interval for faster testing

        alert_queue = AsyncMaxSizeQueue()
        shutdown_event = asyncio.Event()

        # Create the service
        service = AlertsWatcherService(config, alert_queue, shutdown_event)

        try:
            # Start the service
            task = asyncio.create_task(service.start())

            # Let it run briefly to initialize
            await asyncio.sleep(0.3)

            # Add an alert to the file
            with Path(temp_path).open("w") as f:
                await write_alert(f, {"timestamp": "2021-01-01", "rule": {"level": 5}})

            # Wait longer for alert to be processed
            await asyncio.sleep(0.5)

            # Verify alert was processed
            assert alert_queue.qsize() == 1, "Alert wasn't processed, queue is empty"

            # Stop the service
            shutdown_event.set()
            await service.stop()

            # Await the task to ensure clean shutdown
            try:
                await asyncio.wait_for(task, 1.0)
            except TimeoutError:
                LOGGER.error("Service task did not complete in time")

        finally:
            if Path(config.json_alert_file).exists() and service.file_monitor:
                await safe_cleanup(service.file_monitor, config.json_alert_file)


@pytest.mark.asyncio
async def test_alerts_watcher_service_config_validation():
    """Test AlertsWatcherService configuration validation."""
    from pydantic import ValidationError

    from wazuh_dfn.config import WazuhConfig

    # Use Pydantic's ValidationError instead of ConfigValidationError
    with pytest.raises(ValidationError):
        invalid_config = WazuhConfig(json_alert_file="")  # Invalid empty path
        AlertsWatcherService(invalid_config, AsyncMaxSizeQueue(), asyncio.Event())


@pytest.mark.asyncio
async def test_file_monitor_incomplete_json(caplog):
    """Test FileMonitor handling of incomplete JSON alerts."""
    caplog.set_level(logging.DEBUG)
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        reader = None
        try:
            # Write incomplete JSON - do this before creating the file monitor
            with Path(temp_path).open("w") as f:
                f.write('{"timestamp": "2021-01-01", "incomplete')
                f.flush()

            # Create reader after initial content is written
            reader = FileMonitor(
                temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False
            )
            await reader.open()

            # Initial check - should not process incomplete JSON
            await reader.check_file()
            assert alert_queue.empty(), "Incomplete JSON should not be processed"

            # Close the reader to ensure file handle is released
            await reader.close()

            # Complete the JSON with required rule field in a new write operation
            LOGGER.debug("Completing the JSON with rule field")
            with Path(temp_path).open("w") as f:
                # Write complete JSON with required rule field in one go (starting fresh)
                f.write('{"timestamp": "2021-01-01", "incomplete": true, "rule": {"level": 4}}\n')
                f.flush()

            # Explicit wait for file system to sync
            await asyncio.sleep(0.3)

            # Recreate and reopen reader for completed content
            reader = FileMonitor(
                temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False
            )
            await reader.open()

            # Check for alert multiple times with increasing delays
            for attempt in range(5):
                LOGGER.debug(f"Checking for completed alert (attempt {attempt+1})")
                await reader.check_file()

                if not alert_queue.empty():
                    break

                await asyncio.sleep(0.2 * (attempt + 1))  # Increasing delay

            # Verify the alert was processed
            assert alert_queue.qsize() == 1, "Complete JSON alert wasn't processed"
            alert = await alert_queue.get()
            assert alert["timestamp"] == "2021-01-01"
            assert alert["incomplete"] is True
            assert alert["rule"]["level"] == 4

        finally:
            # Clean up
            if reader:
                await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_file_deletion_recreation(caplog):
    """Test FileMonitor handling of file deletion and recreation."""
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    file_path = Path(tempfile.gettempdir()) / "test_monitor.json"
    alert_queue = AsyncMaxSizeQueue()
    logger.debug("Test starting with file path: %s", file_path)
    reader = None  # Initialize reader to None
    try:
        # Create and write initial file
        with file_path.open("w") as f:
            await write_alert(f, {"timestamp": "2021-01-01", "rule": {"level": 5}})

        # Create monitor
        reader = FileMonitor(str(file_path), alert_queue, alert_prefix='{"timestamp"', tail=True)

        # Process initial file
        await reader.open()
        await reader.check_file()

        # Verify first alert was read
        assert alert_queue.qsize() == 1
        first_alert = await alert_queue.get()
        assert first_alert["rule"]["level"] == 5

        # Close monitor and delete file
        await reader.close()
        reader = None
        file_path.unlink()

        # Create new file with different content
        with file_path.open("w") as f:
            await write_alert(f, {"timestamp": "2021-01-02", "rule": {"level": 6}})

        # Create new monitor
        reader = FileMonitor(str(file_path), alert_queue, alert_prefix='{"timestamp"', tail=True)

        # Process new file
        await reader.open()
        await reader.check_file()

        # Verify second alert was read
        assert alert_queue.qsize() == 1
        second_alert = await alert_queue.get()
        assert second_alert["rule"]["level"] == 6, "Second alert should have level 6"
    finally:
        # Clean up
        if reader:
            await safe_cleanup(reader, str(file_path))


@pytest.mark.asyncio
async def test_file_monitor_malformed_json():
    """Test FileMonitor handling of malformed JSON alerts."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        reader = FileMonitor(temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False)

        try:
            await reader.open()

            # Write malformed JSON
            with Path(temp_path).open("w") as f:
                f.write('{"timestamp": "2021-01-01", "malformed": true,}\n')  # Extra comma
                f.flush()

            # Check file - should detect and report error
            await reader.check_file()

            # Verify no alerts were processed due to malformed JSON
            assert alert_queue.empty()
            assert reader.errors > 0

        finally:
            # Clean up
            if reader:
                await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_split_json_alert():
    """Test FileMonitor handling of JSON alerts split across multiple reads."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        # Create a smaller chunk size to force split reads
        test_chunk_size = 100

        with patch("wazuh_dfn.services.file_monitor.CHUNK_SIZE", test_chunk_size):
            reader = FileMonitor(
                temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False
            )

            try:
                await reader.open()

                # Write a JSON larger than the test chunk size
                large_data = "x" * 200  # Larger than test_chunk_size
                with Path(temp_path).open("w") as f:
                    await write_alert(f, {"timestamp": "2021-01-01", "data": large_data})

                # Check file - should handle split reads properly
                await reader.check_file()

                # Verify alert was processed despite being split
                assert alert_queue.qsize() == 1
                alert = await alert_queue.get()
                assert alert["timestamp"] == "2021-01-01"
                assert alert["data"] == large_data

            finally:
                # Clean up
                if reader:
                    await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_multiple_consecutive_alerts():
    """Test FileMonitor handling of multiple consecutive alerts."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        reader = FileMonitor(temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False)

        try:
            await reader.open()

            # Write multiple alerts
            num_alerts = 5
            with Path(temp_path).open("w") as f:
                for i in range(num_alerts):
                    await write_alert(f, {"timestamp": f"2021-01-{i+1:02d}", "index": i})

            # Check file - should process all alerts
            await reader.check_file()

            # Verify all alerts were processed in order
            assert alert_queue.qsize() == num_alerts
            for i in range(num_alerts):
                alert = await alert_queue.get()
                assert alert["timestamp"] == f"2021-01-{i+1:02d}"
                assert alert["index"] == i

        finally:
            # Clean up
            await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_large_json_alert():
    """Test FileMonitor handling of very large JSON alerts."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        reader = FileMonitor(temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False)

        try:
            await reader.open()

            # Write a very large JSON alert (larger than CHUNK_SIZE)
            large_data = "x" * (CHUNK_SIZE * 2)  # Twice the chunk size
            with Path(temp_path).open("w") as f:
                await write_alert(f, {"timestamp": "2021-01-01", "large_data": large_data})

            # Check file - should handle large alerts
            await reader.check_file()

            # Verify large alert was processed correctly
            assert alert_queue.qsize() == 1
            alert = await alert_queue.get()
            assert alert["timestamp"] == "2021-01-01"
            assert len(alert["large_data"]) == len(large_data)
            assert alert["large_data"] == large_data

        finally:
            # Clean up
            await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_unicode_alerts():
    """Test FileMonitor handling of Unicode characters in alerts."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        reader = FileMonitor(temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False)

        try:
            await reader.open()

            # Write an alert with Unicode characters
            unicode_data = "Unicode: 你好, こんにちは, Привет, مرحبا, ¡Hola!"
            with Path(temp_path).open("w") as f:
                await write_alert(f, {"timestamp": "2021-01-01", "unicode": unicode_data})

            # Check file - should handle unicode properly
            await reader.check_file()

            # Verify unicode data was preserved
            assert alert_queue.qsize() == 1
            alert = await alert_queue.get()
            assert alert["timestamp"] == "2021-01-01"
            assert alert["unicode"] == unicode_data

        finally:
            # Clean up
            await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_nested_prefix_alerts():
    """Test FileMonitor handling of nested JSON with similar prefixes."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        reader = FileMonitor(temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False)

        try:
            await reader.open()

            # Write an alert with nested data containing the prefix
            with Path(temp_path).open("w") as f:
                await write_alert(
                    f, {"timestamp": "2021-01-01", "nested": {"timestamp": "nested timestamp", "data": "nested data"}}
                )

            # Check file - should handle nested prefixes correctly
            await reader.check_file()

            # Verify alert with nested data was processed properly
            assert alert_queue.qsize() == 1
            alert = await alert_queue.get()
            assert alert["timestamp"] == "2021-01-01"
            assert alert["nested"]["timestamp"] == "nested timestamp"
            assert alert["nested"]["data"] == "nested data"

        finally:
            # Clean up
            await safe_cleanup(reader, temp_path)


@pytest.mark.asyncio
async def test_file_monitor_multiple_incomplete_alerts():
    """Test FileMonitor handling of multiple incomplete alerts."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        alert_queue = AsyncMaxSizeQueue()

        reader = FileMonitor(temp_path, alert_queue, alert_prefix='{"timestamp"', tail=True, store_failed_alerts=False)

        try:
            await reader.open()

            # Write an incomplete alert
            with Path(temp_path).open("w") as f:
                f.write('{"timestamp": "2021-01-01", "incomplete": true')
                f.flush()

            # Check file - should not process incomplete alert
            await reader.check_file()
            assert alert_queue.empty()

            # Complete the first alert and add a second incomplete alert
            with Path(temp_path).open("a") as f:
                f.write('}\n{"timestamp": "2021-01-02", "also_incomplete": true')
                f.flush()

            # Check file - should process only the complete alert
            await reader.check_file()
            assert alert_queue.qsize() == 1
            alert = await alert_queue.get()
            assert alert["timestamp"] == "2021-01-01"

            # Complete the second alert with proper rule structure
            with Path(temp_path).open("a") as f:
                f.write(', "rule": {"level": 3}}\n')
                f.flush()

            # Check file - should now process the second alert
            await reader.check_file()
            assert alert_queue.qsize() == 1
            found_alerts = await alert_queue.get()
            assert found_alerts["timestamp"] == "2021-01-02", "Should have the correct timestamp"
            assert found_alerts["rule"]["level"] == 3, "Should have correct alert level"
        finally:
            await safe_cleanup(reader, str(temp_path))


@pytest.mark.asyncio
async def test_file_monitor_race_condition():
    """Test FileMonitor handling of rapid writes and rotations."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        reader = None  # Initialize reader to None
        try:
            alert_queue = AsyncMaxSizeQueue()
            reader = FileMonitor(str(temp_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
            await reader.open()

            async def write_alerts():
                for i in range(100):
                    with temp_path.open("a") as f:
                        f.write(f'{{"timestamp":"2024-01-01 00:00:{i:02d}","rule":{{"level":{i}}}}}\n')
                    await asyncio.sleep(0.001)  # Small delay to simulate rapid writes

            # Start writing alerts in a separate task
            write_task = asyncio.create_task(write_alerts())

            # Read alerts while they're being written
            all_alerts = []
            start_time = time.time()
            while not write_task.done() or time.time() - start_time < 2:
                await reader.check_file()
                while not alert_queue.empty():
                    all_alerts.append(await alert_queue.get())
                await asyncio.sleep(0.01)

            await write_task

            # Verify all alerts were captured
            assert len(all_alerts) == 100
            levels = sorted(alert["rule"]["level"] for alert in all_alerts)
            assert levels == list(range(100))
        finally:
            if reader:
                await safe_cleanup(reader, str(temp_path))


@pytest.mark.asyncio
async def test_file_monitor_memory_limits():
    """Test FileMonitor handling of memory limits with large number of alerts."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        reader = None  # Initialize reader to None
        try:
            alert_queue = AsyncMaxSizeQueue()
            reader = FileMonitor(str(temp_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
            await reader.open()

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

                with temp_path.open("a") as f:
                    f.writelines(batch_alerts)

                timeout = time.time() + 5
                while len(alerts_processed) < alerts_written and time.time() < timeout:
                    await reader.check_file()
                    while not alert_queue.empty():
                        alerts_processed.append(await alert_queue.get())
                    await asyncio.sleep(0.01)

                if len(alerts_processed) < alerts_written:
                    raise AssertionError(
                        f"Timeout while processing batch. Expected {alerts_written} alerts, got {len(alerts_processed)}"
                    )

            assert (
                len(alerts_processed) == num_alerts
            ), f"Total alerts mismatch. Expected {num_alerts}, got {len(alerts_processed)}"

            assert (
                alerts_processed[0]["rule"]["level"] == 0
            ), f"First alert level mismatch. Expected 0, got {alerts_processed[0]['rule']['level']}"
            assert (
                alerts_processed[-1]["rule"]["level"] == num_alerts - 1
            ), f"Last alert level mismatch. Expected {num_alerts-1}, got {alerts_processed[-1]['rule']['level']}"
        finally:
            if reader:
                await safe_cleanup(reader, str(temp_path))


@pytest.mark.asyncio
async def test_file_monitor_invalid_utf8():
    """Test FileMonitor handling of invalid UTF-8 bytes."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        reader = None  # Initialize reader to None
        try:
            alert_queue = AsyncMaxSizeQueue()
            reader = FileMonitor(str(temp_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
            await reader.open()

            alerts = [
                b'{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n',
                b"\xfe\xff" + b'{"timestamp":"2024-01-01 00:00:01",' + b'"rule":{"level":2}}\n',
                b'{"timestamp":"2024-01-01 00:00:02","rule":{"level":3}}\n',
            ]

            temp_path.write_bytes(b"".join(alerts))

            timeout = time.time() + 5
            processed = []
            while len(processed) < 3 and time.time() < timeout:
                await reader.check_file()
                while not alert_queue.empty():
                    processed.append(await alert_queue.get())
                await asyncio.sleep(0.1)

            assert (
                len(processed) == 3
            ), f"Alert count mismatch. Expected 3 alerts, got {len(processed)}.\nProcessed alerts: {processed}"

            expected_levels = [1, 2, 3]
            actual_levels = [a["rule"]["level"] for a in processed]
            assert (
                actual_levels == expected_levels
            ), f"Alert levels mismatch.\nExpected: {expected_levels}\nGot: {actual_levels}"
        finally:
            await safe_cleanup(reader, str(temp_path))


@pytest.mark.asyncio
async def test_file_monitor_mixed_encoding():
    """Test FileMonitor handling of mixed valid and invalid encodings."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        reader = None  # Initialize reader to None
        try:
            alert_queue = AsyncMaxSizeQueue()
            reader = FileMonitor(str(temp_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
            await reader.open()

            test_data = (
                b'{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n'
                b"\xfe\xff\n"
                b'{"timestamp":"2024-01-01 00:00:02","rule":{"level":3}}\n'
            )

            temp_path.write_bytes(test_data)

            timeout = time.time() + 5
            processed = []
            while len(processed) < 2 and time.time() < timeout:
                await reader.check_file()
                while not alert_queue.empty():
                    processed.append(await alert_queue.get())
                await asyncio.sleep(0.1)

            assert len(processed) == 2, (
                f"Valid alert count mismatch. Expected 2 valid alerts, got {len(processed)}.\n"
                f"Processed alerts: {processed}"
            )

            expected_levels = [1, 3]
            actual_levels = [a["rule"]["level"] for a in processed]
            assert (
                actual_levels == expected_levels
            ), f"Alert levels mismatch.\nExpected: {expected_levels}\nGot: {actual_levels}"

        finally:
            await safe_cleanup(reader, str(temp_path))


@pytest.mark.asyncio
async def test_file_monitor_utf8_byte_scanning():
    """Test FileMonitor handling of UTF-8 byte sequences."""
    file_path = Path(tempfile.gettempdir()) / "test_utf8.json"
    alert_queue = AsyncMaxSizeQueue()
    reader = None  # Initialize reader to None
    try:
        reader = FileMonitor(str(file_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
        await reader.open()

        # Write each alert and verify immediately
        alerts = [
            (b'{"timestamp":"2024-01-01","message":"ABC"}\n', "ABC"),
            (b'{"timestamp":"2024-01-02","message":"\xc3\xa9"}\n', "é"),  # é
            (b'{"timestamp":"2024-01-03","message":"\xe2\x82\xac"}\n', "€"),  # €
            (b'{"timestamp":"2024-01-04","message":"\xf0\x9f\x8c\x9f"}\n', "🌟"),  # 🌟
        ]

        for i, (raw_alert, expected_message) in enumerate(alerts):
            # Write single alert
            mode = "wb" if i == 0 else "ab"
            with file_path.open(mode) as f:
                f.write(raw_alert)

            # Verify file content
            content = file_path.read_bytes()
            LOGGER.debug(f"File content for alert {i}: {content!r}")

            await asyncio.sleep(0.1)
            await reader.check_file()

            assert not alert_queue.empty(), f"Alert {i} ({expected_message!r}) should be in queue but queue is empty"
            alert = await alert_queue.get()
            assert (
                alert["message"] == expected_message
            ), f"Alert {i} message mismatch.\nExpected: {expected_message!r}\nGot: {alert['message']!r}"
    finally:
        await safe_cleanup(reader, str(file_path))


@pytest.mark.asyncio
async def test_file_monitor_utf8_boundary():
    """Test handling of UTF-8 sequences split across buffer boundaries."""
    file_path = Path(tempfile.gettempdir()) / "test_utf8_boundary.json"
    alert_queue = AsyncMaxSizeQueue()
    reader = None  # Initialize reader to None
    try:
        reader = FileMonitor(str(file_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
        await reader.open()

        # First complete alert
        file_path.write_bytes(b'{"timestamp":"2024-01-01","text":"start"}\n')

        await asyncio.sleep(0.1)
        LOGGER.debug("Checking first alert")
        await reader.check_file()
        assert alert_queue.qsize() == 1, "First alert ('start') should be in queue but queue is empty"
        assert (await alert_queue.get())["text"] == "start", "First alert should have text 'start'"

        LOGGER.debug("Writing split alert part 1")
        with file_path.open("ab") as f:
            f.write(b'{"timestamp":"2024-01-02","text":"split\xf0\x9f')

        await asyncio.sleep(0.1)
        await reader.check_file()
        assert alert_queue.empty(), "Incomplete UTF-8 sequence should not be processed"

        LOGGER.debug("Completing split alert")
        with file_path.open("ab") as f:
            f.write(b'\x8c\x9f end"}\n')

        await asyncio.sleep(0.1)
        await reader.check_file()
        assert alert_queue.qsize() == 1, "Completed split alert should be in queue"
        alert = await alert_queue.get()
        assert (
            alert["text"] == "split🌟 end"
        ), f"Split UTF-8 alert text mismatch.\nExpected: 'split🌟 end'\nGot: {alert['text']!r}"

        # Write final alert
        with file_path.open("ab") as f:
            f.write(b'{"timestamp":"2024-01-03","text":"done"}\n')

        await asyncio.sleep(0.1)
        await reader.check_file()
        assert alert_queue.qsize() == 1, "Final alert should be processed"
        assert (await alert_queue.get())["text"] == "done"
    finally:
        await safe_cleanup(reader, str(file_path))


@pytest.mark.asyncio
async def test_file_monitor_partial_alert_boundaries():
    """Test handling of alerts split at buffer boundaries."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        reader = None  # Initialize reader to None
        try:
            alert_queue = AsyncMaxSizeQueue()
            reader = FileMonitor(str(temp_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
            await reader.open()

            # Write initial complete alerts
            with temp_path.open("w") as f:
                f.write('{"timestamp":"2024-01-01 00:00:00","rule":{"level":1}}\n')
                f.write('{"timestamp":"2024-01-01 00:00:01","rule":{"level":2}}\n')

            await asyncio.sleep(0.1)
            LOGGER.debug("Checking initial alerts")
            await reader.check_file()

            found_alerts = []
            while not alert_queue.empty():
                found_alerts.append(await alert_queue.get())

            assert (
                len(found_alerts) == 2
            ), f"Expected 2 initial alerts, got {len(found_alerts)}.\nFound alerts: {found_alerts}"

            assert [a["rule"]["level"] for a in found_alerts] == [1, 2], (
                "Initial alerts have incorrect levels.\n"
                f"Expected: [1, 2]\n"
                f"Got: {[a['rule']['level'] for a in found_alerts]}"
            )

            LOGGER.debug("Writing partial alert")
            with temp_path.open("a") as f:
                f.write('{"timestamp":"2024-01-01 00:00:02",')
                f.write('"rule":{"level":3},"data":"test"')

            await asyncio.sleep(0.1)
            await reader.check_file()
            assert alert_queue.empty(), "Incomplete alert should not be processed"

            LOGGER.debug("Completing alert and adding final")
            with temp_path.open("a") as f:
                f.write("}\n")
                f.write('{"timestamp":"2024-01-01 00:00:03","rule":{"level":4}}\n')

            await asyncio.sleep(0.1)
            await reader.check_file()

            found_alerts = []
            while not alert_queue.empty():
                found_alerts.append(await alert_queue.get())

            assert (
                len(found_alerts) == 2
            ), f"Expected 2 additional alerts, got {len(found_alerts)}.\nFound alerts: {found_alerts}"

            levels = [a["rule"]["level"] for a in found_alerts]
            assert levels == [3, 4], f"Additional alerts have incorrect levels.\nExpected: [3, 4]\nGot: {levels}"
        finally:
            await safe_cleanup(reader, str(temp_path))


@pytest.mark.asyncio
async def test_file_monitor_newline_handling():
    """Test handling of different newline types."""
    file_path = Path(tempfile.gettempdir()) / "test_newlines.json"
    alert_queue = AsyncMaxSizeQueue()
    reader = None  # Initialize reader to None
    try:
        reader = FileMonitor(str(file_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
        await reader.open()

        # Test different newline variations
        alerts = [
            (b'{"timestamp":"2024-01-01","rule":{"level":1}}\n', 1),  # Unix (LF)
            (b'{"timestamp":"2024-01-02","rule":{"level":2}}\r\n', 2),  # Windows (CRLF)
            (b'{"timestamp":"2024-01-03","rule":{"level":3}}\r', 3),  # Old Mac (CR)
        ]

        # Write and verify each alert
        for i, (alert, level) in enumerate(alerts):
            mode = "wb" if i == 0 else "ab"
            with file_path.open(mode) as f:
                f.write(alert)

            await asyncio.sleep(0.1)
            await reader.check_file()

            assert not alert_queue.empty(), f"Alert {i} should be processed"
            processed_alert = await alert_queue.get()
            assert processed_alert["rule"]["level"] == level, f"Alert {i} has incorrect level"
    finally:
        await safe_cleanup(reader, str(file_path))


@pytest.mark.asyncio
async def test_file_monitor_read_then_process():
    """Test FileMonitor's two-phase read-then-process behavior."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        reader = None  # Initialize reader to None
        try:
            alert_queue = AsyncMaxSizeQueue()
            # Create the reader instance before accessing its properties
            reader = FileMonitor(str(temp_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
            await reader.open()

            # Write several alerts in different states
            alerts = [
                '{"timestamp":"2024-01-01","rule":{"level":1}}\n',  # Complete alert
                '{"timestamp":"2024-01-02","rule":{"level":2}}\n',  # Complete alert
                '{"timestamp":"2024-01-03","rule":',  # Partial alert
            ]

            # Write initial content
            temp_path.write_text("".join(alerts))

            # First check should process complete alerts and maintain position
            initial_position = reader.last_complete_position
            await reader.check_file()

            # Verify two complete alerts were processed
            assert alert_queue.qsize() == 2, "Should process exactly two complete alerts"
            assert_alerts = []
            for _ in range(2):
                assert_alerts.append(await alert_queue.get())
            assert all(alert["rule"]["level"] == i for i, alert in zip([1, 2], assert_alerts, strict=False))

            # Verify position was updated correctly
            assert reader.last_complete_position > initial_position
            last_good_position = reader.last_complete_position

            # Complete the partial alert
            with temp_path.open("a") as f:
                f.write('{"level":3}}\n')

            # Check again
            await reader.check_file()
            assert alert_queue.qsize() == 1, "Should process the completed alert"
            assert (await alert_queue.get())["rule"]["level"] == 3

            # Verify position was updated
            assert reader.last_complete_position > last_good_position

            # Write some invalid content followed by valid alert
            with temp_path.open("a") as f:
                f.write('invalid json\n{"timestamp":"2024-01-04","rule":{"level":4}}\n')

            await reader.check_file()
            assert alert_queue.qsize() == 1, "Should skip invalid JSON and process valid alert"
            assert (await alert_queue.get())["rule"]["level"] == 4
        finally:
            await safe_cleanup(reader, str(temp_path))


async def safe_unlink(file_path: str, max_retries: int = 5, delay: float = 0.1) -> None:
    """Safely unlink a file with retries.

    Args:
        file_path: Path to file to remove
        max_retries: Maximum number of retries
        delay: Delay between retries in seconds
    """
    path_obj = Path(file_path)
    for i in range(max_retries):
        try:
            path_obj.unlink()
            return
        except PermissionError:
            if i < max_retries - 1:
                await asyncio.sleep(delay)
            else:
                raise


@pytest.mark.asyncio
async def test_file_monitor_position_reversion():
    """Test FileMonitor's position reversion behavior."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        reader = None
        try:
            alert_queue = AsyncMaxSizeQueue()
            reader = FileMonitor(str(temp_path), alert_queue, alert_prefix='{"timestamp"', tail=True)
            await reader.open()

            # Write initial complete alert
            temp_path.write_text('{"timestamp":"2024-01-01","rule":{"level":1}}\n')

            # Process initial alert and store position
            await reader.check_file()
            assert alert_queue.qsize() == 1, "Should process initial alert"
            assert (await alert_queue.get())["rule"]["level"] == 1
            initial_good_position = reader.last_complete_position

            # Write incomplete alert
            with temp_path.open("a") as f:
                f.write('{"timestamp":"2024-01-02","rule":{"level":2}')  # No closing brace or newline

            # File size increased but position should not advance due to incomplete alert
            assert Path(temp_path).stat().st_size > initial_good_position
            await reader.check_file()
            assert alert_queue.empty(), "Incomplete alert should not be processed"
            assert (
                reader.last_complete_position == initial_good_position
            ), "Position should not advance for incomplete alert"

            # Complete the alert and add another
            with temp_path.open("a") as f:
                f.write("}\n")  # Complete previous alert
                f.write('{"timestamp":"2024-01-03","rule":{"level":3}}\n')  # Add new alert

            # Check both alerts are processed
            await reader.check_file()
            assert alert_queue.qsize() == 2, "Should process both completed alerts"
            alerts = [await alert_queue.get() for _ in range(2)]
            assert [a["rule"]["level"] for a in alerts] == [2, 3], "Alerts have incorrect levels"

            # Final position should be updated
            assert (
                reader.last_complete_position > initial_good_position
            ), "Position should advance after processing complete alerts"
        finally:
            await safe_cleanup(reader, str(temp_path))
