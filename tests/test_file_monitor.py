import asyncio
import logging
import pytest
import pytest_asyncio
import tempfile
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from wazuh_dfn.services.file_monitor import MAX_WAIT_TIME, FileMonitor
from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue

LOGGER = logging.getLogger(__name__)


@pytest.fixture
def temp_log_file():
    with tempfile.NamedTemporaryFile(mode="w+b", suffix=".log", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        yield str(tmp_path)
        # Safely remove the temporary file with retries
        for _ in range(5):
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
                break
            except PermissionError:
                time.sleep(0.1)


@pytest.fixture
def temp_failed_alerts_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname


@pytest.fixture
def alert_queue():
    return AsyncMaxSizeQueue(maxsize=1000)


@pytest_asyncio.fixture
async def file_monitor(temp_log_file, alert_queue, temp_failed_alerts_dir):
    monitor = FileMonitor(
        file_path=temp_log_file,
        alert_queue=alert_queue,
        alert_prefix='{"alert":',
        tail=True,
        failed_alerts_path=temp_failed_alerts_dir,
        store_failed_alerts=True,
    )
    yield monitor
    await monitor.close()


@pytest.mark.asyncio
async def test_file_monitor_initialization(file_monitor, temp_log_file):
    try:
        assert file_monitor.file_path == temp_log_file
        assert file_monitor.alert_prefix == b'{"alert":'
        assert file_monitor.buffer == bytearray()
        assert file_monitor.current_inode is None
        assert file_monitor.latest_queue_put is None
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_open_file(file_monitor):
    try:
        assert await file_monitor.open()
        assert file_monitor.fp is not None
        assert file_monitor.current_inode is not None
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_close_file(file_monitor):
    try:
        await file_monitor.open()
        await file_monitor.close()
        assert file_monitor.fp is None
        assert file_monitor.buffer == bytearray()
    finally:
        # Extra close is safe
        await file_monitor.close()


@pytest.mark.asyncio
async def test_process_valid_alert(file_monitor, temp_log_file):
    try:
        valid_alert = '{"alert": {"field": "value"}}\n'
        file_path = Path(temp_log_file)
        file_path.write_text(valid_alert)

        await file_monitor.open()
        await file_monitor.check_file()

        alert = await file_monitor.alert_queue.get()
        assert alert == {"alert": {"field": "value"}}
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_process_invalid_json(file_monitor, temp_log_file):
    try:
        invalid_alert = '{"alert": invalid_json}\n'
        file_path = Path(temp_log_file)
        file_path.write_text(invalid_alert)

        await file_monitor.open()
        await file_monitor.check_file()
        assert file_monitor.alert_queue.empty()
        assert file_monitor.errors == 1
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_file_rotation(file_monitor, temp_log_file):
    try:
        # Write initial content
        file_path = Path(temp_log_file)
        file_path.write_text('{"alert": {"id": "1"}}\n')

        await file_monitor.open()
        await file_monitor.check_file()

        # Explicitly close the file handle before attempting to delete
        await file_monitor.close()
        await asyncio.sleep(0.2)  # Give extra time for Windows to release the file handle

        # Use a more careful file removal approach
        try:
            if file_path.exists():
                file_path.unlink()
        except OSError as e:
            LOGGER.warning(f"Could not remove file in test: {e}")
            # Continue the test even if we couldn't remove the file

        # Write new file with different content
        file_path.write_text('{"alert": {"id": "2"}}\n')

        # Reopen the file and process new content
        await file_monitor.open()
        await file_monitor.check_file()

        alerts = []
        while not file_monitor.alert_queue.empty():
            alerts.append(await file_monitor.alert_queue.get())

        assert len(alerts) == 2
        assert alerts[0]["alert"]["id"] == "1"
        assert alerts[1]["alert"]["id"] == "2"
    finally:
        # Use safe cleanup at the end
        await file_monitor.close()


@pytest.mark.asyncio
async def test_failed_alerts_storage(file_monitor, temp_log_file, temp_failed_alerts_dir):
    try:
        # Write an alert with invalid UTF-8 bytes to trigger both failed and replaced files
        invalid_bytes = b'{"alert": "\xff\xfe invalid utf8"}\n'
        file_path = Path(temp_log_file)
        file_path.write_bytes(invalid_bytes)

        await file_monitor.open()
        await file_monitor.check_file()

        # Check if failed alert file was created
        failed_dir = Path(temp_failed_alerts_dir)
        failed_files = sorted(file.name for file in failed_dir.iterdir())
        assert len(failed_files) == 2  # Should have both failed and replaced versions
        # Check naming pattern
        assert any(f.endswith("_failed_alert.json") for f in failed_files)
        assert any(f.endswith("_replaced_alert.json") for f in failed_files)
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_stats_calculation(file_monitor):
    try:
        # Simulate some activity
        file_monitor.processed_alerts = 100
        file_monitor.errors = 5
        file_monitor.replaced_alerts = 10
        file_monitor.last_stats_time = datetime.now()

        # Add a small delay to ensure non-zero time difference
        await asyncio.sleep(0.1)

        alerts_per_sec, error_rate, processed, errors, replaced = await file_monitor.log_stats()

        assert processed == 100
        assert errors == 5
        assert replaced == 10
        assert abs(error_rate - 5.0) < 1e-6  # 5 errors out of 100 processed = 5%
        assert 0 < alerts_per_sec <= 1000  # Reasonable range given the 0.1s delay

        # Verify counters are reset
        assert file_monitor.processed_alerts == 0
        assert file_monitor.errors == 0
        assert file_monitor.replaced_alerts == 0
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_cleanup_failed_alerts(file_monitor, temp_failed_alerts_dir):
    try:
        # Create max_failed_files pairs of files (original and replaced)
        target_total = file_monitor.max_failed_files + 5
        failed_dir = Path(temp_failed_alerts_dir)

        for _ in range(target_total):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            # Create only failed alert files (not pairs) to test exact limit
            failed_path = failed_dir / f"{timestamp}_failed_alert.json"
            failed_path.write_text("{}")
            await asyncio.sleep(0.001)  # Ensure unique timestamps

        await file_monitor._cleanup_failed_alerts()

        remaining_files = list(failed_dir.iterdir())
        assert len(remaining_files) == file_monitor.max_failed_files
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_large_alert_spanning_chunks(file_monitor, temp_log_file):
    try:
        # Create an alert larger than CHUNK_SIZE (8192)
        large_data = "x" * 20000  # Create string longer than CHUNK_SIZE
        large_alert = f'{{"alert": {{"field": "{large_data}"}}}}\n'

        file_path = Path(temp_log_file)
        file_path.write_text(large_alert)

        await file_monitor.open()
        await file_monitor.check_file()

        # Verify the alert was properly read and processed
        alert = await file_monitor.alert_queue.get()
        assert alert["alert"]["field"] == large_data
        assert file_monitor.alert_queue.empty()
        assert file_monitor.errors == 0
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_process_alert_with_replace(mocker):
    # Setup mocks
    mock_queue = mocker.MagicMock()
    # Create AsyncMock for the put method
    mock_queue.put = mocker.AsyncMock()

    file_monitor = FileMonitor(
        file_path="/test/path",
        alert_queue=mock_queue,
        alert_prefix='{"timestamp"',
        store_failed_alerts=True,
        failed_alerts_path="/tmp",  # noqa: S108
    )

    # Create alert bytes with invalid UTF-8 sequence
    alert_bytes = b'{"timestamp": "2023-01-01T00:00:00", "data": "\xff"}'

    # Mock _save_failed_alert
    _save_mock = mocker.patch.object(file_monitor, "_save_failed_alert")

    # Test processing with replacement
    result = await file_monitor._process_alert_with_replace(alert_bytes)

    # Verify alert was processed and saved with replacement
    assert result is True
    mock_queue.put.assert_called_once()
    _save_mock.assert_called()


@pytest.mark.asyncio
async def test_file_monitor_handle_nonexistent_inode(file_monitor, temp_log_file):
    """Test handling of file rotation with nonexistent path."""
    try:
        # First make sure file is open
        assert await file_monitor.open()

        # Store current inode
        original_inode = file_monitor.current_inode
        assert original_inode is not None

        # Mock Path.stat() to raise an exception
        with patch("pathlib.Path.stat", side_effect=FileNotFoundError("No such file")):
            # Check inode should handle the error
            assert await file_monitor._check_inode() is False
            # Current inode should remain unchanged
            assert file_monitor.current_inode == original_inode
            # Buffer should be untouched
            assert len(file_monitor.buffer) == 0
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_wait_for_data_timeout(file_monitor):
    """Test waiting for data with timeout."""
    try:
        # Add data to buffer to trigger waiting
        file_monitor.buffer.extend(b'{"incomplete": "alert"')

        # Test with wait_start already set (should return the same wait_start)
        wait_start = time.time() - 0.05  # Started 50ms ago
        result = await file_monitor._wait_for_data(wait_start)
        assert result == wait_start  # Should return the same wait_start

        # Test timeout (wait_start older than MAX_WAIT_TIME)
        old_wait_start = time.time() - (MAX_WAIT_TIME + 0.1)  # Just past the timeout
        result = await file_monitor._wait_for_data(old_wait_start)
        assert result is None  # Should return None after timeout
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_cleanup_failed_alerts_error_handling(file_monitor, temp_failed_alerts_dir):
    """Test error handling in cleanup_failed_alerts."""
    try:
        # Create test files
        failed_dir = Path(temp_failed_alerts_dir)
        test_files = []
        for i in range(5):
            test_file = failed_dir / f"test_{i}_failed_alert.json"
            test_file.write_text("{}")
            test_files.append(test_file)

        # Mock unlink to raise an error for one file
        with patch.object(Path, "unlink", side_effect=PermissionError("Access denied")):
            # This should log the error but not fail
            await file_monitor._cleanup_failed_alerts()

            # Files should still exist since deletion failed
            assert all(f.exists() for f in test_files)
    finally:
        await file_monitor.close()


@pytest.mark.asyncio
async def test_handle_file_status_nonexistent_file(file_monitor, temp_log_file):
    """Test handling file status when file doesn't exist."""
    try:
        # First make sure file is opened
        assert await file_monitor.open()

        # Close the file explicitly before attempting to delete it
        await file_monitor.close()
        await asyncio.sleep(0.2)  # Give time for OS to release file handle

        # Try to delete the file with retries
        file_deleted = False
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                Path(temp_log_file).unlink()
                file_deleted = True
                break
            except PermissionError:
                if attempt < max_attempts - 1:
                    LOGGER.warning(f"File still locked, waiting before retry {attempt+1}/{max_attempts}")
                    await asyncio.sleep(0.3)
                else:
                    LOGGER.error("Could not delete file, will mock the file as missing instead")

        # If we couldn't delete the file, mock Path.exists() to simulate it being gone
        if not file_deleted:
            with patch.object(Path, "exists", return_value=False):
                result = await file_monitor._handle_file_status()
                assert result is False
                assert file_monitor.fp is None
        else:
            # File was successfully deleted, test without mocking
            result = await file_monitor._handle_file_status()
            assert result is False
            assert file_monitor.fp is None
    finally:
        await file_monitor.close()
