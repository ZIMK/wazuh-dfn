import logging
import os
import tempfile
import time
from datetime import datetime

import pytest

from wazuh_dfn.services.file_monitor import FileMonitor
from wazuh_dfn.services.max_size_queue import MaxSizeQueue

LOGGER = logging.getLogger(__name__)


def safe_cleanup(reader: FileMonitor, file_path: str, max_retries: int = 5, delay: float = 0.1) -> None:
    """Safely cleanup test resources with retries.

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


@pytest.fixture
def temp_log_file():
    with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as f:
        yield f.name
    if os.path.exists(f.name):
        os.unlink(f.name)


@pytest.fixture
def temp_failed_alerts_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname


@pytest.fixture
def alert_queue():
    return MaxSizeQueue(maxsize=1000)


@pytest.fixture
def file_monitor(temp_log_file, alert_queue, temp_failed_alerts_dir):
    monitor = FileMonitor(
        file_path=temp_log_file,
        alert_queue=alert_queue,
        alert_prefix='{"alert":',
        tail=True,
        failed_alerts_path=temp_failed_alerts_dir,
        store_failed_alerts=True,
    )
    yield monitor
    monitor.close()


def test_file_monitor_initialization(file_monitor, temp_log_file):
    assert file_monitor.file_path == temp_log_file
    assert file_monitor.alert_prefix == b'{"alert":'
    assert file_monitor.buffer == bytearray()
    assert file_monitor.current_inode is None
    assert file_monitor.latest_queue_put is None


def test_open_file(file_monitor):
    assert file_monitor.open()
    assert file_monitor.fp is not None
    assert file_monitor.current_inode is not None


def test_close_file(file_monitor):
    file_monitor.open()
    file_monitor.close()
    assert file_monitor.fp is None
    assert file_monitor.buffer == bytearray()


def test_process_valid_alert(file_monitor, temp_log_file):
    valid_alert = '{"alert": {"field": "value"}}\n'
    with open(temp_log_file, "w") as f:
        f.write(valid_alert)

    file_monitor.open()
    file_monitor.check_file()

    alert = file_monitor.alert_queue.get_nowait()
    assert alert == {"alert": {"field": "value"}}


def test_process_invalid_json(file_monitor, temp_log_file):
    invalid_alert = '{"alert": invalid_json}\n'
    with open(temp_log_file, "w") as f:
        f.write(invalid_alert)

    file_monitor.open()
    file_monitor.check_file()

    assert file_monitor.alert_queue.empty()
    assert file_monitor.errors == 1


def test_file_rotation(file_monitor, temp_log_file):
    # Write initial content
    with open(temp_log_file, "w") as f:
        f.write('{"alert": {"id": "1"}}\n')

    file_monitor.open()
    file_monitor.check_file()

    # Close the file handle before deletion
    file_monitor.close()
    time.sleep(0.1)  # Small delay is enough with safe_cleanup

    try:
        os.unlink(temp_log_file)
    except OSError:
        pass  # Ignore errors, we'll create new file anyway

    # Write new file
    with open(temp_log_file, "w") as f:
        f.write('{"alert": {"id": "2"}}\n')

    file_monitor.open()
    file_monitor.check_file()

    alerts = []
    while not file_monitor.alert_queue.empty():
        alerts.append(file_monitor.alert_queue.get_nowait())

    assert len(alerts) == 2
    assert alerts[0]["alert"]["id"] == "1"
    assert alerts[1]["alert"]["id"] == "2"

    # Use safe cleanup at the end
    safe_cleanup(file_monitor, temp_log_file)


def test_failed_alerts_storage(file_monitor, temp_log_file, temp_failed_alerts_dir):
    # Write an alert with invalid UTF-8 bytes to trigger both failed and replaced files
    invalid_bytes = b'{"alert": "\xFF\xFE invalid utf8"}\n'
    with open(temp_log_file, "wb") as f:
        f.write(invalid_bytes)

    file_monitor.open()
    file_monitor.check_file()

    # Check if failed alert file was created
    failed_files = sorted(os.listdir(temp_failed_alerts_dir))
    assert len(failed_files) == 2  # Should have both failed and replaced versions
    # Check naming pattern
    assert any(f.endswith("_failed_alert.json") for f in failed_files)
    assert any(f.endswith("_replaced_alert.json") for f in failed_files)


def test_stats_calculation(file_monitor):
    import time

    # Simulate some activity
    file_monitor.processed_alerts = 100
    file_monitor.errors = 5
    file_monitor.replaced_alerts = 10
    file_monitor.last_stats_time = datetime.now()

    # Add a small delay to ensure non-zero time difference
    time.sleep(0.1)

    alerts_per_sec, error_rate, processed, errors, replaced = file_monitor.log_stats()

    assert processed == 100
    assert errors == 5
    assert replaced == 10
    assert abs(error_rate - 5.0) < 1e-6  # 5 errors out of 100 processed = 5%
    assert 0 < alerts_per_sec <= 1000  # Reasonable range given the 0.1s delay

    # Verify counters are reset
    assert file_monitor.processed_alerts == 0
    assert file_monitor.errors == 0
    assert file_monitor.replaced_alerts == 0


def test_cleanup_failed_alerts(file_monitor, temp_failed_alerts_dir):
    # Create max_failed_files pairs of files (original and replaced)
    target_total = file_monitor.max_failed_files + 5
    for i in range(target_total):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        # Create only failed alert files (not pairs) to test exact limit
        failed_path = os.path.join(temp_failed_alerts_dir, f"{timestamp}_failed_alert.json")
        with open(failed_path, "w") as f:
            f.write("{}")
        time.sleep(0.001)  # Ensure unique timestamps

    file_monitor._cleanup_failed_alerts()

    remaining_files = os.listdir(temp_failed_alerts_dir)
    assert len(remaining_files) == file_monitor.max_failed_files


def test_large_alert_spanning_chunks(file_monitor, temp_log_file):
    # Create an alert larger than CHUNK_SIZE (8192)
    large_data = "x" * 20000  # Create string longer than CHUNK_SIZE
    large_alert = f'{{"alert": {{"field": "{large_data}"}}}}\n'

    with open(temp_log_file, "w") as f:
        f.write(large_alert)

    file_monitor.open()
    file_monitor.check_file()

    # Verify the alert was properly read and processed
    alert = file_monitor.alert_queue.get_nowait()
    assert alert["alert"]["field"] == large_data
    assert file_monitor.alert_queue.empty()
    assert file_monitor.errors == 0
