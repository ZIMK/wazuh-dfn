import asyncio
import json
import pytest
import tempfile
from contextlib import suppress
from pathlib import Path
from wazuh_dfn.services.file_monitor import FileMonitor
from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue


# Utility functions
def load_json_alert(filename):
    """Load a JSON alert file from the tests directory"""
    test_dir = Path(__file__).parent
    with (test_dir / filename).open() as f:
        return json.load(f)


def get_test_files():
    """Get list of all JSON test files"""
    test_dir = Path(__file__).parent
    return [f.name for f in test_dir.glob("*.json")]


async def write_alerts_to_temp_file(alerts):
    """Write alerts to a temporary file"""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp:
        temp_path = temp.name

    with Path(temp_path).open(mode="w") as f:
        for alert in alerts:
            json.dump(alert, f)
            f.write("\n")
    return temp_path


# Test cases
def test_load_alerts():
    """Test that all JSON alert files can be loaded"""
    test_files = get_test_files()
    assert len(test_files) > 0, "No test files found"

    alerts = []
    for filename in test_files:
        alert = load_json_alert(filename)
        alerts.append(alert)

        # Basic validation of required fields
        assert "agent" in alert
        assert "id" in alert["agent"]
        assert "name" in alert["agent"]
        assert "data" in alert
        assert "timestamp" in alert
        assert "rule" in alert
        assert "id" in alert["rule"]
        assert "level" in alert["rule"]


def test_alert_types():
    """Test specific alert types"""
    # Test Windows login failure
    win_alert = load_json_alert("win_4625.json")
    assert win_alert["data"]["win"]["system"]["eventID"] == "4625"
    assert win_alert["rule"]["id"] == "60204"

    # Test Fail2ban alert
    f2b_alert = load_json_alert("lin_fail2ban-1.json")
    assert f2b_alert["data"]["program_name"] == "fail2ban.filter"
    assert f2b_alert["rule"]["id"] == "833002"


def test_alert_geolocation():
    """Test alerts with geolocation data"""
    alerts_with_geo = [load_json_alert(f) for f in get_test_files() if "GeoLocation" in load_json_alert(f)]

    for alert in alerts_with_geo:
        geo = alert["GeoLocation"]
        assert "city_name" in geo
        assert "country_name" in geo
        assert "location" in geo
        assert "lat" in geo["location"]
        assert "lon" in geo["location"]


@pytest.mark.asyncio
async def test_file_monitor_processing():
    """Test FileMonitor processing of alerts"""
    # Load all test alerts
    test_files = get_test_files()
    alerts = [load_json_alert(f) for f in test_files]

    # Write alerts to temp file
    temp_file = await write_alerts_to_temp_file(alerts)
    monitor = None

    try:
        # Set up FileMonitor
        alert_queue = AsyncMaxSizeQueue()
        monitor = FileMonitor(file_path=temp_file, alert_queue=alert_queue, alert_prefix="{", tail=True)

        # Create task to run the monitor
        monitor_task = asyncio.create_task(monitor.check_file())

        # Wait for processing
        await asyncio.sleep(1)

        # Cancel the monitor task
        monitor_task.cancel()
        with suppress(asyncio.CancelledError):
            await monitor_task

        # Verify results
        processed_alerts = []
        while not alert_queue.empty():
            processed_alerts.append(await alert_queue.get())
            alert_queue.task_done()

        # Compare original and processed alerts
        assert len(processed_alerts) == len(alerts), f"Expected {len(alerts)} alerts, got {len(processed_alerts)}"

        for orig, proc in zip(alerts, processed_alerts, strict=False):
            assert orig["id"] == proc["id"]
            assert orig["rule"]["id"] == proc["rule"]["id"]
            assert orig["timestamp"] == proc["timestamp"]

    finally:
        # Cleanup
        if monitor:
            await monitor.close()
        Path(temp_file).unlink()


@pytest.mark.asyncio
async def test_file_monitor_rotation():
    """Test FileMonitor handling file rotation"""
    # Load test alerts
    alerts_batch1 = [load_json_alert("win_4625.json")]
    alerts_batch2 = [load_json_alert("lin_fail2ban-1.json")]

    temp_file = await write_alerts_to_temp_file(alerts_batch1)
    monitor = None

    try:
        # Set up monitoring
        alert_queue = AsyncMaxSizeQueue()
        monitor = FileMonitor(file_path=temp_file, alert_queue=alert_queue, alert_prefix="{", tail=True)

        # First check with task
        check_task = asyncio.create_task(monitor.check_file())
        await asyncio.sleep(0.1)  # Allow time for processing
        check_task.cancel()

        with suppress(asyncio.CancelledError):
            await check_task

        # Verify first batch
        assert not alert_queue.empty(), "No alerts processed from first batch"
        first_alert = await alert_queue.get()
        assert first_alert["rule"]["id"] == "60204", "Wrong alert processed"
        alert_queue.task_done()

        # Simulate file rotation
        await monitor.close()
        await asyncio.sleep(0.2)  # Wait for monitor to fully close
        Path(temp_file).unlink()
        temp_file = await write_alerts_to_temp_file(alerts_batch2)
        await asyncio.sleep(0.2)  # Allow filesystem to update and file to be fully written

        # Reopen monitor with new file
        monitor = FileMonitor(file_path=temp_file, alert_queue=alert_queue, alert_prefix="{", tail=True)
        await asyncio.sleep(0.1)  # Allow monitor to initialize

        check_task2 = asyncio.create_task(monitor.check_file())
        await asyncio.sleep(0.2)  # Allow more time for processing
        check_task2.cancel()

        with suppress(asyncio.CancelledError):
            await check_task2

        # Verify second batch
        assert not alert_queue.empty(), "No alerts processed after rotation"
        second_alert = await alert_queue.get()
        assert second_alert["rule"]["id"] == "833002", "Wrong alert processed after rotation"
        alert_queue.task_done()

        # Verify no extra alerts
        assert alert_queue.empty(), "Unexpected extra alerts in queue"

    finally:
        # Cleanup
        if monitor:
            await monitor.close()
        temp_path = Path(temp_file)
        if temp_path.exists():
            temp_path.unlink()
