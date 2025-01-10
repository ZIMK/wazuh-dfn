import json
import os
import tempfile
from pathlib import Path
from queue import Queue
from threading import Thread
from time import sleep

from wazuh_dfn.services.file_monitor import FileMonitor


# Utility functions
def load_json_alert(filename):
    """Load a JSON alert file from the tests directory"""
    test_dir = Path(__file__).parent
    with open(test_dir / filename, "r") as f:
        return json.load(f)


def get_test_files():
    """Get list of all JSON test files"""
    test_dir = Path(__file__).parent
    return [f for f in os.listdir(test_dir) if f.endswith(".json")]


def write_alerts_to_temp_file(alerts):
    """Write alerts to a temporary file"""
    temp = tempfile.NamedTemporaryFile(mode="w", delete=False)
    for alert in alerts:
        json.dump(alert, temp)
        temp.write("\n")
    temp.close()
    return temp.name


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


def test_file_monitor_processing():
    """Test FileMonitor processing of alerts"""
    # Load all test alerts
    test_files = get_test_files()
    alerts = [load_json_alert(f) for f in test_files]

    # Write alerts to temp file
    temp_file = write_alerts_to_temp_file(alerts)

    try:
        # Set up FileMonitor
        alert_queue = Queue()
        monitor = FileMonitor(file_path=temp_file, alert_queue=alert_queue, alert_prefix="{", tail=True)

        # Start monitoring in a separate thread
        thread = Thread(target=lambda: monitor.check_file())
        thread.start()

        # Wait for processing
        sleep(1)

        # Verify results
        processed_alerts = []
        while not alert_queue.empty():
            processed_alerts.append(alert_queue.get())

        # Compare original and processed alerts
        assert len(processed_alerts) == len(alerts), f"Expected {len(alerts)} alerts, got {len(processed_alerts)}"

        for orig, proc in zip(alerts, processed_alerts):
            assert orig["id"] == proc["id"]
            assert orig["rule"]["id"] == proc["rule"]["id"]
            assert orig["timestamp"] == proc["timestamp"]

    finally:
        # Cleanup
        if monitor:
            monitor.close()
        os.unlink(temp_file)


def test_file_monitor_rotation():
    """Test FileMonitor handling file rotation"""
    # Load test alerts
    alerts_batch1 = [load_json_alert("win_4625.json")]
    alerts_batch2 = [load_json_alert("lin_fail2ban-1.json")]

    temp_file = write_alerts_to_temp_file(alerts_batch1)

    try:
        # Set up monitoring
        alert_queue = Queue()
        monitor = FileMonitor(file_path=temp_file, alert_queue=alert_queue, alert_prefix="{", tail=True)

        # First check
        monitor.check_file()
        sleep(0.1)  # Allow time for processing

        # Verify first batch
        assert not alert_queue.empty(), "No alerts processed from first batch"
        first_alert = alert_queue.get()
        assert first_alert["rule"]["id"] == "60204", "Wrong alert processed"

        # Simulate file rotation
        monitor.close()
        sleep(0.2)  # Wait for monitor to fully close
        os.unlink(temp_file)
        temp_file = write_alerts_to_temp_file(alerts_batch2)
        sleep(0.2)  # Allow filesystem to update and file to be fully written

        # Reopen monitor with new file
        monitor = FileMonitor(file_path=temp_file, alert_queue=alert_queue, alert_prefix="{", tail=True)
        sleep(0.1)  # Allow monitor to initialize
        monitor.check_file()
        sleep(0.2)  # Allow more time for processing

        # Verify second batch
        assert not alert_queue.empty(), "No alerts processed after rotation"
        second_alert = alert_queue.get()
        assert second_alert["rule"]["id"] == "833002", "Wrong alert processed after rotation"

        # Verify no extra alerts
        assert alert_queue.empty(), "Unexpected extra alerts in queue"

    finally:
        # Cleanup
        if monitor:
            monitor.close()
        if os.path.exists(temp_file):
            os.unlink(temp_file)


if __name__ == "__main__":
    test_load_alerts()
    test_alert_types()
    test_alert_geolocation()
    test_file_monitor_processing()
    test_file_monitor_rotation()
    print("All tests passed!")
