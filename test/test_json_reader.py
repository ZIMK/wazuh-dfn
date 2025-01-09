import json
import os
import tempfile
import time

import pytest

from wazuh_dfn.services.json_reader import JSONReader


@pytest.fixture
def temp_json_file():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as f:
        json_data = {"alert": {"field": "value"}}
        f.write(json.dumps(json_data) + "\n")
        f.write(json.dumps(json_data) + "\n")
        f.flush()
        os.fsync(f.fileno())  # Force write to disk
        path = f.name
    time.sleep(0.1)  # Give filesystem time to complete write
    yield path
    os.unlink(path)


def test_json_reader_init():
    reader = JSONReader("test.json")
    assert reader.file_path == "test.json"
    assert reader.alert_prefix == ""
    assert reader.tail is True


def test_json_reader_context_manager(temp_json_file):
    # Write test data explicitly to ensure proper file closure
    test_data = {"alert": {"field": "value"}}
    with open(temp_json_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(test_data) + "\n")
        f.write(json.dumps(test_data) + "\n")
        f.flush()
        os.fsync(f.fileno())

    time.sleep(0.1)  # Ensure file operations are complete

    with JSONReader(file_path=temp_json_file, tail=False) as reader:
        assert reader.is_active()
        alerts = reader.next_alerts()
        assert len(alerts) == 2
        assert all(isinstance(alert, dict) for alert in alerts)
        assert all(alert["alert"]["field"] == "value" for alert in alerts)


def test_json_reader_file_not_found():
    reader = JSONReader("nonexistent.json")
    reader.open()
    assert not reader.is_active()


def test_json_reader_rotation(temp_json_file):
    with JSONReader(temp_json_file) as reader:
        # Simulate file rotation
        reader.fp.close()
        os.unlink(temp_json_file)

        with open(temp_json_file, "w") as f:
            json_data = {"alert": {"field": "new_value"}}
            f.write(json.dumps(json_data) + "\n")
            f.flush()  # Ensure contents are written to disk
            os.fsync(f.fileno())  # Force the OS to write buffers to disk

        time.sleep(0.1)  # Give the filesystem a moment to complete the write
        # Force rotation check
        reader.last_check_time = 0
        alerts = reader.next_alerts()
        print(len(alerts))
        assert len(alerts) == 1
        assert alerts[0]["alert"]["field"] == "new_value"


def test_json_reader_invalid_json(temp_json_file):
    with open(temp_json_file, "w") as f:
        f.write('{"invalid_json\n')

    with JSONReader(temp_json_file) as reader:
        alerts = reader.next_alerts()
        assert len(alerts) == 0


def test_json_reader_empty_file(temp_json_file):
    with open(temp_json_file, "w") as f:
        f.write("")

    with JSONReader(temp_json_file) as reader:
        alerts = reader.next_alerts()
        assert len(alerts) == 0
