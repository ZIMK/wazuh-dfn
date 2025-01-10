"""Test module for Windows Handler."""

import logging
from unittest.mock import MagicMock, patch

import pytest

from wazuh_dfn.services.handlers.windows_handler import WindowsHandler

LOGGER = logging.getLogger(__name__)


@pytest.fixture
def kafka_service():
    """Create a Kafka service instance."""
    return MagicMock()


@pytest.fixture
def wazuh_service():
    """Create a Wazuh service instance."""
    return MagicMock()


@pytest.fixture
def windows_handler(kafka_service, wazuh_service):
    """Create a WindowsHandler instance."""
    return WindowsHandler(kafka_service, wazuh_service)


@pytest.fixture
def sample_4625_alert():
    """Create a sample Windows 4625 alert."""
    return {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5},
        "data": {
            "win": {
                "system": {
                    "eventID": "4625",
                    "computer": "TestComputer",
                    "eventSourceName": "Microsoft-Windows-Security-Auditing",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": "2024-01-01T00:00:00",
                    "level": "0",
                    "task": "12345",
                    "opcode": "0",
                    "version": "0",
                },
                "eventdata": {
                    "targetUserName": "TestUser",
                    "targetDomainName": "TestDomain",
                    "workstationName": "TestWorkstation",
                    "ipAddress": "192.168.1.100",
                },
            }
        },
    }


@pytest.fixture
def sample_1100_alert():
    """Create a sample Windows 1100 alert."""
    return {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5},
        "data": {
            "win": {
                "system": {
                    "eventID": "1100",
                    "computer": "TestComputer",
                    "eventSourceName": "Microsoft-Windows-Security-Auditing",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": "2024-01-01T00:00:00",
                    "level": "0",
                    "task": "12345",
                    "opcode": "0",
                    "version": "0",
                }
            }
        },
    }


def test_windows_handler_initialization(windows_handler):
    """Test WindowsHandler initialization."""
    assert windows_handler.kafka_service is not None
    assert windows_handler.wazuh_service is not None


def test_windows_handler_process_alert(windows_handler, sample_4625_alert):
    """Test WindowsHandler alert processing."""
    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(sample_4625_alert)

    # Verify Kafka message was sent
    assert windows_handler.kafka_service.send_message.called
    # Verify Wazuh event was sent
    assert windows_handler.wazuh_service.send_event.called


def test_windows_handler_invalid_alert(windows_handler):
    """Test WindowsHandler with invalid alert."""
    invalid_alert = {"invalid": "data"}
    windows_handler.process_alert(invalid_alert)
    assert not windows_handler.kafka_service.send_message.called
    assert not windows_handler.wazuh_service.send_event.called


def test_windows_handler_missing_data(windows_handler):
    """Test WindowsHandler with missing data fields."""
    incomplete_alert = {"timestamp": "2024-01-01T00:00:00", "data": {"win": {"system": {"eventID": "4625"}}}}
    windows_handler.process_alert(incomplete_alert)
    assert not windows_handler.kafka_service.send_message.called
    assert not windows_handler.wazuh_service.send_event.called


def test_windows_handler_kafka_error(windows_handler, sample_4625_alert):
    """Test WindowsHandler Kafka error handling."""
    windows_handler.kafka_service.send_message = MagicMock(return_value=False)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(sample_4625_alert)

    assert windows_handler.kafka_service.send_message.called
    assert not windows_handler.wazuh_service.send_event.called


@patch("wazuh_dfn.services.handlers.windows_handler.LOGGER")
def test_windows_handler_logging(mock_logger, windows_handler, sample_4625_alert):
    """Test WindowsHandler logging."""
    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(sample_4625_alert)

    # Verify debug logging occurred
    mock_logger.debug.assert_called()


def test_windows_handler_alert_transformation(windows_handler, sample_4625_alert):
    """Test WindowsHandler alert transformation."""
    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(sample_4625_alert)

    # Verify the transformed alert structure
    call_args = windows_handler.kafka_service.send_message.call_args[0][0]
    assert isinstance(call_args, dict)
    assert "timestamp" in call_args
    assert "event_raw" in call_args
    assert "event_format" in call_args
    assert call_args["event_format"] == "windows-xml"


def test_windows_handler_event_1102(windows_handler):
    """Test WindowsHandler processing Event ID 1102 (Security Log Cleared)."""
    event_1102 = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5},
        "data": {
            "win": {
                "system": {
                    "eventID": "1102",
                    "computer": "TestComputer",
                    "eventSourceName": "Microsoft-Windows-Security-Auditing",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": "2024-01-01T00:00:00",
                    "level": "0",
                    "task": "12345",
                    "opcode": "0",
                    "version": "0",
                },
                "eventdata": {"subjectUserName": "TestUser", "subjectDomainName": "TestDomain"},
            }
        },
    }

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(event_1102)

    # Verify message was sent
    assert windows_handler.kafka_service.send_message.called
    assert windows_handler.wazuh_service.send_event.called


def test_windows_handler_multiple_alerts(windows_handler, sample_4625_alert):
    """Test WindowsHandler processing multiple alerts in sequence."""
    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    # Process same alert multiple times
    num_alerts = 3
    for _ in range(num_alerts):
        windows_handler.process_alert(sample_4625_alert)

    assert windows_handler.kafka_service.send_message.call_count == num_alerts
    assert windows_handler.wazuh_service.send_event.call_count == num_alerts


def test_windows_handler_alert_enrichment(windows_handler):
    """Test WindowsHandler alert enrichment with additional context."""
    enriched_alert = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5},
        "data": {
            "win": {
                "system": {
                    "eventID": "4625",
                    "computer": "TestComputer",
                    "eventSourceName": "Microsoft-Windows-Security-Auditing",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": "2024-01-01T00:00:00",
                    "level": "0",
                    "task": "12345",
                    "opcode": "0",
                    "version": "0",
                    "keywords": "Audit Failure",
                },
                "eventdata": {
                    "targetUserName": "TestUser",
                    "targetDomainName": "TestDomain",
                    "workstationName": "TestWorkstation",
                    "ipAddress": "192.168.1.100",
                    "logonType": "3",
                    "processName": "C:\\Windows\\System32\\svchost.exe",
                    "status": "0xC000006D",
                    "subStatus": "0xC0000064",
                },
            }
        },
    }

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(enriched_alert)

    # Verify enriched alert was processed
    assert windows_handler.kafka_service.send_message.called
    call_args = windows_handler.kafka_service.send_message.call_args[0][0]
    assert "event_raw" in call_args
    assert "event_format" in call_args
    assert call_args["event_format"] == "windows-xml"


@patch("wazuh_dfn.services.handlers.windows_handler.LOGGER")
def test_windows_handler_error_logging(mock_logger, windows_handler):
    """Test WindowsHandler detailed error logging."""
    # Create an alert that will trigger an error in _process_windows_alert
    invalid_alert = {"data": {"win": {"system": {"eventID": "4625"}}}}
    windows_handler.process_alert(invalid_alert)

    # Verify error was logged
    mock_logger.error.assert_called_with("Error processing Windows alert: Unknown: 'providerName'", exc_info=True)


def test_windows_handler_wazuh_integration(windows_handler, sample_4625_alert):
    """Test WindowsHandler integration with Wazuh service."""
    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(sample_4625_alert)

    # Verify Wazuh service interaction
    windows_handler.wazuh_service.send_event.assert_called_with(
        alert=sample_4625_alert,
        event_format="windows-xml",
        event_id="4625",
        win_timestamp=sample_4625_alert["data"]["win"]["system"]["systemTime"],
        wz_timestamp=sample_4625_alert["timestamp"],
    )


def test_windows_handler_event_1100(windows_handler, sample_1100_alert):
    """Test WindowsHandler processing Event ID 1100 (Service Shutdown)."""
    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(sample_1100_alert)

    assert windows_handler.kafka_service.send_message.called
    assert windows_handler.wazuh_service.send_event.called

    # Verify the event data structure
    call_args = windows_handler.kafka_service.send_message.call_args[0][0]
    assert "event_raw" in call_args
    assert "event_format" in call_args
    assert call_args["event_format"] == "windows-xml"


def test_windows_handler_missing_eventdata(windows_handler, sample_4625_alert):
    """Test WindowsHandler with missing eventdata field."""
    alert = sample_4625_alert.copy()
    alert["id"] = "test-alert-id"  # Add required id field
    alert["agent"] = {"id": "001", "name": "test-agent"}  # Add required agent field
    del alert["data"]["win"]["eventdata"]

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(alert)

    assert windows_handler.kafka_service.send_message.called
    assert windows_handler.wazuh_service.send_event.called


def test_windows_handler_missing_system_fields(windows_handler):
    """Test WindowsHandler with missing optional system fields."""
    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "id": "test-alert-id",  # Add required id field
        "agent": {"id": "001", "name": "test-agent"},  # Add required agent field
        "rule": {"level": 5},
        "data": {
            "win": {
                "system": {
                    "eventID": "4625",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": "2024-01-01T00:00:00",
                }
            }
        },
    }

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(alert)

    assert windows_handler.kafka_service.send_message.called
    assert windows_handler.wazuh_service.send_event.called


def test_windows_handler_empty_eventdata(windows_handler):
    """Test WindowsHandler with empty eventdata."""
    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5},
        "data": {
            "win": {
                "system": {
                    "eventID": "4625",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": "2024-01-01T00:00:00",
                },
                "eventdata": {},
            }
        },
    }

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(alert)

    assert windows_handler.kafka_service.send_message.called
    assert windows_handler.wazuh_service.send_event.called


def test_windows_handler_missing_win_field(windows_handler):
    """Test WindowsHandler with missing win field."""
    alert = {"timestamp": "2024-01-01T00:00:00", "rule": {"level": 5}, "data": {}}

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(alert)

    assert not windows_handler.kafka_service.send_message.called
    assert not windows_handler.wazuh_service.send_event.called


def test_windows_handler_event_1102_missing_fields(windows_handler):
    """Test WindowsHandler Event ID 1102 with missing logFileCleared field."""
    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "id": "test-alert-id",
        "agent": {"id": "001", "name": "test-agent"},
        "rule": {"level": 5},
        "data": {
            "win": {
                "system": {
                    "eventID": "1102",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": "2024-01-01T00:00:00",
                }
            }
        },
    }

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(alert)

    assert windows_handler.kafka_service.send_message.called
    assert windows_handler.wazuh_service.send_event.called


def test_windows_handler_missing_required_fields(windows_handler):
    """Test WindowsHandler with missing required system fields."""
    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "id": "test-alert-id",
        "agent": {"id": "001", "name": "test-agent"},
        "rule": {"level": 5},
        "data": {"win": {"system": {"eventID": "4625"}}},  # Missing required providerName, providerGuid, systemTime
    }

    windows_handler.kafka_service.send_message = MagicMock(return_value=True)
    windows_handler.wazuh_service.send_event = MagicMock()

    windows_handler.process_alert(alert)

    assert not windows_handler.kafka_service.send_message.called
    assert not windows_handler.wazuh_service.send_event.called
