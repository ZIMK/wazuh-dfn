"""Test module for Syslog Handler."""

import asyncio
import ipaddress
import logging
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from wazuh_dfn.services.handlers import SyslogHandler

# Configure logging
logging.basicConfig(level=logging.DEBUG)

LOGGER = logging.getLogger(__name__)


@pytest.fixture
def syslog_handler(sample_config, kafka_service, wazuh_service):
    """Create a SyslogHandler instance."""
    return SyslogHandler(sample_config.misc, kafka_service, wazuh_service)


@pytest.mark.asyncio
async def test_syslog_handler_initialization(syslog_handler):
    """Test SyslogHandler initialization."""
    assert syslog_handler.kafka_service is not None
    assert syslog_handler.wazuh_service is not None
    assert syslog_handler.own_network is None  # Default config has no own_network


@pytest.mark.asyncio
@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
async def test_syslog_handler_process_alert(mock_ipaddress, syslog_handler):
    """Test SyslogHandler alert processing."""
    # Mock IP validation
    mock_ip = MagicMock()
    mock_ip.is_global = True
    mock_ip.is_private = False
    mock_ip.__str__.return_value = "192.168.1.100"
    mock_ipaddress.ip_address.return_value = mock_ip
    mock_ipaddress.IPv4Address = type(mock_ip)

    alert = {
        "id": "test-alert-1",  # Add ID for proper logging
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "groups": ["fail2ban"]},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "agent": {"name": "test-agent"},
        "full_log": "NOTICE Test alert from 192.168.1.100",
    }

    # Mock services
    syslog_handler.kafka_service.send_message = AsyncMock(return_value=True)
    syslog_handler.wazuh_service.send_event = AsyncMock()
    syslog_handler.own_network = None  # Disable own network check for test

    # Mock _is_global_ip to ensure it returns True
    with patch.object(syslog_handler, "_is_global_ip", return_value=True):
        await syslog_handler.process_alert(alert)

        # Wait for the asyncio task to complete before checking assertions
        await asyncio.sleep(0.1)

        # Verify Kafka message was sent
        assert syslog_handler.kafka_service.send_message.called


@pytest.mark.asyncio
async def test_syslog_handler_invalid_alert(syslog_handler):
    """Test SyslogHandler with invalid alert."""
    invalid_alert = {"invalid": "data"}
    syslog_handler.kafka_service.send_message = AsyncMock()
    syslog_handler.wazuh_service.send_event = AsyncMock()

    await syslog_handler.process_alert(invalid_alert)

    # Verify no messages were sent
    assert not syslog_handler.kafka_service.send_message.called
    assert not syslog_handler.wazuh_service.send_event.called


@pytest.mark.asyncio
async def test_syslog_handler_missing_data(syslog_handler):
    """Test SyslogHandler with missing data fields."""
    incomplete_alert = {"data": {"program_name": "fail2ban.actions"}}
    syslog_handler.kafka_service.send_message = AsyncMock()
    syslog_handler.wazuh_service.send_event = AsyncMock()

    await syslog_handler.process_alert(incomplete_alert)

    # Verify no messages were sent
    assert not syslog_handler.kafka_service.send_message.called
    assert not syslog_handler.wazuh_service.send_event.called


@pytest.mark.asyncio
async def test_syslog_handler_internal_ip(syslog_handler):
    """Test SyslogHandler with internal IP address."""
    # Setup the own_network correctly to test internal IP filtering
    syslog_handler.own_network = ipaddress.ip_network("192.168.1.0/24")

    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "groups": ["fail2ban"]},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE"},
        "agent": {"name": "test-agent"},
        "full_log": "fail2ban Test alert from 192.168.1.100",
        "id": "test-alert-1",
    }

    # Mock _is_global_ip to return False for our test IP
    with patch.object(syslog_handler, "_is_global_ip", return_value=False):
        syslog_handler.kafka_service.send_message = AsyncMock()
        syslog_handler.wazuh_service.send_event = AsyncMock()

        await syslog_handler.process_alert(alert)

        # Verify no messages were sent for internal IP
        assert not syslog_handler.kafka_service.send_message.called
        assert not syslog_handler.wazuh_service.send_event.called


@pytest.mark.asyncio
@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
async def test_syslog_handler_kafka_error(mock_ipaddress, syslog_handler):
    """Test SyslogHandler Kafka error handling."""
    # Mock IP validation
    mock_ip = MagicMock()
    mock_ip.is_global = True
    mock_ip.is_private = False
    mock_ip.__str__.return_value = "192.168.1.100"
    mock_ipaddress.ip_address.return_value = mock_ip
    mock_ipaddress.IPv4Address = type(mock_ip)

    alert = {
        "id": "test-alert-1",  # Add ID for proper logging
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "groups": ["fail2ban"]},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "agent": {"name": "test-agent"},
        "full_log": "NOTICE Test alert from 192.168.1.100",
    }

    # Mock services
    syslog_handler.kafka_service.send_message = AsyncMock(return_value=False)
    syslog_handler.wazuh_service.send_error = AsyncMock()  # Add mock for send_error

    # Mock _is_global_ip to ensure it returns True - this is crucial
    with patch.object(syslog_handler, "_is_global_ip", return_value=True):
        await syslog_handler.process_alert(alert)

        # Wait for the asyncio task to complete
        await asyncio.sleep(0.1)

        # Verify Kafka was called
        assert syslog_handler.kafka_service.send_message.called
        # Verify the error was sent
        assert syslog_handler.wazuh_service.send_error.called


@pytest.mark.asyncio
@patch("wazuh_dfn.services.handlers.syslog_handler.LOGGER")
@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
async def test_syslog_handler_logging(mock_ipaddress, mock_logger, syslog_handler):
    """Test SyslogHandler logging."""
    # Mock IP validation
    mock_ip = MagicMock()
    mock_ip.is_global = True
    mock_ip.is_private = False
    mock_ip.__str__.return_value = "192.168.1.100"
    mock_ipaddress.ip_address.return_value = mock_ip
    mock_ipaddress.IPv4Address = type(mock_ip)

    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "groups": ["fail2ban"]},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "agent": {"name": "test-agent"},
        "full_log": "NOTICE Test alert from 192.168.1.100",
    }

    # Mock services
    syslog_handler.kafka_service.send_message = AsyncMock(return_value=True)
    syslog_handler.wazuh_service.send_event = AsyncMock()
    syslog_handler.own_network = None  # Disable own network check for test

    await syslog_handler.process_alert(alert)

    # Verify debug logging occurred
    mock_logger.debug.assert_called()


@pytest.mark.asyncio
@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
async def test_syslog_handler_wazuh_integration(mock_ipaddress, syslog_handler):
    """Test SyslogHandler integration with Wazuh service."""
    # Mock IP validation
    mock_ip = MagicMock()
    mock_ip.is_global = True
    mock_ip.is_private = False
    mock_ip.__str__.return_value = "192.168.1.100"
    mock_ipaddress.ip_address.return_value = mock_ip
    mock_ipaddress.IPv4Address = type(mock_ip)

    alert = {
        "id": "test-alert-1",
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "groups": ["fail2ban"]},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "agent": {"name": "test-agent"},
        "full_log": "NOTICE Test alert from 192.168.1.100",
    }

    # Mock services
    syslog_handler.kafka_service.send_message = AsyncMock(return_value=True)
    syslog_handler.wazuh_service.send_event = AsyncMock()
    syslog_handler.own_network = None  # Disable own network check for test

    # Mock _is_global_ip to ensure it returns True
    with patch.object(syslog_handler, "_is_global_ip", return_value=True):
        await syslog_handler.process_alert(alert)

        # Wait for the asyncio task to complete
        await asyncio.sleep(0.1)

        # Verify Wazuh service interaction with correct parameters
        syslog_handler.wazuh_service.send_event.assert_called_once_with(
            alert=alert, event_format="syslog5424-json", wz_timestamp=alert.get("timestamp")
        )


@pytest.mark.asyncio
async def test_syslog_handler_invalid_own_network(sample_config, kafka_service, wazuh_service):
    """Test SyslogHandler with invalid own_network configuration."""
    sample_config.misc.own_network = "invalid_network"
    handler = SyslogHandler(sample_config.misc, kafka_service, wazuh_service)

    assert handler.own_network is None


@pytest.mark.asyncio
async def test_syslog_handler_invalid_alert_structure(syslog_handler, caplog):
    """Test SyslogHandler with an invalid alert structure."""
    caplog.set_level(logging.DEBUG)

    invalid_alert = {"data": {"srcip": "192.168.1.100"}}  # Missing required fields
    await syslog_handler.process_alert(invalid_alert)

    # Check logs
    assert any(
        "No fail2ban alert to process" in record.message for record in caplog.records
    ), "Expected debug info message not found in logs"


@pytest.mark.asyncio
async def test_syslog_handler_internal_ip_handling(syslog_handler, caplog):
    """Test SyslogHandler with internal IP address handling."""
    caplog.set_level(logging.DEBUG)

    # Set own_network correctly as an ip_network object
    syslog_handler.own_network = ipaddress.ip_network("192.168.1.0/24")

    alert = {
        "id": "test-alert-1",
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions"},
        "rule": {"groups": ["fail2ban"]},
    }

    # Mock _is_global_ip to return False for our test IP
    with patch.object(syslog_handler, "_is_global_ip", return_value=False):
        await syslog_handler.process_alert(alert)

    # Check logs for the actual message used in the implementation
    assert any(
        "Ignoring internal IP: 192.168.1.100" in record.message for record in caplog.records
    ), "Expected info message about ignoring internal IP not found in logs"


@pytest.mark.asyncio
async def test_syslog_handler_kafka_failure(syslog_handler, caplog):
    """Test SyslogHandler when Kafka sending fails."""
    caplog.set_level(logging.ERROR)

    alert = {
        "id": "test-alert-1",
        "timestamp": "2024-01-01T00:00:00",
        "agent": {"name": "test-agent"},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "rule": {"groups": ["fail2ban"]},
        "full_log": "NOTICE Test alert from 192.168.1.100",
    }

    # Mock _is_global_ip to return True to process the alert
    with patch.object(syslog_handler, "_is_global_ip", return_value=True):
        syslog_handler.kafka_service.send_message = AsyncMock(return_value=False)  # Simulate Kafka failure
        syslog_handler.wazuh_service.send_error = AsyncMock()  # Mock the error sending

        await syslog_handler.process_alert(alert)

        # Wait for asyncio task to complete
        await asyncio.sleep(0.1)

    # Get the exact error message format using string formatting with the alert ID
    expected_error_msg = f"Failed to send fail2ban alert to Kafka {alert['id']}"

    # Check logs for the specific error message
    assert any(
        expected_error_msg in record.message for record in caplog.records
    ), f"Expected error message '{expected_error_msg}' not found in logs"

    # Verify send_error was called
    assert syslog_handler.wazuh_service.send_error.called


@pytest.mark.asyncio
async def test_syslog_handler_invalid_ip_format(syslog_handler, caplog):
    """Test SyslogHandler with invalid IP address format."""
    caplog.set_level(logging.ERROR)

    alert = {
        "id": "test-alert-1",
        "timestamp": "2024-01-01T00:00:00",
        "agent": {"name": "test-agent"},
        "data": {"srcip": "invalid_ip", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "rule": {"groups": ["fail2ban"]},
        "full_log": "NOTICE Test alert from invalid_ip",
    }

    # Set own_network correctly
    syslog_handler.own_network = ipaddress.ip_network("192.168.1.0/24")

    # Make sure kafka_service.send_message is properly mocked before the test
    syslog_handler.kafka_service.send_message = AsyncMock()

    await syslog_handler.process_alert(alert)

    # Now the mock should have the called attribute
    assert not syslog_handler.kafka_service.send_message.called


@pytest.mark.asyncio
async def test_process_alert_unexpected_exception(syslog_handler, caplog):
    """Test handling of unexpected exceptions in process_alert."""
    caplog.set_level(logging.ERROR)

    # Create a test alert
    test_alert = {
        "id": "test-error-alert",
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions"},
        "rule": {"groups": ["fail2ban"]},
    }

    # Mock _is_relevant_fail2ban_alert to raise an exception
    with patch.object(syslog_handler, "_is_relevant_fail2ban_alert", side_effect=Exception("Unexpected test error")):
        await syslog_handler.process_alert(test_alert)

    # Check error was logged with the alert ID
    assert any("Error processing Syslog alert: test-error-alert" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_is_global_ip_various_cases(syslog_handler):
    """Test IP address validation with various cases."""
    # Setup test network
    syslog_handler.own_network = ipaddress.ip_network("10.0.0.0/8")

    # Test cases
    assert syslog_handler._is_global_ip("8.8.8.8") is True  # Public IP
    assert syslog_handler._is_global_ip("192.168.1.1") is False  # Private IP
    assert syslog_handler._is_global_ip("10.1.2.3") is False  # Own network
    assert syslog_handler._is_global_ip("invalid_ip") is False  # Invalid IP
    assert syslog_handler._is_global_ip("2001:db8::1") is False  # IPv6 documentation address
    assert syslog_handler._is_global_ip("fe80::1") is False  # IPv6 link-local


@pytest.mark.asyncio
async def test_create_message_data_variations(syslog_handler):
    """Test message data creation with different alert structures."""
    # Test with minimal alert
    minimal_alert = {
        "timestamp": "2023-01-01T00:00:00",
        "data": {"program_name": "fail2ban.actions", "srcip": "192.168.1.1", "severity": ""},
        "rule": {"groups": ["fail2ban"]},
        "full_log": "Test log message",
        "agent": {"name": "test-agent"},
    }

    message = syslog_handler._create_message_data(minimal_alert)
    assert message["timestamp"] == "2023-01-01T00:00:00"
    assert message["appName"] == "fail2ban.actions"
    assert message["event_raw"].endswith("Test log message")

    # Test with severity variations
    for severity, expected in [("NOTICE", 5), ("WARNING", 4), ("ERROR", 3)]:
        alert = minimal_alert.copy()
        alert["data"] = alert["data"].copy()
        alert["data"]["severity"] = severity
        message = syslog_handler._create_message_data(alert)
        assert message["severity"] == expected


@pytest.mark.asyncio
async def test_send_message_error_handling(syslog_handler):
    """Test error handling in _send_message method."""
    # Create test message and mock services
    test_message = {"timestamp": "2023-01-01T00:00:00", "context_alert": {"id": "test-send-error"}}

    # Mock Kafka service to fail
    syslog_handler.kafka_service.send_message = AsyncMock(return_value=False)
    syslog_handler.wazuh_service.send_error = AsyncMock()

    # Call method and verify error handling
    await syslog_handler._send_message(test_message, "test-send-error")

    # Verify error was sent to Wazuh
    syslog_handler.wazuh_service.send_error.assert_called_once()
    call_args = syslog_handler.wazuh_service.send_error.call_args[0][0]
    assert call_args["error"] == 503
    assert "Failed to send fail2ban alert" in call_args["description"]
