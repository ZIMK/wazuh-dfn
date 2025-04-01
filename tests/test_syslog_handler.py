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
