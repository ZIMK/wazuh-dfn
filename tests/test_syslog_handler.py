"""Test module for Syslog Handler."""

import logging
from unittest.mock import MagicMock, patch

import pytest

from wazuh_dfn.services.handlers import SyslogHandler

# Configure logging
logging.basicConfig(level=logging.DEBUG)

LOGGER = logging.getLogger(__name__)


@pytest.fixture
def syslog_handler(sample_config, kafka_service, wazuh_service):
    """Create a SyslogHandler instance."""
    return SyslogHandler(sample_config.misc, kafka_service, wazuh_service)


def test_syslog_handler_initialization(syslog_handler):
    """Test SyslogHandler initialization."""
    assert syslog_handler is not None
    assert hasattr(syslog_handler, "kafka_service")
    assert hasattr(syslog_handler, "wazuh_service")
    assert hasattr(syslog_handler, "config")


@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
def test_syslog_handler_process_alert(mock_ipaddress, syslog_handler):
    """Test SyslogHandler alert processing."""
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
    syslog_handler.kafka_service.send_message = MagicMock(return_value=True)
    syslog_handler.wazuh_service.send_event = MagicMock()
    syslog_handler.own_network = None  # Disable own network check for test

    syslog_handler.process_alert(alert)

    # Verify Kafka message was sent
    assert syslog_handler.kafka_service.send_message.called


def test_syslog_handler_invalid_alert(syslog_handler):
    """Test SyslogHandler with invalid alert."""
    invalid_alert = {"invalid": "data"}
    syslog_handler.kafka_service.send_message = MagicMock()
    syslog_handler.wazuh_service.send_event = MagicMock()

    syslog_handler.process_alert(invalid_alert)

    # Verify no messages were sent
    assert not syslog_handler.kafka_service.send_message.called
    assert not syslog_handler.wazuh_service.send_event.called


def test_syslog_handler_missing_data(syslog_handler):
    """Test SyslogHandler with missing data fields."""
    incomplete_alert = {"data": {"program_name": "fail2ban.actions"}}
    syslog_handler.kafka_service.send_message = MagicMock()
    syslog_handler.wazuh_service.send_event = MagicMock()

    syslog_handler.process_alert(incomplete_alert)

    # Verify no messages were sent
    assert not syslog_handler.kafka_service.send_message.called
    assert not syslog_handler.wazuh_service.send_event.called


def test_syslog_handler_internal_ip(syslog_handler):
    """Test SyslogHandler with internal IP address."""
    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "rule": {"level": 5, "groups": ["fail2ban"]},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE"},
        "agent": {"name": "test-agent"},
        "full_log": "fail2ban Test alert from 192.168.1.100",
    }

    syslog_handler.kafka_service.send_message = MagicMock()
    syslog_handler.wazuh_service.send_event = MagicMock()

    syslog_handler.process_alert(alert)

    # Verify no messages were sent for internal IP
    assert not syslog_handler.kafka_service.send_message.called
    assert not syslog_handler.wazuh_service.send_event.called


@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
def test_syslog_handler_kafka_error(mock_ipaddress, syslog_handler):
    """Test SyslogHandler Kafka error handling."""
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
    syslog_handler.kafka_service.send_message = MagicMock(return_value=False)
    syslog_handler.wazuh_service.send_event = MagicMock()
    syslog_handler.own_network = None  # Disable own network check for test

    syslog_handler.process_alert(alert)

    # Verify Kafka was called but not Wazuh
    assert syslog_handler.kafka_service.send_message.called
    assert not syslog_handler.wazuh_service.send_event.called


@patch("wazuh_dfn.services.handlers.syslog_handler.LOGGER")
@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
def test_syslog_handler_logging(mock_ipaddress, mock_logger, syslog_handler):
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
    syslog_handler.kafka_service.send_message = MagicMock(return_value=True)
    syslog_handler.wazuh_service.send_event = MagicMock()
    syslog_handler.own_network = None  # Disable own network check for test

    syslog_handler.process_alert(alert)

    # Verify debug logging occurred
    mock_logger.debug.assert_called()


@patch("wazuh_dfn.services.wazuh_service.socket")
@patch("wazuh_dfn.services.handlers.syslog_handler.ipaddress")
def test_syslog_handler_wazuh_integration(mock_ipaddress, mock_socket, syslog_handler):
    """Test SyslogHandler integration with Wazuh service."""
    # Mock socket connection
    mock_sock = MagicMock()
    mock_socket.return_value = mock_sock
    mock_socket.AF_INET = 2
    mock_socket.SOCK_DGRAM = 2

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
    syslog_handler.kafka_service.send_message = MagicMock(return_value=True)
    syslog_handler.wazuh_service.send_event = MagicMock()
    syslog_handler.wazuh_service._socket = mock_sock
    syslog_handler.own_network = None  # Disable own network check for test

    syslog_handler.process_alert(alert)

    # Verify Wazuh service interaction
    syslog_handler.wazuh_service.send_event.assert_called_once_with(
        alert=alert, event_format="syslog5424-json", wz_timestamp=alert["timestamp"]
    )


def test_syslog_handler_invalid_own_network(sample_config, kafka_service, wazuh_service):
    """Test SyslogHandler with invalid own_network configuration."""
    sample_config.misc.own_network = "invalid_network"
    handler = SyslogHandler(sample_config.misc, kafka_service, wazuh_service)

    assert handler.own_network is None


def test_syslog_handler_invalid_alert_structure(syslog_handler, caplog):
    """Test SyslogHandler with an invalid alert structure."""
    caplog.set_level(logging.DEBUG)

    invalid_alert = {"data": {"srcip": "192.168.1.100"}}  # Missing required fields
    syslog_handler.process_alert(invalid_alert)

    # Check logs
    assert any(
        "No fail2ban alert to process" in record.message for record in caplog.records
    ), "Expected debug info message not found in logs"


def test_syslog_handler_internal_ip_handling(syslog_handler, caplog):
    """Test SyslogHandler with internal IP address handling."""
    caplog.set_level(logging.DEBUG)

    syslog_handler.own_network = ["192.168.1.0/24"]
    alert = {"data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions"}, "rule": {"groups": ["fail2ban"]}}
    syslog_handler.process_alert(alert)

    # Check logs
    assert any(
        "Skipping fail2ban alert from internal IP:" in record.message for record in caplog.records
    ), "Expected debug info message not found in logs"


def test_syslog_handler_kafka_failure(syslog_handler, caplog):
    """Test SyslogHandler when Kafka sending fails."""
    caplog.set_level(logging.DEBUG)

    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "agent": {"name": "test-agent"},
        "data": {"srcip": "192.168.1.100", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "rule": {"groups": ["fail2ban"]},
        "full_log": "NOTICE Test alert from 192.168.1.100",
    }
    syslog_handler.kafka_service.send_message = MagicMock(return_value=False)  # Simulate Kafka failure
    syslog_handler.process_alert(alert)

    # Check logs
    assert any(
        "Failed to send fail2ban alert to Kafka" in record.message for record in caplog.records
    ), "Expected debug info message not found in logs"


def test_syslog_handler_invalid_ip_format(syslog_handler, caplog):
    """Test SyslogHandler with invalid IP address format."""
    caplog.set_level(logging.DEBUG)

    alert = {
        "timestamp": "2024-01-01T00:00:00",
        "agent": {"name": "test-agent"},
        "data": {"srcip": "invalid_ip", "program_name": "fail2ban.actions", "severity": "NOTICE", "pid": "12345"},
        "rule": {"groups": ["fail2ban"]},
        "full_log": "NOTICE Test alert from invalid_ip",
    }

    syslog_handler.own_network = ["192.168.1.0/24"]
    syslog_handler.kafka_service.send_message = MagicMock(return_value=False)  # Simulate Kafka failure
    syslog_handler.process_alert(alert)

    # Check logs
    assert any(
        "Skipping fail2ban alert from internal IP:" in record.message for record in caplog.records
    ), "Expected debug info message not found in logs"
