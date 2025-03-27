"""Test module for WazuhService."""

import logging
import pytest
import socket
import sys
import threading
from pydantic import ValidationError
from unittest.mock import MagicMock, patch
from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.services.wazuh_service import SOCK_DGRAM, WazuhErrorMessage, WazuhService

# Use AF_UNIX for Unix systems, fallback to AF_INET for Windows
try:
    from socket import AF_UNIX as AF  # type: ignore[reportAttributeAccessIssue]
except ImportError:
    from socket import AF_INET as AF  # type: ignore[reportAttributeAccessIssue]

# Set up logging
LOGGER = logging.getLogger(__name__)


@pytest.fixture
def wazuh_config():
    """Create a sample WazuhConfig for testing."""
    if sys.platform == "win32":
        socket_path = ("localhost", 1514)  # Using AF_INET for Windows
    else:
        socket_path = "/var/ossec/queue/sockets/queue"  # Unix socket path
    return WazuhConfig(
        unix_socket_path=socket_path,
        max_event_size=65536,
        max_retries=3,
        retry_interval=1,
    )


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing."""
    return {
        "id": "test-alert-1",
        "agent": {"id": "001", "name": "test-agent", "ip": "192.168.1.100"},
        "data": {"field1": "value1", "field2": "value2"},
    }


@pytest.fixture
def mock_socket_instance():
    """Create a mock socket instance."""
    mock = MagicMock()
    mock.send = MagicMock(return_value=1)  # Return 1 to indicate successful send
    mock.close = MagicMock()
    mock.connect = MagicMock()
    return mock


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_initialization(mock_socket, wazuh_config):
    """Test WazuhService initialization."""
    service = WazuhService(wazuh_config)
    assert service.config == wazuh_config
    assert service._socket is None
    mock_socket.assert_not_called()


def test_wazuh_service_initialization_invalid_config():
    """Test WazuhService initialization with invalid config."""
    # Use try/except instead of pytest.raises
    try:
        WazuhConfig(unix_socket_path="", json_alert_file="invalid")  # Invalid config
        pytest.fail("ValidationError not raised")  # Should not reach here
    except ValidationError:
        # Test passed as expected
        pass


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_connect(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService connect method."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()

    mock_socket.assert_called_once_with(AF, SOCK_DGRAM)
    mock_socket_instance.connect.assert_called_once_with(wazuh_config.unix_socket_path)
    assert service._socket is not None


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_connect_failure(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService connect method failure."""
    mock_socket_instance.connect.side_effect = OSError("Connection refused")
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    with pytest.raises(socket.error, match="Connection refused"):
        service.connect()

    mock_socket_instance.close.assert_called_once()
    assert service._socket is None


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_connect_wazuh_not_running(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService connect when Wazuh is not running."""
    error = OSError("Connection refused")
    error.errno = 111  # Connection refused errno
    mock_socket_instance.connect.side_effect = error
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    with pytest.raises(SystemExit) as exc_info:
        service.connect()

    assert exc_info.value.code == 6
    mock_socket_instance.close.assert_called_once()
    assert service._socket is None


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_send_event_with_optional_params(mock_socket, wazuh_config, sample_alert, mock_socket_instance):
    """Test WazuhService send_event with optional parameters."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()
    service.send_event(
        sample_alert,
        event_format="xml",
        event_id="12345",
        win_timestamp="2023-01-01T00:00:00",
        wz_timestamp="2023-01-01T00:00:00",
    )

    assert mock_socket_instance.send.call_count >= 1
    call_args = mock_socket_instance.send.call_args[0][0].decode()
    assert "xml" in call_args
    assert "12345" in call_args
    assert "2023-01-01T00:00:00" in call_args


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_send_event_no_agent_details(mock_socket, wazuh_config, mock_socket_instance, caplog):
    """Test WazuhService send_event method without agent details."""
    mock_socket.return_value = mock_socket_instance
    mock_socket_instance.send.side_effect = OSError("Connection lost")

    alert = {"id": "test-alert-2"}  # Alert without agent details
    service = WazuhService(wazuh_config)
    service.connect()

    with patch("time.sleep"), caplog.at_level(logging.ERROR):
        service.send_event(alert)  # Should log error about missing agent details

    # Verify error message contains alert ID and unknown agent ID
    assert any(
        "Alert ID: test-alert-2" in record.message and "Agent ID: None" in record.message for record in caplog.records
    )


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_send_event_with_retry(mock_socket, wazuh_config, sample_alert, mock_socket_instance):
    """Test WazuhService send_event method with retry."""
    mock_socket_instance.send.side_effect = [OSError("Connection lost"), None]
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()

    with patch("time.sleep"):  # Mock sleep to speed up tests
        service.send_event(sample_alert)

    assert mock_socket_instance.send.call_count >= 2


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_send_error(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService send_error method."""
    mock_socket.return_value = mock_socket_instance

    error_msg: WazuhErrorMessage = {"description": "test error"}
    service = WazuhService(wazuh_config)
    service.connect()
    service.send_error(error_msg)

    assert mock_socket_instance.send.call_count >= 1
    call_args = mock_socket_instance.send.call_args[0][0].decode()
    assert "dfn" in call_args
    assert "test error" in call_args


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_close(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService close method."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()
    service.close()

    mock_socket_instance.close.assert_called_once()
    assert service._socket is None


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_send_large_event(mock_socket, wazuh_config, caplog, mock_socket_instance):
    """Test sending an event larger than max_event_size."""
    mock_socket.return_value = mock_socket_instance

    # Create an alert with a large data field that will exceed max_event_size after formatting
    large_alert = {
        "id": "test-alert-3",
        "agent": {"id": "001", "name": "test-agent", "ip": "192.168.1.100"},
        "data": {"large_field": "x" * wazuh_config.max_event_size},  # This will make the event exceed max_size
    }

    service = WazuhService(wazuh_config)
    service.connect()

    # Mock json.dumps to return a predictably large string
    with patch("json.dumps") as mock_dumps, caplog.at_level(logging.DEBUG):
        mock_dumps.return_value = "x" * (wazuh_config.max_event_size + 1000)  # Ensure event exceeds max_size
        service.send_event(large_alert)
        # Check if the size warning was logged
        assert any("bytes exceeds the maximum allowed limit" in record.message for record in caplog.records)
        # Verify the event was still sent despite being large
        assert mock_socket_instance.send.called


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_reconnection_backoff(mock_socket, wazuh_config, mock_socket_instance):
    """Test exponential backoff during reconnection attempts."""
    mock_socket_instance.send.side_effect = OSError(107, "Transport endpoint is not connected")
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()

    with (
        patch("time.sleep"),
        pytest.raises(socket.error, match=r"Failed to send event after 3 attempts"),
    ):  # Convert nested with to single with
        service._send_event("test event")


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_max_retries_exceeded(mock_socket, wazuh_config, sample_alert, mock_socket_instance, caplog):
    """Test behavior when max retries are exceeded."""
    error = OSError("Connection lost")
    error.errno = 107  # Transport endpoint not connected
    mock_socket_instance.send.side_effect = error
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()

    with patch("time.sleep"), caplog.at_level(logging.ERROR):  # Mock sleep to speed up tests
        service.send_event(sample_alert)  # Should log error after max retries

    # Verify error logging and retry behavior
    assert mock_socket_instance.send.call_count >= 3  # Should try max_reconnect_attempts times
    assert mock_socket_instance.close.call_count >= 1
    assert any(
        "Failed to send event to Wazuh after" in record.message
        and "Alert ID: test-alert-1" in record.message
        and "Agent ID: 001" in record.message
        for record in caplog.records
    )


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_close_without_connect(mock_socket, wazuh_config, mock_socket_instance):
    """Test closing service without connecting first."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.close()  # Should not raise any errors

    mock_socket_instance.close.assert_not_called()
    assert service._socket is None


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_double_connect(mock_socket, wazuh_config, mock_socket_instance):
    """Test connecting twice to ensure proper socket cleanup."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()
    service.connect()  # Second connect should close first socket

    assert mock_socket_instance.close.call_count == 1
    assert mock_socket_instance.connect.call_count == 2
    assert service._socket is not None


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_send_without_connect(mock_socket, wazuh_config, sample_alert, mock_socket_instance):
    """Test sending event without connecting first."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.send_event(sample_alert)  # Should auto-connect

    assert mock_socket_instance.connect.call_count == 1
    assert mock_socket_instance.send.call_count >= 1


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_start_success(mock_socket, wazuh_config, mock_socket_instance):
    """Test successful WazuhService start."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.start()

    # Verify test message was sent
    assert mock_socket_instance.send.call_count == 1
    sent_data = mock_socket_instance.send.call_args[0][0].decode()
    assert "1:dfn:" in sent_data
    assert "Wazuh service started at" in sent_data


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_start_failure_cleanup(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService start failure with proper cleanup."""
    mock_socket.return_value = mock_socket_instance
    mock_socket_instance.send.side_effect = OSError("Send failed")

    service = WazuhService(wazuh_config)
    with pytest.raises(OSError, match="Send failed"):
        service.start()

    mock_socket_instance.close.assert_called_once()
    assert service._socket is None

    service = WazuhService(wazuh_config)
    with pytest.raises(OSError, match="Send failed"):
        service.start()

    # Verify socket was closed
    assert mock_socket_instance.close.call_count == 2
    assert service._socket is None


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_reconnection(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService reconnection logic."""
    mock_socket_instance.send.side_effect = [OSError("Connection lost"), None]
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()

    with patch("time.sleep"):  # Mock sleep to speed up tests
        service.send_event({"id": "test-id"})  # Should auto-connect

    assert mock_socket_instance.connect.call_count == 1
    assert mock_socket_instance.send.call_count >= 2


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_max_retries(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService respects max retries configuration."""
    mock_socket.return_value = mock_socket_instance
    error = OSError("Connection lost")
    error.errno = 107  # Transport endpoint not connected
    mock_socket_instance.send.side_effect = error

    service = WazuhService(wazuh_config)
    service.connect()

    with patch("time.sleep"):  # Mock sleep to speed up tests
        service.send_event({"id": "test-id"})

    # Verify retry attempts
    assert mock_socket_instance.send.call_count >= wazuh_config.max_retries


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_shutdown(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService proper shutdown."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()

    # Verify initial state
    assert service._socket is not None
    assert mock_socket_instance.connect.call_count == 1

    service.close()  # Close the service

    # Verify proper shutdown
    mock_socket_instance.close.assert_called_once()
    assert service._socket is None

    # Verify reconnection attempt on send after close
    service.send_event({"id": "test-id"})

    # Should have tried to create a new socket and connect again
    assert mock_socket.call_count == 2  # Initial socket + reconnect attempt
    assert mock_socket_instance.connect.call_count == 2  # Initial connect + reconnect


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_event_size_limit(mock_socket, wazuh_config, mock_socket_instance, caplog):
    """Test WazuhService handles event size limits correctly."""
    mock_socket.return_value = mock_socket_instance

    service = WazuhService(wazuh_config)
    service.connect()

    # Create an alert with a large data field that will exceed max_event_size after formatting
    large_alert = {
        "id": "test-alert-3",
        "agent": {"id": "001", "name": "test-agent", "ip": "192.168.1.100"},
        "data": {"large_field": "x" * wazuh_config.max_event_size},  # This will make the event exceed max_size
    }

    # Mock json.dumps to return a predictably large string
    with patch("json.dumps") as mock_dumps, caplog.at_level(logging.DEBUG):
        mock_dumps.return_value = "x" * (wazuh_config.max_event_size + 1000)  # Ensure event exceeds max_size
        service.send_event(large_alert)
        # Check if the size warning was logged
        assert any("bytes exceeds the maximum allowed limit" in record.message for record in caplog.records)
        # Verify the event was still sent despite being large
        assert mock_socket_instance.send.called


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_exponential_backoff(mock_socket, wazuh_config, mock_socket_instance):
    """Test exponential backoff in retry logic."""
    mock_socket.return_value = mock_socket_instance
    mock_socket_instance.send.side_effect = OSError(107, "Transport endpoint is not connected")

    service = WazuhService(wazuh_config)
    service.connect()

    with (
        patch("time.sleep"),
        pytest.raises(socket.error, match=r"Failed to send event after 3 attempts"),
    ):  # Convert nested with to single with
        service._send_event("test event")

    # Verify retry attempts
    assert mock_socket_instance.send.call_count >= wazuh_config.max_retries


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_connect_socket_close_error(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService handles socket close errors during reconnection."""
    mock_socket.return_value = mock_socket_instance
    mock_socket_instance.close.side_effect = OSError("Close failed")

    service = WazuhService(wazuh_config)
    service._socket = mock_socket_instance  # Set initial socket

    # Should handle close error gracefully
    with pytest.raises(socket.error, match="Close failed"):
        service.connect()


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_send_event_missing_agent_info(mock_socket, wazuh_config, mock_socket_instance):
    """Test WazuhService send_event with missing or partial agent info."""
    mock_socket.return_value = mock_socket_instance
    mock_socket_instance.send.return_value = len(b"test")  # Return some length

    service = WazuhService(wazuh_config)
    service.connect()

    # Test with missing agent info
    alert1 = {"id": "test-alert-1"}  # Minimal alert with just ID
    service.send_event(alert1)
    sent_data = mock_socket_instance.send.call_args[0][0].decode()
    assert "1:dfn:" in sent_data
    assert '"integration": "dfn"' in sent_data

    # Test with partial agent info
    alert2 = {"id": "test-alert-2", "agent": {"id": "002"}}  # Missing name and IP
    service.send_event(alert2)
    sent_data = mock_socket_instance.send.call_args[0][0].decode()
    assert "1:dfn:" in sent_data
    assert '"integration": "dfn"' in sent_data


@patch("wazuh_dfn.services.wazuh_service.socket", autospec=True)
def test_wazuh_service_concurrent_reconnection_during_outage(mock_socket, wazuh_config, mock_socket_instance):
    """Test multiple workers handling Wazuh service outage and recovery."""
    mock_socket.return_value = mock_socket_instance

    # Counter to control socket behavior
    attempt_counter = {"value": 0}

    def mock_send(data):
        """Mock socket send with varying behaviors based on attempt count."""
        attempt_counter["value"] += 1
        if attempt_counter["value"] <= 3:
            # Initial connection refused (Wazuh down)
            error = OSError("Connection refused")
            error.errno = 111
            raise error
        elif attempt_counter["value"] <= 8:
            # Transport endpoint not connected
            error = OSError("Transport endpoint is not connected")
            error.errno = 107
            raise error
        # After 8 attempts, succeed
        return len(data)

    mock_socket_instance.send.side_effect = mock_send

    service = WazuhService(wazuh_config)
    service.connect()

    # Simulate multiple workers sending events concurrently
    def worker_send_event():
        try:
            service.send_event({"id": f"test-{threading.get_ident()}"})
        except Exception as e:
            # We expect some workers to fail
            LOGGER.error(f"Worker failed: {e}")

    # Create and start multiple worker threads
    threads = []
    for _ in range(5):  # Simulate 5 concurrent workers
        thread = threading.Thread(target=worker_send_event)
        threads.append(thread)
        thread.start()

    # Mock time.sleep to speed up test
    with patch("time.sleep"):
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=2)

    # Verify behavior
    assert attempt_counter["value"] >= 8  # Ensure we went through all error stages
    assert mock_socket_instance.connect.call_count >= 3  # Multiple reconnection attempts
    assert service._socket is not None  # Service should be connected at the end
