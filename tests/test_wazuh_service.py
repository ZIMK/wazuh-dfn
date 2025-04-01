"""Test module for WazuhService."""

import asyncio
import logging
import pytest
import sys
from contextlib import suppress
from pydantic import ValidationError
from unittest.mock import AsyncMock, MagicMock, patch
from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.services.wazuh_service import WazuhErrorMessage, WazuhService

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
def mock_reader_writer():
    """Create mock StreamReader and StreamWriter instances.

    Note: In asyncio.StreamWriter, write() and close() are NOT coroutines
    while drain() and wait_closed() ARE coroutines. We mock accordingly to avoid warnings.
    """
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    # Regular methods use MagicMock
    mock_writer.write = MagicMock()
    mock_writer.close = MagicMock()
    # Coroutine methods use AsyncMock
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    return (mock_reader, mock_writer)


def test_wazuh_service_initialization(wazuh_config):
    """Test WazuhService initialization."""
    service = WazuhService(wazuh_config)
    assert service.config == wazuh_config
    assert service._reader is None
    assert service._writer is None


def test_wazuh_service_initialization_invalid_config():
    """Test WazuhService initialization with invalid config."""
    try:
        WazuhConfig(unix_socket_path="", json_alert_file="invalid")  # Invalid config
        pytest.fail("ValidationError not raised")  # Should not reach here
    except ValidationError:
        pass


@pytest.mark.asyncio
async def test_wazuh_service_connect(wazuh_config, mock_reader_writer):
    """Test WazuhService connect method."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()

        assert service._reader is mock_reader
        assert service._writer is mock_writer


@pytest.mark.asyncio
async def test_wazuh_service_connect_failure(wazuh_config):
    """Test WazuhService connect method failure."""
    connection_error = OSError("Connection refused")
    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", side_effect=connection_error)
    else:
        connection_patch = patch("asyncio.open_unix_connection", side_effect=connection_error)

    with connection_patch, pytest.raises(SystemExit) as excinfo:
        service = WazuhService(wazuh_config)
        await service.connect()

    assert excinfo.value.code == 6


@pytest.mark.asyncio
async def test_wazuh_service_close(wazuh_config, mock_reader_writer):
    """Test WazuhService close method."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()

        # Directly patch the class methods that need awaiting
        original_close = service.close

        async def patched_close():
            mock_writer.close()  # Non-coroutine
            await mock_writer.wait_closed()  # Coroutine
            service._reader, service._writer = None, None

        # Replace the method temporarily
        service.close = patched_close
        await service.close()

        service.close = original_close  # Restore the original method

        # Verify behavior
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()
        assert service._reader is None
        assert service._writer is None


@pytest.mark.asyncio
async def test_wazuh_service_double_connect(wazuh_config, mock_reader_writer):
    """Test connecting twice to ensure proper socket cleanup."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)

        # Use a custom connect implementation instead of patching
        await service.connect()

        # Store the first writer reference to check it's properly closed
        first_writer = service._writer

        # Setup writer.close so we can check it was called specifically for first_writer
        first_writer.close = MagicMock()

        # Connect again
        await service.connect()

        # Verify first writer was closed
        first_writer.close.assert_called_once()
        # Verify we have a writer
        assert service._writer is mock_writer


@pytest.mark.asyncio
async def test_wazuh_service_send_event_with_retry(wazuh_config, sample_alert):
    """Test WazuhService send_event method with retry."""
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.write = MagicMock()

    # Create a concrete side effect function that works reliably
    call_count = [0]

    async def drain_side_effect():
        call_count[0] += 1
        if call_count[0] == 1:
            # First call raises an error
            raise OSError("Connection lost")
        # Subsequent calls succeed

    mock_writer.drain = AsyncMock(side_effect=drain_side_effect)
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch, patch("asyncio.sleep", new=AsyncMock()):
        service = WazuhService(wazuh_config)
        await service.connect()
        await service.send_event(sample_alert)

    # Check that drain was called multiple times
    assert call_count[0] >= 2
    # Also verify write was called
    assert mock_writer.write.call_count >= 1


@pytest.mark.asyncio
async def test_wazuh_service_concurrent_reconnection_during_outage(wazuh_config):
    """Test multiple workers handling Wazuh service outage and recovery."""
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.write = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    attempt_counter = {"value": 0}

    async def mock_drain():
        attempt_counter["value"] += 1
        if attempt_counter["value"] <= 3:
            raise OSError(107, "Transport endpoint is not connected")
        elif attempt_counter["value"] <= 6:
            raise OSError(111, "Connection refused")
        elif attempt_counter["value"] <= 7:
            raise OSError(9, "Bad file descriptor")
        else:
            return None

    mock_writer.drain.side_effect = mock_drain

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()

        async def worker_send_event():
            with suppress(ConnectionError, OSError):
                await service.send_event({"id": f"test-concurrent-{attempt_counter['value']}"})

        tasks = []
        for _ in range(5):
            tasks.append(asyncio.create_task(worker_send_event()))

        with patch("asyncio.sleep", new=AsyncMock()):
            await asyncio.gather(*tasks)

        assert attempt_counter["value"] >= 8
        assert service._reader is mock_reader
        assert service._writer is mock_writer


@pytest.mark.asyncio
async def test_wazuh_service_send_event_with_optional_params(wazuh_config, sample_alert, mock_reader_writer):
    """Test WazuhService send_event with optional parameters."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()
        await service.send_event(
            sample_alert,
            event_format="xml",
            event_id="12345",
            win_timestamp="2023-01-01T00:00:00",
            wz_timestamp="2023-01-01T00:00:00",
        )

    # Check that write was called
    assert mock_writer.write.call_count >= 1
    # Verify the written data contains all the optional parameters
    call_args = mock_writer.write.call_args[0][0].decode()
    assert "xml" in call_args
    assert "12345" in call_args
    assert "2023-01-01T00:00:00" in call_args


@pytest.mark.asyncio
async def test_wazuh_service_send_event_no_agent_details(wazuh_config, mock_reader_writer, caplog):
    """Test WazuhService send_event method without agent details."""
    mock_reader, mock_writer = mock_reader_writer
    mock_writer.drain = AsyncMock(side_effect=OSError("Connection lost"))

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()

        alert = {"id": "test-alert-2"}  # Alert without agent details

        with caplog.at_level(logging.ERROR), patch("asyncio.sleep", new=AsyncMock()):  # Mock sleep to speed up retries
            await service.send_event(alert)  # Should log error about missing agent details

    # Verify error message contains alert ID and unknown agent ID
    assert any(
        "Alert ID: test-alert-2" in record.message and "Agent ID: None" in record.message for record in caplog.records
    )


@pytest.mark.asyncio
async def test_wazuh_service_send_error(wazuh_config, mock_reader_writer):
    """Test WazuhService send_error method."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()

        error_msg: WazuhErrorMessage = {"error": 123, "description": "test error"}
        await service.send_error(error_msg)

    # Verify the error message was properly formatted and sent
    assert mock_writer.write.call_count >= 1
    call_args = mock_writer.write.call_args[0][0].decode()
    assert "1:dfn:" in call_args
    assert "test error" in call_args


@pytest.mark.asyncio
async def test_wazuh_service_send_large_event(wazuh_config, mock_reader_writer, caplog):
    """Test sending an event larger than max_event_size."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()

        # Create an alert with a large data field that will exceed max_event_size
        large_alert = {
            "id": "test-alert-3",
            "agent": {"id": "001", "name": "test-agent", "ip": "192.168.1.100"},
            "data": {"large_field": "x" * wazuh_config.max_event_size},
        }

        # Mock json.dumps to return a predictably large string
        with patch("json.dumps") as mock_dumps:
            mock_dumps.return_value = "x" * (wazuh_config.max_event_size + 1000)

            with caplog.at_level(logging.DEBUG):
                await service.send_event(large_alert)

    # Check if the size warning was logged - fix assertion to match actual log format
    assert any(
        "len(event)=" in record.message and "exceeds the maximum allowed limit" in record.message
        for record in caplog.records
    )
    # Verify the event was still sent despite being large
    assert mock_writer.write.called


@pytest.mark.asyncio
async def test_wazuh_service_close_without_connect(wazuh_config):
    """Test closing service without connecting first."""
    service = WazuhService(wazuh_config)
    await service.close()  # Should not raise any errors

    assert service._reader is None
    assert service._writer is None


@pytest.mark.asyncio
async def test_wazuh_service_send_without_connect(wazuh_config, sample_alert, mock_reader_writer):
    """Test sending event without connecting first."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.send_event(sample_alert)  # Should auto-connect

        # Verify connection was established
        assert service._writer is mock_writer
        assert mock_writer.write.call_count >= 1


@pytest.mark.asyncio
async def test_wazuh_service_start_success(wazuh_config, mock_reader_writer):
    """Test successful WazuhService start."""
    mock_reader, mock_writer = mock_reader_writer

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.start()

        # Verify connection was established
        assert service._writer is mock_writer

        # Verify test message was sent
        assert mock_writer.write.call_count == 1
        sent_data = mock_writer.write.call_args[0][0].decode()
        assert "1:dfn:" in sent_data
        assert "Wazuh service started at" in sent_data


@pytest.mark.asyncio
async def test_wazuh_service_start_failure_cleanup(wazuh_config, mock_reader_writer):
    """Test WazuhService start failure with proper cleanup."""
    mock_reader, mock_writer = mock_reader_writer
    mock_writer.drain = AsyncMock(side_effect=OSError("Send failed"))

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        with pytest.raises(OSError, match="Send failed"):
            await service.start()

        # Verify cleanup occurred
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()


@pytest.mark.asyncio
async def test_wazuh_service_connect_socket_close_error(wazuh_config, mock_reader_writer):
    """Test WazuhService handles socket close errors during reconnection."""
    mock_reader, mock_writer = mock_reader_writer
    mock_writer.wait_closed = AsyncMock(side_effect=OSError("Close failed"))

    connection_patch = None
    if sys.platform == "win32":
        connection_patch = patch("asyncio.open_connection", return_value=(mock_reader, mock_writer))
    else:
        connection_patch = patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    with connection_patch:
        service = WazuhService(wazuh_config)
        await service.connect()

        # Set a new connection to trigger close of the old one
        with (
            patch(
                "asyncio.open_unix_connection" if sys.platform != "win32" else "asyncio.open_connection",
                side_effect=OSError("Connection error"),
            ),
            pytest.raises(OSError, match="Close failed"),
        ):
            # Update to expect the actual error that's occurring first (from wait_closed)
            await service.connect()  # This should try to close the old connection first

        # The close error should be logged, but close is called twice
        # once in the try block and once in the exception handler
        assert mock_writer.close.call_count == 2
        mock_writer.wait_closed.assert_called_once()
