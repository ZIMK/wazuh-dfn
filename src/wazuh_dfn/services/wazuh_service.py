"""Wazuh service module for handling Wazuh server operations."""

import json
import logging
import sys
import threading
import time
from enum import StrEnum
from socket import SOCK_DGRAM, socket
from socket import error as socket_error
from typing import Any, TypedDict
from wazuh_dfn.config import WazuhConfig
from wazuh_dfn.validators import WazuhConfigValidator

LOGGER = logging.getLogger(__name__)

# Use AF_UNIX for Unix systems, fallback to AF_INET for Windows
try:
    from socket import AF_UNIX as AF  # type: ignore[reportAttributeAccessIssue]
except ImportError:
    from socket import AF_INET as AF  # type: ignore[reportAttributeAccessIssue]


class RecoverableSocketError(StrEnum):
    """Socket error codes that can be recovered from."""

    EPIPE = "107"  # Broken pipe
    EPIPE_WIN = "32"  # Windows equivalent
    EBADF = "9"  # Bad file descriptor
    ECONNREFUSED = "111"  # Connection refused


class WazuhErrorMessage(TypedDict, total=False):
    """Type definition for a Wazuh error message."""

    integration: str
    error: int
    description: str


class WazuhEventMessage(TypedDict, total=False):
    """Type definition for a Wazuh event message."""

    integration: str
    alert_id: str
    agent_name: str
    dfn: dict[str, Any]
    description: str


class WazuhService:
    """Service for handling Wazuh server operations.

    This class manages the connection to a Wazuh server and handles sending events
    and alerts. It implements automatic reconnection and error handling for
    socket-based communication.

    Attributes:
        config (WazuhConfig): Configuration settings for Wazuh connection
        _socket (Optional[socket]): Socket connection to Wazuh server
    """

    def __init__(self, config: WazuhConfig) -> None:
        """Initialize WazuhService with configuration.

        Args:
            config: Wazuh-specific configuration settings

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        WazuhConfigValidator.validate(config)
        self.config = config
        self._socket: socket | None = None

        self._lock = threading.Lock()
        self._is_reconnecting = False

    def start(self) -> None:
        """Start the Wazuh service and verify connection.

        Establishes initial connection to the Wazuh server and verifies it
        by sending a test message. Includes connection status in startup message.

        Raises:
            socket_error: If connection fails or test message cannot be sent
            Exception: For other unexpected errors during startup
        """
        try:
            LOGGER.info("Starting Wazuh service...")
            self.connect()

            # Verify connection by sending a test message
            test_msg = {
                "integration": "dfn",
                "description": "Wazuh service started at {}".format(time.strftime("%Y-%m-%d %H:%M:%S")),
            }
            self._send_event(f"1:dfn:{json.dumps(test_msg)}")
            LOGGER.info("Successfully started Wazuh service and verified connection")
        except Exception as e:
            LOGGER.error(f"Failed to start Wazuh service: {e}")
            if self._socket:
                self.close()
            raise

    def connect(self) -> None:
        """Establish socket connection to Wazuh server.

        Creates and connects a new socket to the Wazuh server. Uses Unix domain socket
        on Unix systems and TCP socket on Windows.

        Raises:
            socket_error: If connection to socket fails
            Exception: For other connection-related errors
        """
        try:
            if self._socket:
                self._socket.close()

            self._socket = socket(AF, SOCK_DGRAM)

            if sys.platform == "win32":
                # For Windows, parse host:port from unix_socket_path
                if isinstance(self.config.unix_socket_path, tuple):
                    self._socket.connect(self.config.unix_socket_path)
                else:
                    host, port = self.config.unix_socket_path.split(":")
                    self._socket.connect((host, int(port)))
            else:
                # For Unix systems, use the socket path directly
                self._socket.connect(self.config.unix_socket_path)

            LOGGER.info("Connected to Wazuh server")
            self._is_reconnecting = False
        except Exception as e:
            LOGGER.error(f"Failed to connect to Wazuh server: {e}")
            if self._socket:
                self._socket.close()
                self._socket = None
            if isinstance(e, socket_error) and getattr(e, "errno", None) == 111:
                LOGGER.error("Wazuh is not running")
                sys.exit(6)
            raise

    def send_event(
        self,
        alert: dict[str, Any],
        event_format: str = "json",
        event_id: str | None = None,
        win_timestamp: str | None = None,
        wz_timestamp: str | None = None,
    ) -> None:
        """Send event to Wazuh server.

        Args:
            event: Event data to send
            event_format: Format of the event (default: json)
            event_id: Event ID for Windows events
            win_timestamp: Windows event timestamp
            wz_timestamp: Wazuh event timestamp
        """
        retry_count = 0
        alert_id = alert.get("id")
        agent_id = alert.get("agent", {}).get("id", None)
        agent_name = alert.get("agent", {}).get("name", None)
        agent_ip = alert.get("agent", {}).get("ip", "any")

        while retry_count < self.config.max_retries:
            try:
                if not self._socket:
                    self.connect()

                msg: WazuhEventMessage = {
                    "integration": "dfn",
                    "alert_id": alert_id,
                    "agent_name": agent_name,
                    "dfn": {
                        "event_format": event_format,
                        "event_id": event_id,
                        "win_timestamp": win_timestamp,
                        "wz_timestamp": wz_timestamp,
                    },
                }

                self._send(msg=msg, agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip)
                break  # If successful, exit the retry loop
            except Exception as e:
                retry_count += 1
                if retry_count < self.config.max_retries:
                    wait_time = min(self.config.retry_interval * (2**retry_count), 30)
                    LOGGER.warning(
                        f"Failed to send event to Wazuh (attempt {retry_count}/{self.config.max_retries}). "
                        f"Alert ID: {alert_id}, Agent ID: {agent_id}. "
                        f"Retrying in {wait_time} seconds... Error: {e}"
                    )
                    time.sleep(wait_time)
                else:
                    LOGGER.error(
                        f"Failed to send event to Wazuh after {self.config.max_retries} attempts. "
                        f"Alert ID: {alert_id}, Agent ID: {agent_id}. Error: {e}"
                    )

    def _try_reconnect(self) -> None:
        """Attempt to reestablish connection to Wazuh server."""
        with self._lock:
            if self._is_reconnecting:
                # If another thread is already reconnecting, just wait and return
                return

            self._is_reconnecting = True
            try:
                if self._socket:
                    try:
                        self._socket.close()
                    except Exception as e:
                        LOGGER.warning(f"Error closing socket during reconnect: {e}")
                    finally:
                        self._socket = None

                # Add small delay to prevent reconnect storm
                time.sleep(0.1)
                self.connect()
            except Exception as e:
                LOGGER.error(f"Failed to reconnect to Wazuh socket: {e}")
                raise
            finally:
                self._is_reconnecting = False

    def _send(
        self,
        msg: WazuhEventMessage,
        agent_id: str | None = None,
        agent_name: str | None = None,
        agent_ip: str | None = None,
    ) -> None:
        """Format and send a message to the Wazuh server.

        Formats the message according to Wazuh's expected format, including
        optional agent information, and sends it through the socket connection.

        Args:
            msg: Message content to send
            agent_id: Optional ID of the agent sending the message
            agent_name: Optional name of the agent sending the message
            agent_ip: Optional IP address of the agent sending the message

        Raises:
            socket_error: If sending message fails
        """
        if not agent_id or not agent_name:
            event = f"1:dfn:{json.dumps(msg)}"
        else:
            location = f"[{agent_id}] ({agent_name}) {agent_ip}"
            location = location.replace("|", "||").replace(":", "|:")
            event = f"1:{location}->dfn:{json.dumps(msg)}"
        self._send_event(event)

    def send_error(self, msg: WazuhErrorMessage) -> None:
        """Send an error message to the Wazuh server.

        Ensures the message is properly formatted as a DFN integration error
        message before sending.

        Args:
            msg: Error message content to send. Will be augmented with
                integration identifier if not present.

        Raises:
            socket_error: If sending error message fails
        """
        if "integration" not in msg:
            msg["integration"] = "dfn"

        self._send_event(f"1:dfn:{json.dumps(msg)}")

    def _handle_socket_error(self, e: socket_error, attempt: int, max_attempts: int) -> bool:
        """Handle socket errors during event sending.

        Returns:
            bool: True if should continue retrying, False if should raise error
        """
        error_code = getattr(e, "errno", None)
        LOGGER.warning(f"Socket error (attempt {attempt + 1}/{max_attempts}): {e} (errno: {error_code})")

        # Check if error code is in recoverable errors
        if str(error_code) not in RecoverableSocketError.__members__.values():
            LOGGER.error(f"Unrecoverable socket error: {e}")
            raise e

        if attempt >= max_attempts:
            if str(error_code) == RecoverableSocketError.ECONNREFUSED:
                LOGGER.error("Wazuh is not running after maximum retries")
                sys.exit(6)
            return False

        wait_time = min(self.config.retry_interval * (2**attempt), 30)
        LOGGER.info(f"Waiting {wait_time} seconds before retry...")
        time.sleep(wait_time)

        try:
            self._try_reconnect()
        except Exception as reconnect_error:
            LOGGER.error(f"Reconnection attempt {attempt} failed: {reconnect_error}")

        return True

    def _ensure_connection(self) -> bool:
        """Ensure socket connection is available.

        Returns:
            bool: True if connection is ready, False if should retry
        """
        if not self._socket:
            self._try_reconnect()
            if not self._socket:
                time.sleep(1)
                return False
        return True

    def _send_event(self, event: str) -> None:
        """Send an event through the Wazuh socket connection."""
        if len(event) > self.config.max_event_size:
            LOGGER.debug(f"{len(event)=} bytes exceeds the maximum allowed limit of {self.config.max_event_size} bytes")

        LOGGER.debug(event[:1000])
        attempt = 0
        max_attempts = self.config.max_retries

        while attempt < max_attempts:
            if not self._ensure_connection():
                continue

            try:
                self._socket.send(event.encode())
                return
            except OSError as e:
                if not self._handle_socket_error(e, attempt, max_attempts):
                    break
                attempt += 1

        raise OSError(f"Failed to send event after {max_attempts} attempts")

    def close(self) -> None:
        """Close the connection to Wazuh server.

        Ensures the socket connection is properly closed and resources
        are released. Safe to call multiple times.
        """
        if self._socket:
            try:
                self._socket.close()
                LOGGER.info("Closed connection to Wazuh server")
            except Exception as e:
                LOGGER.error(f"Error closing Wazuh server connection: {e}")
            finally:
                self._socket = None
