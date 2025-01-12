"""Wazuh service module for handling Wazuh server operations."""

import json
import logging
import sys
import threading
import time
from socket import SOCK_DGRAM
from socket import error as socket_error
from socket import socket
from typing import Any, Dict, Optional

from ..config import WazuhConfig
from ..validators import WazuhConfigValidator

LOGGER = logging.getLogger(__name__)

# Use AF_UNIX for Unix systems, fallback to AF_INET for Windows
try:
    from socket import AF_UNIX as AF
except ImportError:
    from socket import AF_INET as AF


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
        self._socket: Optional[socket] = None

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
        alert: Dict[str, Any],
        event_format: str = "json",
        event_id: Optional[str] = None,
        win_timestamp: Optional[str] = None,
        wz_timestamp: Optional[str] = None,
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
        alert_id = alert.get("id", None)
        agent_id = alert.get("agent", {}).get("id", None)
        agent_name = alert.get("agent", {}).get("name", None)
        agent_ip = alert.get("agent", {}).get("ip", "any")

        while retry_count < self.config.max_retries:
            try:
                if not self._socket:
                    self.connect()

                msg = {
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
        """Attempt to reestablish connection to Wazuh server.

        Closes any existing socket connection and attempts to create
        a new connection. This is used during error recovery when
        the original connection is lost.

        Raises:
            socket_error: If reconnection to socket fails
            Exception: For other connection-related errors
        """
        with self._lock:  # Ensure only one thread can execute this at a time
            if not self._is_reconnecting:  # Check if a reconnect attempt is already in progress
                self._is_reconnecting = True  # Set the flag
                try:
                    if self._socket:
                        try:
                            self._socket.close()
                        except socket_error as e:
                            LOGGER.warning(f"Error closing socket: {e}")
                        except Exception as e:
                            LOGGER.warning(f"Unexpected error while closing socket: {e}")
                        self._socket = None
                    self.connect()
                except Exception as e:
                    LOGGER.error(f"Failed to reconnect to Wazuh socket: {e}")
                    raise
                finally:
                    self._is_reconnecting = False  # Reset the flag after the attempt

    def _send(
        self,
        msg: dict,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        agent_ip: Optional[str] = None,
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
            location = "[{0}] ({1}) {2}".format(
                agent_id,
                agent_name,
                agent_ip,
            )
            location = location.replace("|", "||").replace(":", "|:")
            event = f"1:{location}->dfn:{json.dumps(msg)}"
        self._send_event(event)

    def send_error(self, msg: dict) -> None:
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

    def _send_event(self, event: str) -> None:
        """Send an event through the Wazuh socket connection.

        Handles the low-level socket communication including automatic
        reconnection attempts on failure. Uses exponential backoff
        between retry attempts.

        Automatic reconnection is attempted for the following socket errors:
        - errno 107: Transport endpoint not connected
        - errno 32: Broken pipe
        - errno 9: Bad file descriptor
        - errno 111: Connection refused (Wazuh not running)

        Args:
            event: Formatted event string to send

        Raises:
            socket_error: If sending fails after all retry attempts
                or on unrecoverable socket errors
            SystemExit: If Wazuh is not running (errno 111) after max attempts
        """
        if len(event) > self.config.max_event_size:
            LOGGER.debug(f"Message size exceeds the maximum allowed limit of {self.config.max_event_size} bytes.")

        LOGGER.debug(event)
        max_attempts = self.config.max_retries

        for attempt in range(max_attempts):
            try:
                if not self._socket:
                    with self._lock:
                        if not self._is_reconnecting:
                            self._is_reconnecting = True
                            self.connect()  # Only the first worker will call connect
                        else:
                            while self._is_reconnecting:  # Wait for the reconnect to finish
                                time.sleep(1)
                self._socket.send(event.encode())
                return
            except socket_error as e:
                error_code = getattr(e, "errno", None)
                if attempt < max_attempts - 1 and error_code in (107, 32, 9, 111):
                    LOGGER.warning(f"Socket disconnected (attempt {attempt + 1}/{max_attempts}): {e}")
                    wait_time = min(self.config.retry_interval * (2**attempt), 30)
                    time.sleep(wait_time)

                    self._try_reconnect()
                else:
                    if error_code == 111:
                        LOGGER.error(f"Failed to send event after {max_attempts} attempts: Wazuh is not running")
                        sys.exit(6)
                    LOGGER.error(f"Failed to send event: {e}")
                    raise

        raise socket_error("Failed to send event after maximum retries")

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
