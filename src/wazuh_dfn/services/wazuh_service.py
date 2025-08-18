"""Wazuh service module for handling Wazuh server operations."""

import asyncio
import json
import logging
import socket
import sys
import time
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, TypedDict

from wazuh_dfn.config import WazuhConfig

LOGGER = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection state management for atomic state tracking."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


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
        _reader: StreamReader for async socket operations
        _writer: StreamWriter for async socket operations
    """

    def __init__(self, config: WazuhConfig) -> None:
        """Initialize WazuhService with configuration.

        Args:
            config: Configuration settings for Wazuh connection

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        # Validation is handled by Pydantic automatically
        self.config = config
        self._reader = None
        self._writer = None
        self._dgram_sock = None
        self._is_dgram = False

        # Connection state management (Fix #1: Atomic connection state)
        self._connection_state = ConnectionState.DISCONNECTED
        self._state_lock = asyncio.Lock()

        self._lock = asyncio.Lock()
        self._is_reconnecting = False

    @property
    def is_connected(self) -> bool:
        """Check if currently connected to Wazuh server.

        Returns:
            bool: True if connected, False otherwise
        """
        return self._connection_state == ConnectionState.CONNECTED

    async def start(self) -> None:
        """Start the Wazuh service and verify connection asynchronously.

        Establishes initial connection to the Wazuh server and verifies it
        by sending a test message. Includes connection status in startup message.

        Raises:
            Exception: For unexpected errors during startup
        """
        try:
            LOGGER.info("Starting Wazuh service...")
            await self.connect()

            # Verify connection by sending a test message
            test_msg = {
                "integration": f"{self.config.integration_name}",
                "description": "Wazuh service started at {}".format(time.strftime("%Y-%m-%d %H:%M:%S")),
            }
            await self._send_event(f"1:{self.config.integration_name}:{json.dumps(test_msg)}")
            LOGGER.info("Successfully started Wazuh service and verified connection")
        except Exception as e:
            LOGGER.error(f"Failed to start Wazuh service: {e}")
            raise

    async def connect(self) -> None:
        """Establish socket connection to Wazuh server asynchronously.

        Creates and connects a new socket to the Wazuh server using asyncio streams.
        Uses Unix domain socket on Unix systems and TCP socket on Windows.

        Raises:
            ConnectionError: If connection to socket fails
            Exception: For other connection-related errors
        """
        async with self._state_lock:
            try:
                # Set connecting state
                self._connection_state = ConnectionState.CONNECTING
                
                # Close any existing connection without additional locking
                await self._close_internal()

                if sys.platform == "win32":
                    # For Windows, parse host:port from unix_socket_path
                    if isinstance(self.config.unix_socket_path, tuple):
                        host, port = self.config.unix_socket_path
                    else:
                        host, port_str = self.config.unix_socket_path.split(":")
                        port = int(port_str)

                    LOGGER.info(f"Connecting to Wazuh server via TCP socket - host: {host}, port: {port}")
                    self._reader, self._writer = await asyncio.open_connection(host, port)
                    self._is_dgram = False
                else:
                    # For Unix systems
                    socket_path = Path(self.config.unix_socket_path)
                    LOGGER.info(f"Connecting to Wazuh server via Unix socket - path: {socket_path}")

                    # Check if socket file exists
                    if not socket_path.exists():
                        LOGGER.error(f"Unix socket path does not exist: {socket_path}")
                        raise FileNotFoundError(f"Unix socket path not found: {socket_path}")

                    # Log socket file permissions and details
                    try:
                        socket_stat = socket_path.stat()
                        LOGGER.debug(
                            f"Socket file details - mode: {oct(socket_stat.st_mode)}, "
                            f"size: {socket_stat.st_size}"
                        )
                    except Exception as stat_error:
                        LOGGER.warning(f"Could not get socket file details: {stat_error}")

                    # Try datagram socket first (as it was before switching to asyncio)
                    try:
                        LOGGER.debug("Attempting to connect with datagram socket...")
                        self._is_dgram = True
                        # Create a Unix domain datagram socket
                        self._dgram_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                        self._dgram_sock.setblocking(False)
                        self._dgram_sock.connect(str(socket_path))
                        LOGGER.info("Connected to Wazuh server using datagram socket")
                    except OSError as dgram_error:
                        LOGGER.debug(f"Datagram socket failed: {dgram_error}, trying with stream socket...")
                        self._is_dgram = False
                        if self._dgram_sock:
                            self._dgram_sock.close()
                            self._dgram_sock = None

                        # Fall back to stream socket
                        try:
                            self._reader, self._writer = await asyncio.open_unix_connection(str(socket_path))
                            LOGGER.info("Connected to Wazuh server using stream socket")
                        except Exception as stream_error:
                            LOGGER.error(f"Failed to connect with stream socket: {stream_error}")
                            raise

                # Set connected state atomically
                self._connection_state = ConnectionState.CONNECTED
                LOGGER.info("Connected to Wazuh server")
                self._is_reconnecting = False
            except Exception as e:
                # Set error state atomically
                self._connection_state = ConnectionState.ERROR
                LOGGER.error(f"Failed to connect to Wazuh server: {e}")
                await self._close_internal()
                if "Connection refused" in str(e):
                    LOGGER.error("Wazuh is not running")
                    sys.exit(6)
                raise

    async def send_event(
        self,
        alert: dict[str, Any],
        event_format: str = "json",
        event_id: str | None = None,
        win_timestamp: str | None = None,
        wz_timestamp: str | None = None,
    ) -> None:
        """Send event to Wazuh server asynchronously.

        Args:
            alert: Event data to send
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
                # Use the new atomic connection state check
                if not self.is_connected:
                    await self.connect()

                msg: WazuhEventMessage = {
                    "integration": self.config.integration_name,
                    "alert_id": str(alert_id),
                    "agent_name": str(agent_name),
                    "dfn": {
                        "event_format": event_format,
                        "event_id": event_id,
                        "win_timestamp": win_timestamp,
                        "wz_timestamp": wz_timestamp,
                    },
                }

                await self._send(msg=msg, agent_id=agent_id, agent_name=agent_name, agent_ip=agent_ip)
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
                    await asyncio.sleep(wait_time)
                else:
                    LOGGER.error(
                        f"Failed to send event to Wazuh after {self.config.max_retries} attempts. "
                        f"Alert ID: {alert_id}, Agent ID: {agent_id}. Error: {e}"
                    )

    async def _try_reconnect(self) -> None:
        """Attempt to reestablish connection to Wazuh server asynchronously."""
        async with self._lock:
            # Check if we're in a valid state to reconnect
            if self._connection_state == ConnectionState.CONNECTING:
                # Another task is already connecting, just wait
                while self._connection_state == ConnectionState.CONNECTING:
                    await asyncio.sleep(0.1)
                return

            if self._is_reconnecting:
                # If another task is already reconnecting, just wait and return
                return

            # Validate current state before attempting reconnection
            if self._connection_state not in [ConnectionState.DISCONNECTED, ConnectionState.ERROR]:
                LOGGER.warning(f"Unexpected state during reconnect attempt: {self._connection_state}")

            self._is_reconnecting = True
            try:
                # Use internal close to avoid lock conflicts
                async with self._state_lock:
                    await self._close_internal()

                # Add small delay to prevent reconnect storm
                await asyncio.sleep(0.1)
                await self.connect()
            except Exception as e:
                LOGGER.error(f"Failed to reconnect to Wazuh socket: {e}")
                # Ensure we're in error state if connection failed
                async with self._state_lock:
                    self._connection_state = ConnectionState.ERROR
                raise
            finally:
                self._is_reconnecting = False

    async def _send(
        self,
        msg: WazuhEventMessage,
        agent_id: str | None = None,
        agent_name: str | None = None,
        agent_ip: str | None = None,
    ) -> None:
        """Format and send a message to the Wazuh server asynchronously.

        Args:
            msg: Message content to send
            agent_id: Optional ID of the agent sending the message
            agent_name: Optional name of the agent sending the message
            agent_ip: Optional IP address of the agent sending the message

        Raises:
            ConnectionError: If sending message fails
        """
        if not agent_id or not agent_name:
            event = f"1:{self.config.integration_name}:{json.dumps(msg)}"
        else:
            location = f"[{agent_id}] ({agent_name}) {agent_ip}"
            location = location.replace("|", "||").replace(":", "|:")
            event = f"1:{location}->{self.config.integration_name}:{json.dumps(msg)}"
        await self._send_event(event)

    async def send_error(self, msg: WazuhErrorMessage) -> None:
        """Send an error message to the Wazuh server asynchronously.

        Args:
            msg: Error message content to send.

        Raises:
            ConnectionError: If sending error message fails
        """
        if "integration" not in msg:
            msg["integration"] = self.config.integration_name
        await self._send_event(f"1:{self.config.integration_name}:{json.dumps(msg)}")

    async def _handle_socket_error(self, e: Exception, attempt: int, max_attempts: int) -> bool:
        """Handle socket errors during event sending asynchronously.

        Returns:
            bool: True if should continue retrying, False if should raise error
        """
        error_code = getattr(e, "errno", None)
        LOGGER.warning(f"Socket error (attempt {attempt + 1}/{max_attempts}): {e} (errno: {error_code})")

        # Check if error code is in recoverable errors
        if str(error_code) not in RecoverableSocketError.__members__.values():
            LOGGER.error(f"Unrecoverable socket error: {e}")
            # Set connection state to ERROR for unrecoverable errors
            async with self._state_lock:
                self._connection_state = ConnectionState.ERROR
            raise e

        if attempt >= max_attempts:
            if "Connection refused" in str(e) or str(error_code) == RecoverableSocketError.ECONNREFUSED:
                LOGGER.error("Wazuh is not running after maximum retries")
                sys.exit(6)
            return False

        wait_time = min(self.config.retry_interval * (2**attempt), 30)
        LOGGER.info(f"Waiting {wait_time} seconds before retry...")
        await asyncio.sleep(wait_time)

        try:
            await self._try_reconnect()
        except Exception as reconnect_error:
            LOGGER.error(f"Reconnection attempt {attempt} failed: {reconnect_error}")
        return True

    async def _ensure_connection(self) -> bool:
        """Ensure socket connection is available asynchronously.

        Returns:
            bool: True if connection is ready, False if should retry
        """
        # Use the new atomic connection state check
        if not self.is_connected:
            await self._try_reconnect()
            if not self.is_connected:
                await asyncio.sleep(1)
                return False
        return True

    async def _send_event(self, event: str) -> None:
        """Send an event through the Wazuh socket connection asynchronously."""
        if len(event) > self.config.max_event_size:
            LOGGER.debug(f"{len(event)=} bytes exceeds the maximum allowed limit of {self.config.max_event_size} bytes")

        LOGGER.debug(event[:1000])
        attempt = 0
        max_attempts = self.config.max_retries

        while attempt < max_attempts:
            if not await self._ensure_connection():
                continue

            try:
                if not self._is_dgram:
                    # For stream sockets
                    self._writer.write(event.encode())
                    await self._writer.drain()
                elif self._dgram_sock:
                    # For datagram sockets, use the event loop to send asynchronously
                    loop = asyncio.get_event_loop()
                    await loop.sock_sendall(self._dgram_sock, event.encode())
                return
            except Exception as e:
                if not await self._handle_socket_error(e, attempt, max_attempts):
                    break
                attempt += 1

        raise ConnectionError(f"Failed to send event after {max_attempts} attempts")

    async def _close_internal(self) -> None:
        """Internal close method without state locking."""
        try:
            # Only log if we actually have connections to close
            closing_connections = []
            if not self._is_dgram and self._writer:
                closing_connections.append("stream")
            if self._is_dgram and self._dgram_sock:
                closing_connections.append("datagram")
            
            if closing_connections:
                LOGGER.debug(f"Closing {', '.join(closing_connections)} connection(s) to Wazuh server")
            
            # Close stream connection
            if not self._is_dgram and self._writer:
                try:
                    self._writer.close()
                    await self._writer.wait_closed()
                    LOGGER.debug("Closed stream connection to Wazuh server")
                except Exception as e:
                    LOGGER.error(f"Error closing Wazuh stream connection: {e}")
                finally:
                    self._reader, self._writer = None, None

            # Close datagram connection
            if self._is_dgram and self._dgram_sock:
                try:
                    self._dgram_sock.close()
                    LOGGER.debug("Closed datagram connection to Wazuh server")
                except Exception as e:
                    LOGGER.error(f"Error closing Wazuh datagram connection: {e}")
                finally:
                    self._dgram_sock = None

            # Reset connection state
            self._is_dgram = False
            self._connection_state = ConnectionState.DISCONNECTED
            
            if closing_connections:
                LOGGER.debug("Connection to Wazuh server closed")
                
        except Exception as e:
            LOGGER.error(f"Error closing connection to Wazuh server: {e}")
            # Ensure state is reset even if there are errors
            self._reader = None
            self._writer = None
            self._dgram_sock = None
            self._is_dgram = False
            self._connection_state = ConnectionState.ERROR

    async def close(self) -> None:
        """Close the connection to Wazuh server asynchronously.

        Ensures the socket connection is properly closed and resources
        are released. Safe to call multiple times.
        """
        async with self._state_lock:
            await self._close_internal()
