"""Wazuh service module for handling Wazuh server operations."""

import asyncio
import json
import logging
import sys
import time
from enum import StrEnum
from typing import Any, TypedDict

from wazuh_dfn.config import WazuhConfig

LOGGER = logging.getLogger(__name__)


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

        self._lock = asyncio.Lock()
        self._is_reconnecting = False

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
                "integration": "dfn",
                "description": "Wazuh service started at {}".format(time.strftime("%Y-%m-%d %H:%M:%S")),
            }
            await self._send_event(f"1:dfn:{json.dumps(test_msg)}")
            LOGGER.info("Successfully started Wazuh service and verified connection")
        except Exception as e:
            LOGGER.error(f"Failed to start Wazuh service: {e}")
            if self._writer:
                await self.close()
            raise

    async def connect(self) -> None:
        """Establish socket connection to Wazuh server asynchronously.

        Creates and connects a new socket to the Wazuh server using asyncio streams.
        Uses Unix domain socket on Unix systems and TCP socket on Windows.

        Raises:
            ConnectionError: If connection to socket fails
            Exception: For other connection-related errors
        """
        try:
            if self._writer:
                self._writer.close()
                await self._writer.wait_closed()

            if sys.platform == "win32":
                # For Windows, parse host:port from unix_socket_path
                if isinstance(self.config.unix_socket_path, tuple):
                    host, port = self.config.unix_socket_path
                else:
                    host, port_str = self.config.unix_socket_path.split(":")
                    port = int(port_str)

                self._reader, self._writer = await asyncio.open_connection(host, port)
            else:
                # For Unix systems
                self._reader, self._writer = await asyncio.open_unix_connection(self.config.unix_socket_path)

            LOGGER.info("Connected to Wazuh server")
            self._is_reconnecting = False
        except Exception as e:
            LOGGER.error(f"Failed to connect to Wazuh server: {e}")
            if self._writer:
                self._writer.close()
                self._reader, self._writer = None, None
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
                if not self._writer:
                    await self.connect()

                msg: WazuhEventMessage = {
                    "integration": "dfn",
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
            if self._is_reconnecting:
                # If another task is already reconnecting, just wait and return
                return

            self._is_reconnecting = True
            try:
                if self._writer:
                    try:
                        self._writer.close()
                        await self._writer.wait_closed()
                    except Exception as e:
                        LOGGER.warning(f"Error closing socket during reconnect: {e}")
                    finally:
                        self._reader, self._writer = None, None

                # Add small delay to prevent reconnect storm
                await asyncio.sleep(0.1)
                await self.connect()
            except Exception as e:
                LOGGER.error(f"Failed to reconnect to Wazuh socket: {e}")
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
            event = f"1:dfn:{json.dumps(msg)}"
        else:
            location = f"[{agent_id}] ({agent_name}) {agent_ip}"
            location = location.replace("|", "||").replace(":", "|:")
            event = f"1:{location}->dfn:{json.dumps(msg)}"
        await self._send_event(event)

    async def send_error(self, msg: WazuhErrorMessage) -> None:
        """Send an error message to the Wazuh server asynchronously.

        Args:
            msg: Error message content to send.

        Raises:
            ConnectionError: If sending error message fails
        """
        if "integration" not in msg:
            msg["integration"] = "dfn"

        await self._send_event(f"1:dfn:{json.dumps(msg)}")

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
        if not self._writer:
            await self._try_reconnect()
            if not self._writer:
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
                self._writer.write(event.encode())
                await self._writer.drain()
                return
            except Exception as e:
                if not await self._handle_socket_error(e, attempt, max_attempts):
                    break
                attempt += 1

        raise ConnectionError(f"Failed to send event after {max_attempts} attempts")

    async def close(self) -> None:
        """Close the connection to Wazuh server asynchronously.

        Ensures the socket connection is properly closed and resources
        are released. Safe to call multiple times.
        """
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
                LOGGER.info("Closed connection to Wazuh server")
            except Exception as e:
                LOGGER.error(f"Error closing Wazuh server connection: {e}")
            finally:
                self._reader, self._writer = None, None
