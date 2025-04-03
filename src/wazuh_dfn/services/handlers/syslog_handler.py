"""Syslog alert handler module."""

import asyncio
import ipaddress
import logging
from typing import Any

from wazuh_dfn.config import MiscConfig
from wazuh_dfn.services.kafka_service import KafkaMessage, KafkaService
from wazuh_dfn.services.wazuh_service import WazuhService

LOGGER = logging.getLogger(__name__)


class SyslogHandler:
    """Handler for syslog alerts.

    This class processes syslog-specific alerts and formats them
    according to RFC 5424.
    """

    def __init__(
        self,
        config: MiscConfig,
        kafka_service: KafkaService,
        wazuh_service: WazuhService,
    ) -> None:
        """Initialize SyslogHandler.

        Args:
            config: Miscellaneous configuration
            kafka_service: Service for Kafka operations
            wazuh_service: Service for Wazuh operations
        """
        self.config = config
        self.kafka_service = kafka_service
        self.wazuh_service = wazuh_service
        self.own_network = None
        if self.config.own_network:
            try:
                self.own_network = ipaddress.ip_network(self.config.own_network)
            except ValueError as e:
                LOGGER.error(f"Invalid own_network CIDR: {e}")

    async def process_alert(self, alert: dict[str, Any]) -> None:
        """Process a syslog alert.

        Args:
            alert: Alert data to process
        """
        try:
            if self._is_relevant_fail2ban_alert(alert):
                await self._process_fail2ban_alert(alert)
            else:
                LOGGER.debug("No fail2ban alert to process")
        except Exception as error:
            alert_id = alert.get("id", "Unknown")
            LOGGER.error(f"Error processing Syslog alert: {alert_id}: {error!s}", exc_info=True)

    def _is_relevant_fail2ban_alert(self, alert: dict[str, Any]) -> bool:
        """Check if the alert is a relevant fail2ban alert to process.

        Args:
            alert: Alert data to check

        Returns:
            bool: True if the alert is a relevant fail2ban alert
        """
        return (
            "data" in alert
            and "srcip" in alert["data"]
            and "program_name" in alert["data"]
            and alert["data"]["program_name"] == "fail2ban.actions"
            and "rule" in alert
            and "groups" in alert["rule"]
            and "fail2ban" in alert["rule"]["groups"]
        )

    async def _process_fail2ban_alert(self, alert: dict[str, Any]) -> None:
        """Process fail2ban-specific alert data.

        Args:
            alert: Alert data to process
        """
        LOGGER.debug("Processing fail2ban alert...")
        LOGGER.debug("Executing _process_fail2ban_alert method")

        # Extract source IP
        source_ip = alert["data"]["srcip"]
        if not source_ip:
            LOGGER.error("No source IP in fail2ban alert")
            return

        # Check if IP is internal (only if own_network is configured)
        if self.own_network and not self._is_global_ip(source_ip):
            LOGGER.info(f"Ignoring internal IP: {source_ip}")
            return

        # Create message data for Kafka
        message_data = self._create_message_data(alert)

        # Use asyncio to send to Kafka
        alert_id = alert.get("id", "Unknown")

        # Wait for _send_message to complete instead of fire-and-forget
        await self._send_message(message_data, alert_id)

    async def _send_message(self, message_data: KafkaMessage, alert_id: str) -> None:
        """Send message to Kafka asynchronously.

        Sends a fail2ban alert to Kafka and logs the result.

        Args:
            message_data: The formatted message to send to Kafka
            alert_id: The alert ID for logging and tracking
        """
        # Send to Kafka
        result = await self.kafka_service.send_message(message_data)
        if result:
            LOGGER.debug(f"Fail2ban alert sent successfully: {result}")
            # Extract the original alert from the message_data context
            alert = message_data.get("context_alert", {})

            # Send to Wazuh with the original format as fire-and-forget
            asyncio.create_task(  # noqa: RUF006
                self._send_to_wazuh(
                    alert=alert, event_format="syslog5424-json", wz_timestamp=alert.get("timestamp"), alert_id=alert_id
                )
            )
        else:
            error_msg = f"Failed to send fail2ban alert to Kafka {alert_id}"
            LOGGER.error(error_msg)
            # Send error to Wazuh as fire-and-forget
            asyncio.create_task(self._send_error_to_wazuh(error_msg=error_msg, alert_id=alert_id))  # noqa: RUF006

    async def _send_to_wazuh(
        self, alert: dict[str, Any], event_format: str, wz_timestamp: str | None, alert_id: str
    ) -> None:
        """Send event to Wazuh service with error handling.

        Args:
            alert: Alert data to send
            event_format: Format of the event
            wz_timestamp: Wazuh event timestamp
            alert_id: Alert ID for error tracking
        """
        try:
            await self.wazuh_service.send_event(
                alert=alert,
                event_format=event_format,
                wz_timestamp=wz_timestamp,
            )
        except Exception as e:
            LOGGER.error(f"Failed to send event to Wazuh for alert {alert_id}: {e}")

    async def _send_error_to_wazuh(self, error_msg: str, alert_id: str) -> None:
        """Send error to Wazuh service with error handling.

        Args:
            error_msg: Error message to send
            alert_id: Alert ID for error tracking
        """
        try:
            await self.wazuh_service.send_error(
                {
                    "error": 503,
                    "description": error_msg,
                }
            )
        except Exception as e:
            LOGGER.error(f"Failed to send error to Wazuh for alert {alert_id}: {e}")

    def _is_global_ip(self, ip: str) -> bool:
        """Check if IP is global (not private/local).

        Args:
            ip: IP address to check

        Returns:
            bool: True if IP is global
        """
        try:
            ip_addr = ipaddress.ip_address(ip)

            # Handle own_network check for IPv4
            if self.own_network and type(ip_addr) is ipaddress.IPv4Address and ip_addr in self.own_network:
                return False

            # Let Python's ipaddress module determine if the IP is global
            return ip_addr.is_global

        except Exception:
            return False

    def _create_message_data(self, alert: dict[str, Any]) -> KafkaMessage:  # NOSONAR
        """Create message data for Kafka.

        Args:
            alert: Alert data

        Returns:
            Dict containing formatted message data
        """
        msg_data: KafkaMessage = {
            "timestamp": alert["timestamp"],
            "event_format": "syslog5424-json",
            "event_forward": True,
            "event_parser": "wazuh",
            "event_source": "soc-agent",
            "hostName": alert.get("agent", {}).get("name", ""),
            "structuredData": "",
            "body": "",  # Will be set below
            "context_alert": alert,  # Store the original alert for later use
        }

        # Access data using the dictionary get() method
        severity = 0
        if "data" in alert:
            if "program_name" in alert["data"]:
                msg_data["appName"] = alert["data"]["program_name"]
                msg_data["appInst"] = alert["data"]["program_name"]
            if "pid" in alert["data"]:
                msg_data["procId"] = alert["data"]["pid"]

            severity = 6
            if "severity" in alert["data"]:
                if alert["data"]["severity"] == "NOTICE":
                    severity = 5
                if alert["data"]["severity"] == "WARNING":
                    severity = 4
                if alert["data"]["severity"] == "ERROR":
                    severity = 3

        priority = (4 * 8) + severity
        msg_data["facility"] = "4"
        msg_data["priority"] = priority
        msg_data["severity"] = severity

        msg = alert["full_log"]
        if msg and msg.startswith("fail2ban"):
            msg = alert["full_log"][10:]

        msg_data["event_raw"] = f"<{priority}> 1 {msg}"

        index_of = -1
        severity_str = alert["data"].get("severity", "")
        if severity_str and len(severity_str) > 0:
            # Only search for non-empty severity strings
            if severity_str in msg_data["event_raw"]:
                index_of = msg_data["event_raw"].index(severity_str)

        if index_of >= 0:
            msg_data["body"] = msg_data["event_raw"][index_of:]
        else:
            msg_data["body"] = msg_data["event_raw"]

        return msg_data
