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
            self._process_fail2ban_alert(alert)
        except Exception as error:
            alert_id = alert.get("id", "Unknown")
            LOGGER.error(f"Error processing Syslog alert: {alert_id}: {error!s}", exc_info=True)

    def _process_fail2ban_alert(self, alert: dict[str, Any]) -> None:
        """Process fail2ban-specific alert data.

        Args:
            alert: Alert data to process
        """
        LOGGER.debug("Processing fail2ban alert...")
        LOGGER.debug("Executing _process_fail2ban_alert method")

        if (
            "data" in alert
            and "srcip" in alert["data"]
            and "program_name" in alert["data"]
            and alert["data"]["program_name"] == "fail2ban.actions"
            and "rule" in alert
            and "groups" in alert["rule"]
            and "fail2ban" in alert["rule"]["groups"]
        ):
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
            # Store the task reference to fix RUF006, and suppress the linting error
            _task = asyncio.create_task(self._send_message(message_data, alert_id))  # noqa: RUF006
        else:
            LOGGER.debug("No fail2ban alert to process")

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

            # Send to Wazuh with the original format
            await self.wazuh_service.send_event(
                alert=alert,
                event_format="syslog5424-json",
                wz_timestamp=alert.get("timestamp"),
            )
        else:
            error_msg = f"Failed to send fail2ban alert to Kafka {alert_id}"
            LOGGER.error(error_msg)
            # Send error to Wazuh
            await self.wazuh_service.send_error(
                {
                    "error": 503,
                    "description": error_msg,
                }
            )

    def _is_global_ip(self, ip: str) -> bool:
        """Check if IP is global (not private/local).

        Args:
            ip: IP address to check

        Returns:
            bool: True if IP is global
        """
        try:
            ip_addr = ipaddress.ip_address(ip)

            if (
                self.own_network
                and type(ip_addr) is ipaddress.IPv4Address
                and ip_addr in ipaddress.ip_network(self.own_network)
            ):
                return False
            return ip_addr.is_global

        except Exception:
            return False

    def _create_message_data(self, alert: dict[str, Any]) -> KafkaMessage:
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
        if len(alert["data"]["severity"]) > 0:
            index_of = msg_data["event_raw"].index(alert["data"]["severity"])
        if index_of >= 0:
            msg_data["body"] = msg_data["event_raw"][index_of:]
        else:
            msg_data["body"] = msg_data["event_raw"]

        return msg_data
