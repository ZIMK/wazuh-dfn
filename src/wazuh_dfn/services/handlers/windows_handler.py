"""Windows alert handler module."""

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Any

from wazuh_dfn.services.kafka_service import KafkaMessage, KafkaService
from wazuh_dfn.services.wazuh_service import WazuhService

LOGGER = logging.getLogger(__name__)


class WindowsHandler:
    """Handler for Windows alerts.

    This class processes Windows-specific alerts and formats them
    according to the Windows event schema.
    """

    def __init__(
        self,
        kafka_service: KafkaService,
        wazuh_service: WazuhService,
    ) -> None:
        """Initialize WindowsHandler.

        Args:
            kafka_service: Service for Kafka operations
            wazuh_service: Service for Wazuh operations
        """
        self.kafka_service = kafka_service
        self.wazuh_service = wazuh_service

    async def process_alert(self, alert: dict[str, Any]) -> None:
        """Process a Windows alert.

        Args:
            alert: Alert data to process
        """
        try:
            if self._is_relevant_windows_alert(alert):
                await self._process_windows_alert(alert)
            else:
                LOGGER.debug("No windows alert to process")
        except Exception as error:
            alert_id = alert.get("id", "Unknown")
            LOGGER.error(f"Error processing Windows alert: {alert_id}: {error!s}", exc_info=True)

    def _is_relevant_windows_alert(self, alert: dict[str, Any]) -> bool:
        """Check if the alert is a relevant Windows alert to process.

        Args:
            alert: Alert data to check

        Returns:
            bool: True if the alert is a relevant Windows alert
        """
        if (
            "data" in alert
            and "win" in alert["data"]
            and "system" in alert["data"]["win"]
            and "eventID" in alert["data"]["win"]["system"]
        ):
            event_id = str(alert["data"]["win"]["system"]["eventID"])

            # Complete list of event IDs to process
            return event_id in [
                "4625",  # Failed logon attempt
                "4719",  # System audit policy was changed
                "4964",  # Special groups assigned to a new logon
                "1102",  # Audit log was cleared
                "4794",  # Directory service restore mode admin password set attempt
                "4724",  # Password reset attempt was made
                "4697",  # Service was installed in the system
                "4702",  # Scheduled task was created
                "4698",  # Scheduled task was created
                "4672",  # Special privileges assigned to new logon
                "4720",  # User account was created
                "1100",  # Event logging service was shut down
            ]
        return False

    async def _process_windows_alert(self, alert: dict[str, Any]) -> None:
        """Process Windows-specific alert data.

        Args:
            alert: Alert data to process
        """
        event_id = str(alert["data"]["win"]["system"]["eventID"])

        # Create message data for Kafka
        message_data = self._create_message_data(alert, event_id)

        # Use asyncio to send to Kafka
        alert_id = alert.get("id", "Unknown")
        # Wait for _send_message to complete instead of fire-and-forget
        await self._send_message(message_data, alert_id)

    async def _send_message(self, message_data: KafkaMessage, alert_id: str) -> None:
        """Send message to Kafka asynchronously.

        Sends a Windows event alert to Kafka and logs the result.

        Args:
            message_data: The formatted message to send to Kafka
            alert_id: The alert ID for logging and tracking
        """
        # Send to Kafka
        result = await self.kafka_service.send_message(message_data)
        if result:
            LOGGER.debug(f"Windows alert sent successfully: {result}")
            # Extract the original alert from the message_data context
            alert = message_data.get("context_alert", {})

            # Get Windows timestamp from alert if available
            win_timestamp = None
            if "data" in alert and "win" in alert["data"] and "system" in alert["data"]["win"]:
                if "systemTime" in alert["data"]["win"]["system"]:
                    win_timestamp = alert["data"]["win"]["system"]["systemTime"]

            # Send to Wazuh with the original format as fire-and-forget
            asyncio.create_task(  # noqa: RUF006
                self._send_to_wazuh(
                    alert=alert,
                    event_format="windows-xml",
                    event_id=alert.get("data", {}).get("win", {}).get("system", {}).get("eventID"),
                    win_timestamp=win_timestamp,
                    wz_timestamp=alert.get("timestamp"),
                    alert_id=alert_id,
                )
            )
        else:
            error_msg = f"Failed to send Windows alert to Kafka {alert_id}"
            LOGGER.error(error_msg)
            # Send error to Wazuh as fire-and-forget
            asyncio.create_task(self._send_error_to_wazuh(error_msg=error_msg, alert_id=alert_id))  # noqa: RUF006

    async def _send_to_wazuh(
        self,
        alert: dict[str, Any],
        event_format: str,
        event_id: str | None,
        win_timestamp: str | None,
        wz_timestamp: str | None,
        alert_id: str,
    ) -> None:
        """Send event to Wazuh service with error handling.

        Args:
            alert: Alert data to send
            event_format: Format of the event
            event_id: Event ID for Windows events
            win_timestamp: Windows event timestamp
            wz_timestamp: Wazuh event timestamp
            alert_id: Alert ID for error tracking
        """
        try:
            await self.wazuh_service.send_event(
                alert=alert,
                event_format=event_format,
                event_id=event_id,
                win_timestamp=win_timestamp,
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

    def _create_message_data(self, alert: dict[str, Any], event_id: str) -> KafkaMessage:
        """Create message data for Kafka.

        Args:
            alert: Alert data
            event_id: Event ID

        Returns:
            Message data for Kafka
        """
        # Create XML event
        win_event_xml = self._create_xml_event(alert, event_id)

        # Create message data
        message_data: KafkaMessage = {
            "timestamp": alert["timestamp"],
            "event_raw": ET.tostring(win_event_xml, encoding="unicode"),
            "body": ET.tostring(win_event_xml, encoding="unicode"),
            "event_format": "windows-xml",
            "event_forward": True,
            "event_parser": "wazuh",
            "event_source": "soc-agent",
            "data": alert["data"],
            "context_alert": alert,  # Store the original alert for later use
        }

        return message_data

    def _create_xml_event(self, alert: dict[str, Any], event_id: str) -> ET.Element:
        """
        Generate a Windows event XML element based on the alert information and event ID.

        Parameters
        ----------
        alert : dict
            The alert dictionary containing information about the Windows event.
        event_id : str
            The event ID of the Windows event.

        Returns:
        -------
        ET.Element
            An XML element representing the generated Windows event.
        """
        win_alert = alert["data"]["win"]

        root = ET.Element("Event")
        root.set("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")
        system = ET.Element("System")

        root.append(system)

        if "system" not in win_alert:
            return ET.Element("Event")

        self._generate_win_event_system(system, win_alert["system"])

        if event_id == "1100":
            root.append(self._create_win_event_event_data_1100())
        elif event_id == "1102":
            if "logFileCleared" in win_alert:
                root.append(self._create_win_event_event_data_1102(win_alert["logFileCleared"]))
        elif "eventdata" in win_alert:
            root.append(self._create_win_event_event_data(win_alert["eventdata"], event_id))
        else:
            alert_id = alert["id"]
            agent_id = alert["agent"]["id"]
            agent_name = alert["agent"]["name"]
            LOGGER.error(
                f"Incomplete Windows alert. No eventdata found. alert_id: {alert_id},"
                f" agent_id: {agent_id}, agent_name: {agent_name}"
            )

            # Create a task for the async error sending to avoid blocking
            # Using fire-and-forget pattern
            asyncio.create_task(  # noqa: RUF006
                self._send_error_to_wazuh(
                    error_msg=(
                        f"Incomplete Windows alert. No eventdata found. alert_id: {alert_id},"
                        f" agent_id: {agent_id}, agent_name: {agent_name}"
                    ),
                    alert_id=alert_id,
                )
            )

        return root

    def _generate_win_event_system(self, elem: ET.Element, system_alert: dict) -> None:
        """
        Generate the System element for the Windows event XML.

        Parameters
        ----------
        elem : ET.Element
            The parent element to append the System element to.
        system_alert : dict
            The system alert dictionary containing information about the Windows event.

        Returns:
        -------
        None
        """
        elem.append(
            ET.Element("Provider", {"Name": system_alert["providerName"], "Guid": system_alert["providerGuid"]})
        )
        event_id = ET.Element("EventID")
        event_id.text = system_alert["eventID"]
        elem.append(event_id)

        version = ET.Element("Version")
        version.text = system_alert.get("version", "")
        elem.append(version)

        level = ET.Element("Level")
        level.text = system_alert.get("level", "")
        elem.append(level)

        task = ET.Element("Task")
        task.text = system_alert.get("task", "")
        elem.append(task)

        opcode = ET.Element("Opcode")
        opcode.text = system_alert.get("opcode", "")
        elem.append(opcode)

        keywords = ET.Element("Keywords")
        keywords.text = system_alert.get("keywords", "")
        elem.append(keywords)

        if "systemTime" in system_alert:
            elem.append(ET.Element("TimeCreated", {"SystemTime": system_alert["systemTime"]}))
        else:
            LOGGER.warning(f"Missing systemTime in system alert: {system_alert.get('eventRecordID', '')}")
            elem.append(ET.Element("TimeCreated"))

        event_record_id = ET.Element("EventRecordID")
        event_record_id.text = system_alert.get("eventRecordID", "")
        elem.append(event_record_id)

        elem.append(ET.Element("Correlation"))

        elem.append(
            ET.Element(
                "Execution",
                {"ProcessID": system_alert.get("processID", ""), "ThreadID": system_alert.get("threadID", "")},
            )
        )

        channel = ET.Element("Channel")
        channel.text = system_alert.get("channel", "")
        elem.append(channel)

        computer = ET.Element("Computer")
        computer.text = system_alert.get("computer", "")
        elem.append(computer)

        elem.append(ET.Element("Security"))

    def _create_win_event_event_data(self, event_data_alert: dict, event_id: str) -> ET.Element:
        """
        Generate the EventData element for the Windows event XML based on the alert information and event ID.

        Parameters
        ----------
        event_data_alert : dict
            The event data alert dictionary containing information about the Windows event.
        event_id : str
            The event ID of the Windows event.

        Returns:
        -------
        ET.Element
            An XML element representing the generated EventData element.
        """
        event_data = ET.Element("EventData")
        for x in event_data_alert.items():
            tmp = ET.Element("Data", attrib={"Name": x[0][0].upper() + x[0][1:]})
            tmp.text = x[1]
            event_data.append(tmp)

        if event_id in ["4625", "4771", "4768"]:
            if "ipAddress" not in event_data_alert:
                tmp = ET.Element("Data", attrib={"Name": "IpAddress"})
                tmp.text = "-"
                event_data.append(tmp)

            if "ipPort" not in event_data_alert:
                tmp = ET.Element("Data", attrib={"Name": "IpPort"})
                tmp.text = "-"
                event_data.append(tmp)

        return event_data

    def _create_win_event_event_data_1100(self) -> ET.Element:
        """
        Generate the EventData element for the Windows event XML with event ID 1100.

        Returns:
        -------
        ET.Element
            An XML element representing the generated EventData element.
        """
        event_data = ET.Element("UserData")
        elem = ET.Element("ServiceShutdown")
        elem.set("xmlns", "http://manifests.microsoft.com/win/2004/08/windows/eventlog")
        event_data.append(elem)

        return event_data

    def _create_win_event_event_data_1102(self, event_data_alert: dict) -> ET.Element:
        """
        Generate the EventData element for the Windows event XML with event ID 1102.

        Parameters
        ----------
        event_data_alert : dict
            The event data alert dictionary containing information about the Windows event.

        Returns:
        -------
        ET.Element
            An XML element representing the generated EventData element.
        """
        event_data = ET.Element("UserData")
        elem = ET.Element("LogFileCleared")
        elem.set("xmlns", "http://manifests.microsoft.com/win/2004/08/windows/eventlog")
        event_data.append(elem)

        for x in event_data_alert.items():
            tmp = ET.Element(x[0][0].upper() + x[0][1:])
            tmp.text = x[1]
            elem.append(tmp)

        return event_data
