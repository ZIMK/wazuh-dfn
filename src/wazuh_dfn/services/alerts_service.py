"""Alerts service module for handling alert processing."""

import logging
from typing import Any

from wazuh_dfn.config import MiscConfig

from .handlers import SyslogHandler, WindowsHandler
from .kafka_service import KafkaService
from .wazuh_service import WazuhService

LOGGER = logging.getLogger(__name__)


class AlertsService:
    """Service for handling alert processing.

    This class encapsulates all alert-related operations and configuration.
    It follows the principle of least privilege by only accessing
    the configuration it needs.
    """

    def __init__(
        self,
        config: MiscConfig,
        kafka_service: KafkaService,
        wazuh_service: WazuhService,
    ) -> None:
        """Initialize AlertsService.

        Args:
            config: Miscellaneous configuration settings
            kafka_service: Service for Kafka operations
            wazuh_service: Service for Wazuh operations

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        # Validation is handled by Pydantic automatically
        self.config = config
        self.kafka_service = kafka_service
        self.wazuh_service = wazuh_service

        # Initialize handlers
        self.syslog_handler = SyslogHandler(config, kafka_service, wazuh_service)
        self.windows_handler = WindowsHandler(kafka_service, wazuh_service)

    def is_relevant_alert(self, alert: dict[str, Any]) -> bool:
        """Check if an alert is relevant for processing.

        Consults the appropriate handlers to determine if the alert
        should be processed.

        Args:
            alert: Alert data to check

        Returns:
            bool: True if the alert is relevant for processing
        """
        return self.windows_handler._is_relevant_windows_alert(
            alert
        ) or self.syslog_handler._is_relevant_fail2ban_alert(alert)

    async def process_alert(self, alert: dict[str, Any]) -> None:
        """Process an alert.

        Delegates alert processing to specialized handlers based on the alert type.
        Currently supports Windows and Syslog alert formats.

        Args:
            alert: Alert data to process as a dictionary
        """
        try:
            await self.windows_handler.process_alert(alert)
        except Exception as err:
            LOGGER.error(f"Got error in WindowAlertsHandler.send: {err!s}", exc_info=True)

        try:
            await self.syslog_handler.process_alert(alert)
        except Exception as err:
            LOGGER.error(f"Got error in SyslogAlertsHandler.send: {err!s}", exc_info=True)

    # No async version needed as this just delegates to other handlers
    # which will handle async processing internally when needed
