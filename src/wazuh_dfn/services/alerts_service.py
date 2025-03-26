"""Alerts service module for handling alert processing."""

import logging
from .handlers import SyslogHandler, WindowsHandler
from .kafka_service import KafkaService
from .wazuh_service import WazuhService
from wazuh_dfn.config import MiscConfig
from wazuh_dfn.services.handlers.syslog_handler import SyslogAlert
from wazuh_dfn.services.handlers.windows_handler import WindowsAlert

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
            config: Miscellaneous configuration
            kafka_service: KafkaService instance
            wazuh_service: WazuhService instance

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

    def process_alert(self, alert: SyslogAlert | WindowsAlert) -> None:
        """Process an alert.

        Args:
            alert: Alert data to process

        """
        try:
            self.windows_handler.process_alert(alert)
        except Exception as err:
            LOGGER.error(f"Got error in WindowAlertsHandler.send: {err!s}", exc_info=True)

        try:
            self.syslog_handler.process_alert(alert)
        except Exception as err:
            LOGGER.error(f"Got error in SyslogAlertsHandler.send: {err!s}", exc_info=True)
