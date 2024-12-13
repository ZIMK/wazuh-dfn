"""Alerts service module for handling alert processing."""

import logging

from ..config import MiscConfig
from ..validators import MiscConfigValidator
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
            config: Miscellaneous configuration
            kafka_service: Service for Kafka operations
            wazuh_service: Service for Wazuh operations

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        MiscConfigValidator.validate(config)
        self.config = config
        self.kafka_service = kafka_service
        self.wazuh_service = wazuh_service

        # Initialize handlers
        self.syslog_handler = SyslogHandler(config, kafka_service, wazuh_service)
        self.windows_handler = WindowsHandler(kafka_service, wazuh_service)

    def process_alert(self, alert: dict) -> None:
        """Process an alert.

        Args:
            alert: Alert data to process

        """

        try:
            self.windows_handler.process_alert(alert)
        except Exception as err:
            LOGGER.error(f"Got error in WindowAlertsHandler.send: {str(err)}", exc_info=True)

        try:
            self.syslog_handler.process_alert(alert)
        except Exception as err:
            LOGGER.error(f"Got error in SyslogAlertsHandler.send: {str(err)}", exc_info=True)
