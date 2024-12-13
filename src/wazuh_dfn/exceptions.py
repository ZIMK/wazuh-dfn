"""Custom exceptions for the Wazuh DFN integration."""


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""


class AlertProcessingError(Exception):
    """Raised when alert processing fails."""


class ServiceError(Exception):
    """Raised when a service operation fails."""


class KafkaError(Exception):
    """Raised when Kafka operations fail."""


class WazuhError(Exception):
    """Raised when Wazuh operations fail."""
