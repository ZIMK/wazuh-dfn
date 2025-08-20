"""Configuration module for Wazuh DFN service."""

import argparse
import ipaddress
import json
import logging
import os
import tomllib
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .exceptions import ConfigValidationError

# Logging
LOGGER = logging.getLogger(__name__)

# Add support for Pydantic type coercion


class LogLevel(str, Enum):
    """Valid logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class WazuhConfig(BaseModel):
    """Wazuh configuration settings."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    unix_socket_path: str | tuple[str, int] = Field(
        default="/var/ossec/queue/sockets/queue",
        description="Path to Wazuh socket (str for Unix socket or tuple of (host, port) for TCP)",
        json_schema_extra={
            "env_var": "WAZUH_UNIX_SOCKET_PATH",
            "cli": "--wazuh-unix-socket-path",
        },
    )
    max_event_size: int = Field(
        default=65535,
        description="Maximum size of events to process",
        json_schema_extra={
            "env_var": "WAZUH_MAX_EVENT_SIZE",
            "cli": "--wazuh-max-event-size",
        },
        gt=0,
    )
    json_alert_file: str = Field(
        default="/var/ossec/logs/alerts/alerts.json",
        description="Full path to the JSON alerts file to monitor",
        json_schema_extra={
            "env_var": "WAZUH_JSON_ALERT_FILE",
            "cli": "--wazuh-json-alert-file",
        },
    )
    json_alert_prefix: str = Field(
        default='{"timestamp"',
        description="Expected prefix of JSON alert lines",
        json_schema_extra={
            "env_var": "WAZUH_JSON_ALERT_PREFIX",
            "cli": "--wazuh-json-prefix",
        },
    )
    json_alert_suffix: str = Field(
        default="}",
        description="Expected suffix of JSON alert lines",
        json_schema_extra={
            "env_var": "WAZUH_JSON_ALERT_SUFFIX",
            "cli": "--wazuh-json-suffix",
        },
    )
    max_retries: int = Field(
        default=42,
        description="Maximum number of retries",
        json_schema_extra={
            "env_var": "WAZUH_MAX_RETRIES",
            "cli": "--wazuh-max-retries",
        },
        gt=0,
    )
    retry_interval: int = Field(
        default=5,
        description="Interval between retries in seconds",
        json_schema_extra={
            "env_var": "WAZUH_RETRY_INTERVAL",
            "cli": "--wazuh-retry-interval",
        },
        gt=0,
    )
    max_connection_failures_per_event: int = Field(
        default=10,
        description="Maximum consecutive connection failures per event before dropping it (was hardcoded at 3)",
        json_schema_extra={
            "env_var": "WAZUH_MAX_CONNECTION_FAILURES_PER_EVENT",
            "cli": "--wazuh-max-connection-failures-per-event",
        },
        gt=0,
    )
    connection_failure_backoff_base: float = Field(
        default=0.1,
        description="Base sleep time for connection failure exponential backoff (seconds)",
        json_schema_extra={
            "env_var": "WAZUH_CONNECTION_FAILURE_BACKOFF_BASE",
            "cli": "--wazuh-connection-failure-backoff-base",
        },
        gt=0,
    )
    max_retry_wait_time: int = Field(
        default=30,
        description="Maximum wait time cap for exponential backoff (seconds)",
        json_schema_extra={
            "env_var": "WAZUH_MAX_RETRY_WAIT_TIME",
            "cli": "--wazuh-max-retry-wait-time",
        },
        gt=0,
    )
    max_connection_wait_attempts: int = Field(
        default=50,
        description="Maximum attempts to wait for connection state changes (default 50 = 5 seconds at 0.1s intervals)",
        json_schema_extra={
            "env_var": "WAZUH_MAX_CONNECTION_WAIT_ATTEMPTS",
            "cli": "--wazuh-max-connection-wait-attempts",
        },
        gt=0,
    )
    connection_wait_sleep_interval: float = Field(
        default=0.1,
        description="Sleep interval when waiting for connection state changes (seconds)",
        json_schema_extra={
            "env_var": "WAZUH_CONNECTION_WAIT_SLEEP_INTERVAL",
            "cli": "--wazuh-connection-wait-sleep-interval",
        },
        gt=0,
    )
    connection_timeout: float = Field(
        default=30.0,
        description="Socket connection timeout in seconds",
        json_schema_extra={
            "env_var": "WAZUH_CONNECTION_TIMEOUT",
            "cli": "--wazuh-connection-timeout",
        },
        gt=0,
    )
    read_timeout: float = Field(
        default=10.0,
        description="Socket read timeout in seconds",
        json_schema_extra={
            "env_var": "WAZUH_READ_TIMEOUT",
            "cli": "--wazuh-read-timeout",
        },
        gt=0,
    )
    write_timeout: float = Field(
        default=10.0,
        description="Socket write timeout in seconds",
        json_schema_extra={
            "env_var": "WAZUH_WRITE_TIMEOUT",
            "cli": "--wazuh-write-timeout",
        },
        gt=0,
    )
    json_alert_file_poll_interval: float = Field(
        default=1.0,
        description="Interval in seconds between JSON alert file checks",
        json_schema_extra={
            "env_var": "WAZUH_JSON_ALERT_FILE_POLL_INTERVAL",
            "cli": "--wazuh-json-alert-file-poll-interval",
        },
        gt=0,
    )
    store_failed_alerts: bool = Field(
        default=False,
        description="Whether to store failed alerts for later analysis",
        json_schema_extra={
            "env_var": "WAZUH_STORE_FAILED_ALERTS",
            "cli": "--wazuh-store-failed-alerts",
        },
    )
    failed_alerts_path: str = Field(
        default="/opt/wazuh-dfn/failed-alerts",
        description="Directory path to store failed alerts",
        json_schema_extra={
            "env_var": "WAZUH_FAILED_ALERTS_PATH",
            "cli": "--wazuh-failed-alerts-path",
        },
    )
    max_failed_files: int = Field(
        default=100,
        description="Maximum number of failed alert files to keep",
        json_schema_extra={
            "env_var": "WAZUH_MAX_FAILED_FILES",
            "cli": "--wazuh-max-failed-files",
        },
        gt=0,
    )
    json_alert_queue_size: int = Field(
        default=100000,
        description="Maximum number of alerts to queue for processing",
        json_schema_extra={
            "env_var": "WAZUH_JSON_ALERT_QUEUE_SIZE",
            "cli": "--wazuh-json-alert-queue-size",
        },
        gt=0,
    )
    integration_name: str = Field(
        default="dfn",
        description="Integration name for the Wazuh API",
        json_schema_extra={
            "env_var": "WAZUH_INTEGRATION_NAME",
            "cli": "--wazuh-integration-name",
        },
    )

    # Add model validator to validate required fields
    @model_validator(mode="after")
    def validate_wazuh_config(self) -> "WazuhConfig":
        """Validate configuration after initialization.

        Performs validation checks on the WazuhConfig object after it has been initialized.
        Validates that required fields are present and properly formatted.

        Returns:
            WazuhConfig: The validated configuration object

        Raises:
            ValueError: If validation fails
        """
        if not self.unix_socket_path:
            raise ValueError("unix_socket_path cannot be empty")

        # Validate unix_socket_path type
        if isinstance(self.unix_socket_path, str):
            # Python 3.11+ knows self.unix_socket_path is a string in this block
            # For Unix socket path, check if file exists when it's not a default value
            if self.unix_socket_path != "/var/ossec/queue/sockets/queue":
                socket_path = Path(self.unix_socket_path)
                if not socket_path.exists() and not socket_path.is_socket():
                    LOGGER.warning(f"Unix socket path does not exist: {self.unix_socket_path}")
        elif isinstance(self.unix_socket_path, tuple):
            # Python 3.11+ knows self.unix_socket_path is a tuple in this block
            # Validate host/port tuple format
            if len(self.unix_socket_path) != 2:
                raise ValueError("Host/port tuple must have exactly 2 elements: (host, port)")

            host, port = self.unix_socket_path
            if not isinstance(host, str) or not host:
                raise ValueError("Host must be a non-empty string")
            if not isinstance(port, int) or port <= 0 or port > 65535:
                raise ValueError("Port must be an integer between 1 and 65535")
        else:
            raise ValueError("unix_socket_path must be either a string path or a (host, port) tuple")

        if not self.json_alert_file:
            raise ValueError("json_alert_file cannot be empty")
        return self

    @field_validator("unix_socket_path")
    @classmethod
    def validate_socket_path(cls, v):
        """Validate the unix_socket_path format.

        Converts string representations of tuples into actual tuple objects.
        For example, "(localhost, 1514)" becomes ("localhost", 1514).

        Args:
            v: The value to validate, typically a string or tuple

        Returns:
            (tuple[str, int] | Unknown | str): Either the original string or a tuple of (host, port)

        Raises:
            ValueError: If the format resembles a tuple but is malformed
        """
        # If it's a string representation of a tuple like "(localhost, 1514)", convert to actual tuple
        if isinstance(v, str) and v.startswith("(") and v.endswith(")"):
            # Parse tuple string like "(host, port)"
            parts = v.strip("()").split(",")
            if len(parts) == 2:
                host = parts[0].strip().strip("'\"")
                try:
                    port = int(parts[1].strip())
                    return (host, port)
                except ValueError:
                    # Explicitly raise ValueError for non-numeric ports
                    raise ValueError(f"Invalid port in host/port format: {v}. Port must be a number.")
            else:
                raise ValueError(f"Invalid host/port format: {v}. Expected format: '(host, port)'")
        return v


class DFNConfig(BaseModel):
    """DFN-specific configuration parameters."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    dfn_broker: str = Field(
        default="kafka.example.org:443",
        description="DFN Kafka broker address",
        json_schema_extra={
            "env_var": "DFN_BROKER_ADDRESS",
            "cli": "--dfn-broker-address",
        },
    )
    dfn_cert: str = Field(
        default="/opt/wazuh-dfn/certs/dfn-cert.pem",
        description="Path to client certificate for Kafka SSL",
        json_schema_extra={
            "env_var": "DFN_CERT_PATH",
            "cli": "--dfn-cert-path",
        },
    )
    dfn_key: str = Field(
        default="/opt/wazuh-dfn/certs/dfn-key.pem",
        description="Path to client key for Kafka SSL",
        json_schema_extra={
            "env_var": "DFN_KEY_PATH",
            "cli": "--dfn-key-path",
        },
    )
    dfn_ca: str | None = Field(
        default=None,
        description="Path to CA certificate for Kafka SSL",
        json_schema_extra={
            "env_var": "DFN_CA_PATH",
            "cli": "--dfn-ca-path",
        },
    )
    dfn_id: str | None = Field(
        default=None,
        description="DFN customer ID",
        json_schema_extra={
            "env_var": "DFN_CUSTOMER_ID",
            "cli": "--dfn-customer-id",
        },
    )
    skip_path_validation: bool = Field(default=False, exclude=True)

    def validate_certificates(self) -> bool:
        """Validate certificate files for SSL.

        Verifies that certificates are valid, correctly formatted, and properly chained.

        Returns:
            bool: True if certificates are valid, allowing the process to continue

        Raises:
            ConfigValidationError: If certificates are invalid, expired, or mismatched
        """
        if not self.dfn_ca or not self.dfn_cert or not self.dfn_key:
            return True  # Skip validation if not configured

        if self.skip_path_validation:
            return True  # Skip validation if not configured

        try:
            # Load CA certificate
            with Path(self.dfn_ca).open("rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Load client certificate
            with Path(self.dfn_cert).open("rb") as f:
                client_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Load client key
            with Path(self.dfn_key).open("rb") as f:
                client_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()  # Add password parameter if key is encrypted
                )

            now = datetime.now(UTC)

            # More explicit date validation for better tests
            if ca_cert.not_valid_before_utc > now:
                raise ConfigValidationError("CA certificate is not yet valid")
            if now > ca_cert.not_valid_after_utc:
                raise ConfigValidationError("CA certificate is expired")

            if client_cert.not_valid_before_utc > now:
                raise ConfigValidationError("Client certificate is not yet valid")
            if now > client_cert.not_valid_after_utc:
                raise ConfigValidationError("Client certificate is expired")

            # Check that client cert matches private key
            client_public_key = client_cert.public_key()
            key_match = self._verify_key_pair(client_key, client_public_key)
            if not key_match:
                raise ConfigValidationError("Client certificate doesn't match private key")

            # Verify CA signed the client cert
            self._verify_certificate_chain(ca_cert, client_cert)

            return True

        except ConfigValidationError:
            # Re-raise ConfigValidationError directly without wrapping
            raise
        except Exception as e:
            raise ConfigValidationError(f"Certificate validation failed: {e}")

    def _verify_key_pair(self, private_key, public_key) -> bool:
        """Verify that a private key and public key form a valid pair.

        Performs a cryptographic test by signing and verifying a test message to ensure
        the private and public key correspond to each other.

        Args:
            private_key: The private key to test
            public_key: The public key to test against the private key

        Returns:
            bool: True if keys form a valid pair, False otherwise
        """
        try:
            # Create a test message
            message = b"Test message for key verification"

            # Sign with private key
            signature = private_key.sign(
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )

            # Verify with public key
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def _verify_certificate_chain(self, ca_cert, client_cert) -> None:
        """Verify CA signed the client certificate.

        Checks if the client certificate was issued by the provided Certificate Authority
        by comparing the issuer field of the client certificate with the subject field
        of the CA certificate.

        Args:
            ca_cert: The Certificate Authority certificate
            client_cert: The client certificate to verify

        Raises:
            ConfigValidationError: If the client certificate was not issued by the provided CA
        """
        # This is simplified - a complete implementation would handle the full chain
        # and verify against a CRL or OCSP
        issuer = ca_cert.subject
        if client_cert.issuer != issuer:
            raise ConfigValidationError("Client certificate not issued by the provided CA.")


class KafkaConfig(BaseModel):
    """Kafka configuration."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    timeout: int = Field(
        default=60,
        description="Kafka request timeout in seconds",
        json_schema_extra={
            "env_var": "KAFKA_TIMEOUT",
            "cli": "--kafka-timeout",
        },
        gt=0,
    )
    retry_interval: int = Field(
        default=5,
        description="Interval between retries in seconds",
        json_schema_extra={
            "env_var": "KAFKA_RETRY_INTERVAL",
            "cli": "--kafka-retry-interval",
        },
        gt=0,
    )
    connection_max_retries: int = Field(
        default=5,
        description="Maximum number of connection retries",
        json_schema_extra={
            "env_var": "KAFKA_CONNECTION_MAX_RETRIES",
            "cli": "--kafka-connection-max-retries",
        },
        gt=0,
    )
    send_max_retries: int = Field(
        default=5,
        description="Maximum number of send retries",
        json_schema_extra={
            "env_var": "KAFKA_SEND_MAX_RETRIES",
            "cli": "--kafka-send-max-retries",
        },
        gt=0,
    )
    max_wait_time: int = Field(
        default=60,
        description="Maximum wait time between retries in seconds",
        json_schema_extra={
            "env_var": "KAFKA_MAX_WAIT_TIME",
            "cli": "--kafka-max-wait-time",
        },
        gt=0,
    )
    admin_timeout: int = Field(
        default=10,
        description="Timeout for admin operations in seconds",
        json_schema_extra={
            "env_var": "KAFKA_ADMIN_TIMEOUT",
            "cli": "--kafka-admin-timeout",
        },
        gt=0,
    )
    service_retry_interval: int = Field(
        default=5,
        description="Interval between service retries in seconds",
        json_schema_extra={
            "env_var": "KAFKA_SERVICE_RETRY_INTERVAL",
            "cli": "--kafka-service-retry-interval",
        },
        gt=0,
    )
    compression_type: str = Field(
        default="gzip",
        description="Compression type for Kafka messages",
        json_schema_extra={
            "env_var": "KAFKA_COMPRESSION_TYPE",
            "cli": "--kafka-compression-type",
        },
    )
    producer_config: dict[str, Any] = Field(
        default_factory=lambda: {
            "linger_ms": 5,
            "max_batch_size": 16384,
            "acks": 1,
            "max_request_size": 1048576,
        },
        description="Kafka producer configuration",
        json_schema_extra={
            "env_var": "KAFKA_PRODUCER_CONFIG",
            "cli": "--kafka-producer-config",
        },
    )

    def get_common_client_params(self, dfn_config: DFNConfig) -> dict:
        """Get common parameters for both producer and admin client.

        Returns a dictionary with parameters that are identical for both
        producer and admin client configuration.

        Args:
            dfn_config: DFN configuration containing broker and certificate paths

        Returns:
            dict: Common client parameters for aiokafka clients
        """
        return {
            "bootstrap_servers": dfn_config.dfn_broker,
            "security_protocol": "SSL" if (dfn_config.dfn_cert and dfn_config.dfn_key) else None,
            # Common timeouts and retries
            "request_timeout_ms": self.timeout * 1000,
            "retry_backoff_ms": self.retry_interval * 1000,
            "connections_max_idle_ms": 540000,  # 9 minutes
        }

    def get_producer_config(self, dfn_config: DFNConfig) -> dict:
        """Get configuration specifically for the aiokafka producer.

        Creates a configuration compatible with aiokafka's parameters.
        Note: aiokafka has different parameter names than confluent-kafka.

        Args:
            dfn_config: DFN configuration containing broker and certificate paths

        Returns:
            dict: Complete producer configuration with aiokafka-compatible parameter names
        """
        # Create basic config with only aiokafka-compatible parameters
        producer_config = {
            "bootstrap_servers": dfn_config.dfn_broker,
            "security_protocol": "SSL" if (dfn_config.dfn_cert and dfn_config.dfn_key) else None,
            # Timeout and retry settings that are valid for aiokafka
            "request_timeout_ms": self.timeout * 1000,
            "retry_backoff_ms": self.retry_interval * 1000,
            # Basic performance settings valid in aiokafka
            "linger_ms": 5,
            "max_batch_size": 16384,
            "acks": 1,
            # Additional valid parameters
            "max_request_size": 1048576,  # 1MB
            "compression_type": self.compression_type,
        }

        # Remove any potential invalid parameters from user config
        # and only keep known valid aiokafka parameters
        valid_params = {
            "bootstrap_servers",
            "client_id",
            "metadata_max_age_ms",
            "request_timeout_ms",
            "api_version",
            "acks",
            "key_serializer",
            "value_serializer",
            "compression_type",
            "max_batch_size",
            "linger_ms",
            "partitioner",
            "max_request_size",
            "retry_backoff_ms",
            "security_protocol",
            "ssl_context",
            "connections_max_idle_ms",
            "max_in_flight_requests_per_connection",
        }

        # Update with user-specified configs, filtering out invalid parameters
        if self.producer_config:
            filtered_config = {k: v for k, v in self.producer_config.items() if k in valid_params}
            producer_config.update(filtered_config)

        return producer_config

    def get_admin_config(self, dfn_config: DFNConfig) -> dict:
        """Get configuration specifically for the aiokafka admin client.

        Returns a complete dictionary with all parameters needed for AIOKafkaAdminClient.
        Combines common parameters with admin-specific ones.

        Args:
            dfn_config: DFN configuration containing broker and certificate paths

        Returns:
            dict: Complete admin client configuration with aiokafka-compatible parameter names
        """
        # Start with common parameters
        admin_config = self.get_common_client_params(dfn_config)

        # Add admin-specific parameters
        admin_specific = {
            "client_id": "wazuh-dfn",
            "request_timeout_ms": self.admin_timeout * 1000,  # Override common timeout
        }

        # Merge the configurations
        admin_config.update(admin_specific)

        return admin_config


class LogConfig(BaseModel):
    """Logging configuration."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    console: bool = Field(
        default=True,
        description="Enable console logging",
        json_schema_extra={
            "env_var": "LOG_CONSOLE_ENABLED",
            "cli": "--log-console-enabled",
        },
    )
    keep_files: int = Field(
        default=5,
        description="Number of log files to keep when rotating",
        json_schema_extra={
            "env_var": "LOG_KEEP_FILES",
            "cli": "--log-keep-files",
        },
        gt=0,
    )
    interval: int = Field(
        default=600,
        description="Statistics logging interval in seconds",
        json_schema_extra={
            "env_var": "LOG_INTERVAL",
            "cli": "--log-interval",
        },
        gt=0,
    )
    level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
        json_schema_extra={
            "env_var": "LOG_LEVEL",
            "cli": "--log-level",
        },
    )
    file_path: str | None = Field(
        default=None,
        description="Path to log file",
        json_schema_extra={
            "env_var": "LOG_FILE_PATH",
            "cli": "--log-file-path",
        },
    )

    @field_validator("level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is valid.

        Args:
            v: Log level string to validate

        Returns:
            str: The validated log level string

        Raises:
            ValueError: If the log level is not one of the valid levels
        """
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}")
        return v

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        """Validate file path exists and is readable.

        Args:
            v: The file path string to validate

        Returns:
            str: The validated file path

        Note:
            Currently this is a placeholder for future implementation that will
            respect the skip_path_validation setting
        """
        return v


class APIConfig(BaseModel):
    """Health API Server configuration."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    # Core server settings
    enabled: bool = Field(
        default=False,
        description="Master flag to enable/disable HTTP server",
        json_schema_extra={
            "env_var": "HEALTH_HTTP_SERVER_ENABLED",
            "cli": "--health-api-enabled",
        },
    )
    host: str = Field(
        default="127.0.0.1",
        description="Host to bind to (default localhost only for security)",
        json_schema_extra={
            "env_var": "HEALTH_API_HOST",
            "cli": "--health-api-host",
        },
    )
    port: int = Field(
        default=8080,
        description="Port to bind to",
        json_schema_extra={
            "env_var": "HEALTH_API_PORT",
            "cli": "--health-api-port",
        },
        ge=1,
        le=65535,
    )

    # Security settings
    auth_token: str | None = Field(
        default=None,
        description="Optional bearer token for authentication",
        json_schema_extra={
            "env_var": "HEALTH_API_AUTH_TOKEN",
            "cli": "--health-api-auth-token",
        },
    )
    allowed_ips: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "::1"],
        description="Allowed IP addresses/CIDR blocks",
        json_schema_extra={
            "env_var": "HEALTH_API_ALLOWED_IPS",
            "cli": "--health-api-allowed-ips",
        },
    )
    rate_limit: int = Field(
        default=100,
        description="Requests per minute rate limit",
        json_schema_extra={
            "env_var": "HEALTH_API_RATE_LIMIT",
            "cli": "--health-api-rate-limit",
        },
        gt=0,
    )

    # HTTPS settings (optional)
    https_enabled: bool = Field(
        default=False,
        description="Enable HTTPS support",
        json_schema_extra={
            "env_var": "HEALTH_API_HTTPS_ENABLED",
            "cli": "--health-api-https-enabled",
        },
    )
    cert_file: str | None = Field(
        default=None,
        description="Path to SSL certificate file",
        json_schema_extra={
            "env_var": "HEALTH_API_CERT_FILE",
            "cli": "--health-api-cert-file",
        },
    )
    key_file: str | None = Field(
        default=None,
        description="Path to SSL private key file",
        json_schema_extra={
            "env_var": "HEALTH_API_KEY_FILE",
            "cli": "--health-api-key-file",
        },
    )

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, v: list[str]) -> list[str]:
        """Validate IP addresses and CIDR blocks in allowlist."""
        if not v:
            raise ValueError("allowed_ips cannot be empty")

        for ip_str in v:
            ip_cleaned = ip_str.strip()
            if not ip_cleaned:
                continue

            try:
                # Try as network (CIDR) or single IP
                if "/" in ip_cleaned:
                    ipaddress.ip_network(ip_cleaned, strict=False)
                else:
                    ipaddress.ip_address(ip_cleaned)
            except ValueError as e:
                raise ValueError(f"Invalid IP/CIDR in allowed_ips: {ip_cleaned}") from e

        return v

    @model_validator(mode="after")
    def validate_https_config(self) -> "APIConfig":
        """Validate HTTPS configuration consistency."""
        if self.https_enabled and (not self.cert_file or not self.key_file):
            LOGGER.warning(
                "HTTPS enabled but cert_file or key_file not provided. " "HTTPS will be disabled at runtime."
            )
        return self


class HealthConfig(BaseModel):
    """Health monitoring configuration (enhanced replacement for LogConfig.interval)."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    stats_interval: int = Field(
        default=600,
        description="Health statistics collection interval in seconds (replaces LOG_INTERVAL)",
        json_schema_extra={
            "env_var": "HEALTH_STATS_INTERVAL",
            "cli": "--health-stats-interval",
        },
        gt=0,
    )
    history_retention: int = Field(
        default=3600,
        description="Health history retention period in seconds",
        json_schema_extra={
            "env_var": "HEALTH_HISTORY_RETENTION",
            "cli": "--health-history-retention",
        },
        gt=0,
    )
    max_history_entries: int = Field(
        default=1000,
        description="Maximum number of health history entries to prevent unbounded growth",
        json_schema_extra={
            "env_var": "HEALTH_MAX_HISTORY_ENTRIES",
            "cli": "--health-max-history-entries",
        },
        gt=0,
    )

    # API Server Configuration
    api: APIConfig = Field(
        default_factory=APIConfig,
        description="Health API server configuration",
    )

    # Configurable thresholds (replace hardcoded values)
    queue_warning_threshold: int = Field(
        default=70,
        description="Queue fill percentage warning threshold",
        json_schema_extra={
            "env_var": "HEALTH_QUEUE_WARNING_THRESHOLD",
            "cli": "--health-queue-warning-threshold",
        },
        ge=1,
        le=100,
    )
    queue_critical_threshold: int = Field(
        default=90,
        description="Queue fill percentage critical threshold",
        json_schema_extra={
            "env_var": "HEALTH_QUEUE_CRITICAL_THRESHOLD",
            "cli": "--health-queue-critical-threshold",
        },
        ge=1,
        le=100,
    )
    worker_stall_threshold: int = Field(
        default=60,
        description="Worker stall detection threshold in seconds",
        json_schema_extra={
            "env_var": "HEALTH_WORKER_STALL_THRESHOLD",
            "cli": "--health-worker-stall-threshold",
        },
        gt=0,
    )
    kafka_slow_threshold: float = Field(
        default=1.0,
        description="Kafka slow operation threshold in seconds",
        json_schema_extra={
            "env_var": "HEALTH_KAFKA_SLOW_THRESHOLD",
            "cli": "--health-kafka-slow-threshold",
        },
        gt=0.0,
    )
    kafka_extremely_slow_threshold: float = Field(
        default=5.0,
        description="Kafka extremely slow operation threshold in seconds",
        json_schema_extra={
            "env_var": "HEALTH_KAFKA_EXTREMELY_SLOW_THRESHOLD",
            "cli": "--health-kafka-extremely-slow-threshold",
        },
        gt=0.0,
    )

    @field_validator("queue_critical_threshold")
    @classmethod
    def validate_queue_critical_above_warning(cls, v: int, info) -> int:
        """Ensure critical threshold is higher than warning threshold."""
        if "queue_warning_threshold" in info.data:
            warning = info.data["queue_warning_threshold"]
            if v <= warning:
                raise ValueError(
                    f"queue_critical_threshold ({v}) must be greater than " f"queue_warning_threshold ({warning})"
                )
        return v

    @field_validator("kafka_extremely_slow_threshold")
    @classmethod
    def validate_kafka_extremely_slow_above_slow(cls, v: float, info) -> float:
        """Ensure extremely slow threshold is higher than slow threshold."""
        if "kafka_slow_threshold" in info.data:
            slow = info.data["kafka_slow_threshold"]
            if v <= slow:
                raise ValueError(
                    f"kafka_extremely_slow_threshold ({v}) must be greater than " f"kafka_slow_threshold ({slow})"
                )
        return v

    @classmethod
    def with_legacy_log_config_warning(cls, log_config: LogConfig) -> "HealthConfig":
        """Create HealthConfig from LogConfig with migration warning.

        As specified in TODO: "if old LOG_INTERVAL found, log warning and mention new HEALTH_STATS_INTERVAL"

        Args:
            log_config: Existing LogConfig to migrate from

        Returns:
            HealthConfig: New health configuration using log_config.interval
        """
        logger = logging.getLogger(__name__)

        logger.warning(
            f"Using LogConfig.interval ({log_config.interval}s) for health monitoring. "
            f"Consider migrating to HealthConfig with HEALTH_STATS_INTERVAL environment variable."
        )

        return cls(stats_interval=log_config.interval)


class MiscConfig(BaseModel):
    """Miscellaneous configuration."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    num_workers: int = Field(
        default=10,
        description="Number of async worker tasks",
        json_schema_extra={
            "env_var": "MISC_NUM_WORKERS",
            "cli": "--misc-num-workers",
        },
        gt=0,
    )
    own_network: str | None = Field(
        default=None,
        description="Own network CIDR notation (optional)",
        json_schema_extra={
            "env_var": "MISC_OWN_NETWORK",
            "cli": "--misc-own-network",
        },
    )

    @field_validator("own_network")
    @classmethod
    def validate_cidr(cls, v: str | None) -> str | None:
        """Validate CIDR notation.

        Args:
            v: The CIDR notation string to validate, or None

        Returns:
            str or None: The validated CIDR string or None if input was None

        Raises:
            ValueError: If the CIDR notation is invalid or improperly formatted
        """
        if v is None:
            return v

        if not v or "/" not in v:
            raise ValueError(f"Invalid CIDR format: {v}")

        try:
            ipaddress.ip_network(v, strict=True)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {e!s}")

        return v


class Config(BaseModel):
    """Main configuration class."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    dfn: DFNConfig = Field(default_factory=DFNConfig)
    wazuh: WazuhConfig = Field(default_factory=WazuhConfig)
    kafka: KafkaConfig = Field(default_factory=KafkaConfig)
    log: LogConfig = Field(default_factory=LogConfig)
    health: HealthConfig = Field(default_factory=HealthConfig)
    misc: MiscConfig = Field(default_factory=MiscConfig)
    config_cache: dict[str, str] = Field(default_factory=dict, exclude=True)  # Renamed from _config_cache

    @staticmethod
    def _merge_config_values(config: "Config", section_updates: dict, overwrite_existing: bool = True) -> dict:
        """Merge configuration values with existing config.

        Args:
            config: Base configuration with default values
            section_updates: Dictionary with new values to apply
            overwrite_existing: Whether to overwrite existing non-default values

        Returns:
            dict: Merged configuration data ready to be used for creating a new Config
        """
        # Start with a dictionary containing all defaults
        config_data = config.model_dump()

        # Create a dictionary of default values to check against
        default_config = Config().model_dump()

        # Update each section with new values
        for section in ["dfn", "wazuh", "kafka", "log", "health", "misc"]:
            if section in section_updates:
                if section in config_data:
                    # Process each field in the section
                    for field, new_value in section_updates[section].items():
                        current_value = config_data[section].get(field)
                        default_value = default_config[section].get(field)

                        # Only update if:
                        # 1. overwrite_existing is True, OR
                        # 2. Current value is None, OR
                        # 3. Current value equals the default (meaning it wasn't specifically set)
                        if overwrite_existing or current_value is None or current_value == default_value:
                            config_data[section][field] = new_value
                else:
                    # Add new section
                    config_data[section] = section_updates[section]

        return config_data

    @classmethod
    def from_yaml(cls, yaml_path: str, config: "Config | None" = None) -> "Config":
        """Create Config instance from YAML file.

        Args:
            yaml_path: Path to YAML configuration file.
            config: Optional existing config object to use as base. If None, creates new config with defaults.

        Returns:
            Config: Configuration instance.

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        # Start with defaults or use provided config
        if config is None:
            config = cls()

        if not yaml_path:
            return config

        yaml_path_obj = Path(yaml_path)
        if not yaml_path_obj.exists():
            raise FileNotFoundError(f"Configuration file not found: {yaml_path}")

        print(f"Loading config from {yaml_path}")
        try:
            config_dict = yaml.safe_load(yaml_path_obj.read_text())
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML content: {e}")

        if not isinstance(config_dict, dict):
            raise ConfigValidationError("Invalid configuration format")

        # Merge YAML values with defaults - YAML should always override defaults
        config_data = cls._merge_config_values(config, config_dict, overwrite_existing=True)

        # Create a new config with the merged values
        return Config(**config_data)

    @classmethod
    def from_toml(cls, toml_path: str, config: "Config | None" = None) -> "Config":
        """Create Config instance from TOML file.

        Args:
            toml_path: Path to TOML configuration file.
            config: Optional existing config object to use as base. If None, creates new config with defaults.

        Returns:
            Config: Configuration instance.

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        # Start with defaults or use provided config
        if config is None:
            config = cls()

        if not toml_path:
            return config

        toml_path_obj = Path(toml_path)
        if not toml_path_obj.exists():
            raise FileNotFoundError(f"Configuration file not found: {toml_path}")

        print(f"Loading config from {toml_path}")
        try:
            with Path(toml_path_obj).open("rb") as f:
                config_dict = tomllib.load(f)
        except Exception as e:
            raise ConfigValidationError(f"Invalid TOML content: {e}")

        if not isinstance(config_dict, dict):
            raise ConfigValidationError("Invalid configuration format")

        # Merge TOML values with defaults - TOML should always override defaults
        config_data = cls._merge_config_values(config, config_dict, overwrite_existing=True)

        # Create a new config with the merged values
        return Config(**config_data)

    @staticmethod
    def _load_from_env(config: "Config") -> None:
        """Load configuration from environment variables."""
        # Collect updates from environment variables
        env_updates = {}

        for section_name in ["dfn", "wazuh", "kafka", "log", "health", "misc"]:
            section_updates = {}
            section_model = getattr(config, section_name)

            for field_name, field_info in section_model.model_fields.items():
                if field_name.startswith("_"):  # Skip private fields
                    continue
                env_var = field_info.json_schema_extra.get("env_var") if field_info.json_schema_extra else None
                if env_var and env_var in os.environ:
                    value = os.environ[env_var]

                    # If the field type is a dictionary and the value is a JSON string, parse it
                    field_type = field_info.annotation
                    if field_type is dict or (hasattr(field_type, "__origin__") and field_type.__origin__ is dict):
                        # Try to parse as JSON if it looks like JSON
                        if isinstance(value, str) and value.strip().startswith("{") and value.strip().endswith("}"):
                            try:
                                value = json.loads(value)
                            except json.JSONDecodeError:
                                LOGGER.warning(f"Failed to parse JSON for environment variable {env_var}")

                    section_updates[field_name] = value

            if section_updates:
                env_updates[section_name] = section_updates

        # Merge environment values with current config
        # Environment variables should only override defaults, not YAML/TOML values
        if env_updates:
            merged_data = Config._merge_config_values(config, env_updates, overwrite_existing=False)

            # Apply the merged values to the config sections
            for section_name in ["dfn", "wazuh", "kafka", "log", "health", "misc"]:
                if section_name in merged_data:
                    section_cls = type(getattr(config, section_name))
                    setattr(config, section_name, section_cls(**merged_data[section_name]))

    @staticmethod
    def _load_from_cli(config: "Config", args: argparse.Namespace) -> None:
        """Load configuration from command line arguments."""
        # Collect updates from CLI arguments
        cli_updates = {}

        for section_name in ["dfn", "wazuh", "kafka", "log", "health", "misc"]:
            section_updates = {}
            section_model = getattr(config, section_name)

            for field_name, field_info in section_model.model_fields.items():
                if field_name.startswith("_"):  # Skip private fields
                    continue
                cli_flag = field_info.json_schema_extra.get("cli") if field_info.json_schema_extra else None
                if cli_flag:
                    arg_name = cli_flag.lstrip("-").replace("-", "_")
                    value = getattr(args, arg_name, None)
                    if value is not None:
                        section_updates[field_name] = value

            if section_updates:
                cli_updates[section_name] = section_updates

        # Merge CLI values with current config
        # CLI args should take highest precedence and override everything
        if cli_updates:
            merged_data = Config._merge_config_values(config, cli_updates, overwrite_existing=True)

            # Apply the merged values to the config sections
            for section_name in ["dfn", "wazuh", "kafka", "log", "health", "misc"]:
                if section_name in merged_data:
                    section_cls = type(getattr(config, section_name))
                    setattr(config, section_name, section_cls(**merged_data[section_name]))

    def get(self, key: str, default: str | None = None) -> str:
        """Get configuration value.

        Args:
            key: Configuration key.
            default: Default value if key not found.

        Returns:
            str: Configuration value or default.
        """
        # Check instance-level cache first
        if key in self.config_cache:  # Updated reference
            return self.config_cache[key]  # Updated reference

        try:
            section, option = key.split(".")
            config_section = getattr(self, section)
            value = str(getattr(config_section, option))
            # Store in instance cache
            self.config_cache[key] = value  # Updated reference
            return value
        except (AttributeError, ValueError):
            default_value = default if default is not None else ""
            # Cache the default lookup too
            self.config_cache[key] = default_value  # Updated reference
            return default_value

    @classmethod
    def _generate_sample_config(cls, output_path: str, format: str = "toml") -> None:
        """Generate a sample configuration file.

        Args:
            output_path: Path to write the sample configuration to.
            format: Output format ('toml' or 'yaml')
        """
        config = cls()
        sample_dict = cls._build_sample_config_dict(config)
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        if format.lower() == "toml":
            content = cls._format_as_toml(config, sample_dict)
        else:
            content = cls._format_as_yaml(config, sample_dict)
        output_path_obj.write_text(content)

    @classmethod
    def _build_sample_config_dict(cls, config: "Config") -> dict:
        """Build sample configuration dictionary.

        Args:
            config: Configuration instance

        Returns:
            dict: Sample configuration dictionary
        """
        sample_dict = {"dfn": {}, "wazuh": {}, "kafka": {}, "log": {}, "misc": {}}
        # Extract fields and their defaults from each section
        for section_name, section_dict in sample_dict.items():
            section = getattr(config, section_name)

            for field_name, field_info in section.model_fields.items():
                if field_name.startswith("_"):  # Skip private fields
                    continue
                # Get the default value
                section_dict[field_name] = field_info.default

        return sample_dict

    @classmethod
    def _format_field_value(cls, value, format_type: str) -> str:
        """Format a field value for the config file.

        Args:
            value: The value to format
            format_type: The output format ('toml' or 'yaml')

        Returns:
            str: Formatted value
        """
        if isinstance(value, str):
            return f'"{value}"'
        elif isinstance(value, dict):
            return str(value)
        elif value is None:
            return "null"
        else:
            return str(value)

    @classmethod
    def _format_as_toml(cls, config: "Config", sample_dict: dict) -> str:
        """Format the config as TOML.

        Args:
            config: Configuration instance
            sample_dict: Sample configuration dictionary

        Returns:
            str: TOML formatted content
        """
        toml_lines = ["# Wazuh DFN Configuration\n"]

        for section_name in sample_dict:
            section = getattr(config, section_name)
            toml_lines.append(f"\n# {section_name.upper()} Configuration\n[{section_name}]\n")
            cls._add_fields_to_toml(toml_lines, section)

        return "".join(toml_lines)

    @classmethod
    def _add_fields_to_toml(cls, toml_lines: list, section) -> None:
        """Add fields to TOML lines.

        Args:
            toml_lines: List of TOML lines
            section: Configuration section
        """
        for field_name, field_info in section.model_fields.items():
            if field_name.startswith("_"):  # Skip private fields
                continue
            # Format the default value properly for TOML
            default_value = field_info.default
            if default_value is None:
                toml_lines.append(f"# {field_name} = null\n")
            else:
                formatted_value = cls._format_field_value(default_value, "toml")
                toml_lines.append(f"{field_name} = {formatted_value}\n")

    @classmethod
    def _format_as_yaml(cls, config: "Config", sample_dict: dict) -> str:
        """Format the config as YAML.

        Args:
            config: Configuration instance
            sample_dict: Sample configuration dictionary

        Returns:
            str: YAML formatted content
        """
        yaml_lines = ["# Wazuh DFN Configuration\n"]

        for section_name in sample_dict:
            section = getattr(config, section_name)
            yaml_lines.append(f"\n# {section_name.upper()} Configuration\n{section_name}:\n")
            cls._add_fields_to_yaml(yaml_lines, section)

        return "".join(yaml_lines)

    @classmethod
    def _add_fields_to_yaml(cls, yaml_lines: list, section) -> None:
        """Add fields to YAML lines.

        Args:
            yaml_lines: List of YAML lines
            section: Configuration section
        """
        for field_name, field_info in section.model_fields.items():
            if field_name.startswith("_"):  # Skip private fields
                continue
            # Format the default value properly for YAML
            default_value = field_info.default
            if default_value is None:
                yaml_lines.append(f"  # {field_name}: null\n")
            else:
                formatted_value = cls._format_field_value(default_value, "yaml")
                yaml_lines.append(f"  {field_name}: {formatted_value}\n")

    @classmethod
    def _add_field_comments(cls, lines: list, field_info, indent: str) -> None:
        """Add field description and environment variable comments.

        Args:
            lines: List of lines to add comments to
            field_info: Field information
            indent: Indentation string
        """
        description = field_info.description if field_info.description else "No description"
        lines.append(f"{indent}# {description}\n")

        if field_info.json_schema_extra and "env_var" in field_info.json_schema_extra:
            lines.append(f"{indent}# Environment variable: {field_info.json_schema_extra['env_var']}\n")
