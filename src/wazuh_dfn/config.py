"""Configuration module for Wazuh DFN service."""

import argparse
import logging
import yaml
from .exceptions import ConfigValidationError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Logging
LOGGER = logging.getLogger(__name__)


@dataclass
class WazuhConfig:
    """Wazuh configuration settings."""

    unix_socket_path: str = field(
        default="/var/ossec/queue/sockets/queue",
        metadata={
            "help": "Path to Wazuh socket for receiving alerts",
            "env_var": "WAZUH_UNIX_SOCKET_PATH",
            "cli": "--wazuh-unix-socket-path",
        },
    )
    max_event_size: int = field(
        default=65535,
        metadata={
            "help": "Maximum size of events to process",
            "env_var": "WAZUH_MAX_EVENT_SIZE",
            "cli": "--wazuh-max-event-size",
        },
    )
    json_alert_file: str = field(
        default="/var/ossec/logs/alerts/alerts.json",
        metadata={
            "help": "Full path to the JSON alerts file to monitor",
            "env_var": "WAZUH_JSON_ALERT_FILE",
            "cli": "--wazuh-json-alert-file",
        },
    )
    json_alert_prefix: str = field(
        default='{"timestamp"',
        metadata={
            "help": "Expected prefix of JSON alert lines",
            "env_var": "WAZUH_JSON_ALERT_PREFIX",
            "cli": "--wazuh-json-prefix",
        },
    )
    json_alert_suffix: str = field(
        default="}",
        metadata={
            "help": "Expected suffix of JSON alert lines",
            "env_var": "WAZUH_JSON_ALERT_SUFFIX",
            "cli": "--wazuh-json-suffix",
        },
    )
    max_retries: int = field(
        default=42,
        metadata={
            "help": "Maximum number of retries",
            "env_var": "WAZUH_MAX_RETRIES",
            "cli": "--wazuh-max-retries",
        },
    )
    retry_interval: int = field(
        default=5,
        metadata={
            "help": "Interval between retries in seconds",
            "env_var": "WAZUH_RETRY_INTERVAL",
            "cli": "--wazuh-retry-interval",
        },
    )
    json_alert_file_poll_interval: float = field(
        default=1.0,
        metadata={
            "help": "Interval in seconds between JSON alert file checks",
            "env_var": "WAZUH_JSON_ALERT_FILE_POLL_INTERVAL",
            "cli": "--wazuh-json-alert-file-poll-interval",
        },
    )
    store_failed_alerts: bool = field(
        default=False,
        metadata={
            "help": "Whether to store failed alerts for later analysis",
            "env_var": "WAZUH_STORE_FAILED_ALERTS",
            "cli": "--wazuh-store-failed-alerts",
        },
    )
    failed_alerts_path: str = field(
        default="/opt/wazuh-dfn/failed-alerts",
        metadata={
            "help": "Directory path to store failed alerts",
            "env_var": "WAZUH_FAILED_ALERTS_PATH",
            "cli": "--wazuh-failed-alerts-path",
        },
    )
    max_failed_files: int = field(
        default=100,
        metadata={
            "help": "Maximum number of failed alert files to keep",
            "env_var": "WAZUH_MAX_FAILED_FILES",
            "cli": "--wazuh-max-failed-files",
        },
    )
    json_alert_queue_size: int = field(
        default=100000,
        metadata={
            "help": "Maximum number of alerts to queue for processing",
            "env_var": "WAZUH_JSON_ALERT_QUEUE_SIZE",
            "cli": "--wazuh-json-alert-queue-size",
        },
    )

    def __post_init__(self):
        """Validate configuration after initialization."""
        from .validators import WazuhConfigValidator

        validator = WazuhConfigValidator()
        validator.validate(self)


@dataclass
class DFNConfig:
    """DFN-specific configuration parameters."""

    dfn_broker: str = field(
        default="kafka.example.org:443",
        metadata={
            "help": "DFN Kafka broker address",
            "env_var": "DFN_BROKER_ADDRESS",
            "cli": "--dfn-broker-address",
        },
    )
    dfn_ca: str = field(
        default="/opt/wazuh-dfn/certs/dfn-ca.pem",
        metadata={
            "help": "Path to CA certificate for Kafka SSL",
            "env_var": "DFN_CA_PATH",
            "cli": "--dfn-ca-path",
        },
    )
    dfn_cert: str = field(
        default="/opt/wazuh-dfn/certs/dfn-cert.pem",
        metadata={
            "help": "Path to client certificate for Kafka SSL",
            "env_var": "DFN_CERT_PATH",
            "cli": "--dfn-cert-path",
        },
    )
    dfn_key: str = field(
        default="/opt/wazuh-dfn/certs/dfn-key.pem",
        metadata={
            "help": "Path to client key for Kafka SSL",
            "env_var": "DFN_KEY_PATH",
            "cli": "--dfn-key-path",
        },
    )
    dfn_id: str = field(
        default=None,
        metadata={
            "help": "DFN customer ID",
            "env_var": "DFN_CUSTOMER_ID",
            "cli": "--dfn-customer-id",
        },
    )

    def __post_init__(self):
        """Validate configuration after initialization."""
        from .validators import DFNConfigValidator

        validator = DFNConfigValidator()
        validator.validate(self)


@dataclass
class KafkaConfig:
    """Kafka configuration."""

    timeout: int = field(
        default=60,
        metadata={
            "help": "Kafka request timeout in seconds",
            "env_var": "KAFKA_TIMEOUT",
            "cli": "--kafka-timeout",
        },
    )
    retry_interval: int = field(
        default=5,
        metadata={
            "help": "Interval between retries in seconds",
            "env_var": "KAFKA_RETRY_INTERVAL",
            "cli": "--kafka-retry-interval",
        },
    )
    connection_max_retries: int = field(
        default=5,
        metadata={
            "help": "Maximum number of connection retries",
            "env_var": "KAFKA_CONNECTION_MAX_RETRIES",
            "cli": "--kafka-connection-max-retries",
        },
    )
    send_max_retries: int = field(
        default=5,
        metadata={
            "help": "Maximum number of send retries",
            "env_var": "KAFKA_SEND_MAX_RETRIES",
            "cli": "--kafka-send-max-retries",
        },
    )
    max_wait_time: int = field(
        default=60,
        metadata={
            "help": "Maximum wait time between retries in seconds",
            "env_var": "KAFKA_MAX_WAIT_TIME",
            "cli": "--kafka-max-wait-time",
        },
    )
    admin_timeout: int = field(
        default=10,
        metadata={
            "help": "Timeout for admin operations in seconds",
            "env_var": "KAFKA_ADMIN_TIMEOUT",
            "cli": "--kafka-admin-timeout",
        },
    )
    service_retry_interval: int = field(
        default=5,
        metadata={
            "help": "Interval between service retries in seconds",
            "env_var": "KAFKA_SERVICE_RETRY_INTERVAL",
            "cli": "--kafka-service-retry-interval",
        },
    )
    producer_config: dict[str, Any] = field(
        default_factory=lambda: {
            "request.timeout.ms": 60000,
            "connections.max.idle.ms": 540000,  # 9 minutes
            "socket.keepalive.enable": True,
            "linger.ms": 1000,  # Controls how long to wait before sending a batch
            "batch.size": 16384,  # Maximum size of a batch in bytes
            "batch.num.messages": 100,  # Maximum number of messages in a batch
            "enable.idempotence": True,  # Ensure exactly-once delivery
            "acks": "all",  # Wait for all replicas
            "statistics.interval.ms": 0,  # Disable stats for better performance
            "log_level": 0,  # Only log errors
        },
        metadata={
            "help": "Kafka producer configuration",
            "env_var": "KAFKA_PRODUCER_CONFIG",
            "cli": "--kafka-producer-config",
        },
    )

    def __post_init__(self):
        """Validate configuration after initialization."""
        from .validators import KafkaConfigValidator

        validator = KafkaConfigValidator()
        validator.validate(self)

    def get_kafka_config(self, dfn_config: DFNConfig) -> dict:
        """Get Kafka configuration dictionary.

        Args:
            dfn_config: DFN configuration containing broker and SSL settings

        Returns:
            dict: Kafka configuration settings.
        """
        config = {
            "bootstrap.servers": dfn_config.dfn_broker,
            "security.protocol": "SSL",
            "ssl.ca.location": dfn_config.dfn_ca,
            "ssl.certificate.location": dfn_config.dfn_cert,
            "ssl.key.location": dfn_config.dfn_key,
            "socket.timeout.ms": self.timeout * 1000,
            "message.timeout.ms": self.timeout * 1000,
            "retry.backoff.ms": self.retry_interval * 1000,
        } | self.producer_config
        return config


@dataclass
class LogConfig:
    """Logging configuration."""

    console: bool = field(
        default=True,
        metadata={
            "help": "Enable console logging",
            "env_var": "LOG_CONSOLE_ENABLED",
            "cli": "--log-console-enabled",
        },
    )
    file_path: str = field(
        default="/opt/wazuh-dfn/logs/wazuh-dfn.log",
        metadata={
            "help": "Path to log file",
            "env_var": "LOG_FILE_PATH",
            "cli": "--log-file-path",
        },
    )
    keep_files: int = field(
        default=5,
        metadata={
            "help": "Number of log files to keep when rotating",
            "env_var": "LOG_KEEP_FILES",
            "cli": "--log-keep-files",
        },
    )
    interval: int = field(
        default=600,
        metadata={
            "help": "Statistics logging interval in seconds",
            "env_var": "LOG_INTERVAL",
            "cli": "--log-interval",
        },
    )
    level: str = field(
        default="INFO",
        metadata={
            "help": "Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
            "env_var": "LOG_LEVEL",
            "cli": "--log-level",
        },
    )

    def __post_init__(self):
        """Validate configuration after initialization."""
        from .validators import LogConfigValidator

        validator = LogConfigValidator()
        validator.validate(self)


@dataclass
class MiscConfig:
    """Miscellaneous configuration."""

    num_workers: int = field(
        default=10,
        metadata={
            "help": "Number of worker threads",
            "env_var": "MISC_NUM_WORKERS",
            "cli": "--misc-num-workers",
        },
    )
    own_network: str | None = field(
        default=None,
        metadata={
            "help": "Own network CIDR notation (optional)",
            "env_var": "MISC_OWN_NETWORK",
            "cli": "--misc-own-network",
        },
    )

    def __post_init__(self):
        """Validate configuration after initialization."""
        from .validators import MiscConfigValidator

        validator = MiscConfigValidator()
        validator.validate(self)


@dataclass
class Config:
    """Main configuration class."""

    dfn: DFNConfig = field(default_factory=DFNConfig)
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    kafka: KafkaConfig = field(default_factory=KafkaConfig)
    log: LogConfig = field(default_factory=LogConfig)
    misc: MiscConfig = field(default_factory=MiscConfig)
    _config_cache: dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def from_yaml(cls, yaml_path: str, config: Optional["Config"] = None) -> "Config":  # NOSONAR
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
            raise FileNotFoundError

        print(f"Loading config from {yaml_path}")
        try:
            config_dict = yaml.safe_load(yaml_path_obj.read_text())
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML content: {e}")

        if not isinstance(config_dict, dict):
            raise ConfigValidationError("Invalid configuration format")

        # Load YAML values
        if "dfn" in config_dict:
            for k, v in config_dict["dfn"].items():
                setattr(config.dfn, k, v)
        if "wazuh" in config_dict:
            for k, v in config_dict["wazuh"].items():
                setattr(config.wazuh, k, v)
        if "kafka" in config_dict:
            for k, v in config_dict["kafka"].items():
                setattr(config.kafka, k, v)
        if "log" in config_dict:
            for k, v in config_dict["log"].items():
                setattr(config.log, k, v)
        if "misc" in config_dict:
            for k, v in config_dict["misc"].items():
                setattr(config.misc, k, v)

        """Validate configuration after initialization."""
        from .validators import ConfigValidator

        validator = ConfigValidator()
        validator.validate(config)

        return config

    @staticmethod
    def _convert_value(value: str, field_type: type) -> Any:
        """Convert string value to the appropriate type.

        Args:
            value: Value to convert
            field_type: Target type

        Returns:
            Converted value
        """
        if field_type == bool:
            return str(value).lower() in ("true", "1", "yes")
        if field_type == int:
            return int(value)
        if field_type == float:
            return float(value)
        return value

    @staticmethod
    def _load_from_env(config: "Config") -> None:
        """Load configuration from environment variables."""
        import os  # Import os only for environment variables access

        for cls_name in ["dfn", "wazuh", "kafka", "log", "misc"]:
            config_section = getattr(config, cls_name)
            for field_name, field_obj in config_section.__class__.__dataclass_fields__.items():
                env_var = field_obj.metadata.get("env_var")
                if env_var and env_var in os.environ:
                    value = os.environ[env_var]
                    setattr(config_section, field_name, Config._convert_value(value, field_obj.type))

    @staticmethod
    def _load_from_cli(config: "Config", args: argparse.Namespace) -> None:
        """Load configuration from command line arguments."""
        for cls_name in ["dfn", "wazuh", "kafka", "log", "misc"]:
            config_section = getattr(config, cls_name)
            for field_name, field_obj in config_section.__class__.__dataclass_fields__.items():
                cli_flag = field_obj.metadata.get("cli")
                if cli_flag:
                    arg_name = cli_flag.lstrip("-").replace("-", "_")
                    value = getattr(args, arg_name, None)
                    if value is not None:
                        setattr(config_section, field_name, Config._convert_value(value, field_obj.type))

    def get(self, key: str, default: str | None = None) -> str:
        """Get configuration value.

        Args:
            key: Configuration key.
            default: Default value if key not found.

        Returns:
            str: Configuration value or default.
        """
        # Check instance-level cache first
        if key in self._config_cache:
            return self._config_cache[key]

        try:
            section, option = key.split(".")
            config_section = getattr(self, section)
            value = str(getattr(config_section, option))
            # Store in instance cache
            self._config_cache[key] = value
            return value
        except (AttributeError, ValueError):
            default_value = default if default is not None else ""
            # Cache the default lookup too
            self._config_cache[key] = default_value
            return default_value

    @classmethod
    def _generate_sample_config(cls, output_path: str) -> None:
        """Generate a sample configuration file."""
        config = cls()
        sample_dict = {"dfn": {}, "wazuh": {}, "kafka": {}, "log": {}, "misc": {}}

        for section_name, section_dict in sample_dict.items():
            section = getattr(config, section_name)
            section_dict.update(
                {
                    field_name: field_obj.default
                    for field_name, field_obj in section.__class__.__dataclass_fields__.items()  # pylint: disable=no-member
                }
            )

        # Add comments with help text
        yaml_lines = ["# Wazuh DFN Configuration\n"]

        for section_name in sample_dict:
            section = getattr(config, section_name)
            yaml_lines.append(f"\n# {section_name.upper()} Configuration\n{section_name}:\n")

            for field_name, field_obj in section.__class__.__dataclass_fields__.items():  # pylint: disable=no-member
                if "metadata" in field_obj.metadata:
                    metadata = field_obj.metadata["metadata"]
                    yaml_lines.append(f"  # {metadata['help']}\n")
                    if "env_var" in metadata:
                        yaml_lines.append(f"  # Environment variable: {metadata['env_var']}\n")
                    yaml_lines.append(f"  {field_name}: {field_obj.default}\n")

        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)
        output_path_obj.write_text("".join(yaml_lines))
