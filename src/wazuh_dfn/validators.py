"""Configuration validators for Wazuh DFN."""

import logging
import os
from typing import Any, Dict, List, Optional, Union

from .config import Config, DFNConfig, KafkaConfig, LogConfig, MiscConfig, WazuhConfig
from .exceptions import ConfigValidationError

# Logging
LOGGER = logging.getLogger(__name__)


class ConfigValidator:
    """Base class for configuration validators."""

    skip_path_validation = False  # Class variable to control path validation behavior

    @classmethod
    def validate_positive_integer(cls, value: int, field_name: str) -> None:
        """Validate that a value is a positive integer.

        Args:
            value: Value to validate
            field_name: Name of the field being validated

        Raises:
            ConfigValidationError: If value is not a positive integer
        """
        try:
            if not isinstance(value, int):
                raise ConfigValidationError(f"{field_name} must be an integer")
            if value <= 0:
                raise ConfigValidationError(f"{field_name} must be positive")
        except TypeError as e:
            raise ConfigValidationError(f"{field_name} validation failed: {str(e)}")

    @classmethod
    def validate_non_negative_integer(cls, value: int, field_name: str) -> None:
        """Validate that a value is a non-negative integer.

        Args:
            value: Value to validate
            field_name: Name of the field being validated

        Raises:
            ConfigValidationError: If value is not a non-negative integer
        """
        try:
            if not isinstance(value, int):
                raise ConfigValidationError(f"{field_name} must be an integer")
            if value < 0:
                raise ConfigValidationError(f"{field_name} cannot be negative")
        except TypeError as e:
            raise ConfigValidationError(f"{field_name} validation failed: {str(e)}")

    @classmethod
    def validate_non_empty_string(cls, value: str, field_name: str) -> None:
        """Validate that a value is a non-empty string.

        Args:
            value: Value to validate
            field_name: Name of the field being validated

        Raises:
            ConfigValidationError: If value is not a non-empty string
        """
        if not isinstance(value, str):
            raise ConfigValidationError(f"{field_name} must be a string")
        if not value:
            raise ConfigValidationError(f"{field_name} cannot be empty")

    @classmethod
    def validate_path(cls, path: str, field_name: str) -> None:
        """Validate path.

        Args:
            path: Path to validate
            field_name: Field name for error message

        Raises:
            ConfigValidationError: If path is invalid
        """
        if not isinstance(path, str) or not path:
            raise ConfigValidationError(f"{field_name} must be a non-empty string")
        if not cls.skip_path_validation and not os.path.exists(path):
            raise ConfigValidationError(f"{field_name} does not exist: {path}")

    @classmethod
    def validate_optional_path(cls, path: Optional[str], field_name: str) -> None:
        """Validate optional path.

        Args:
            path: Path to validate, can be None
            field_name: Field name for error message

        Raises:
            ConfigValidationError: If path is invalid
        """
        if path is None:
            return
        if not isinstance(path, str) or not path:
            raise ConfigValidationError(f"{field_name} must be a non-empty string")
        if not cls.skip_path_validation and not os.path.exists(path):
            raise ConfigValidationError(f"{field_name} does not exist: {path}")

    @classmethod
    def validate_config_dict(cls, config: Dict[str, Any], required_fields: List[str]) -> None:
        """Validate configuration dictionary.

        Args:
            config: Configuration dictionary to validate
            required_fields: List of required fields

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        errors = []
        for field in required_fields:
            if field not in config:
                errors.append(f"Missing required field: {field}")
            elif isinstance(config[field], str) and not config[field]:
                errors.append(f"Field cannot be empty: {field}")
        if errors:
            raise ConfigValidationError(errors)

    @classmethod
    def validate_dataclass[T](cls, config: T) -> T:
        """Validate dataclass configuration.

        Args:
            config: Configuration to validate

        Returns:
            T: Validated configuration

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        errors = []
        try:
            from dataclasses import fields

            for field in fields(config):
                if not hasattr(config, field.name):
                    errors.append(f"Missing required field: {field.name}")
                elif isinstance(getattr(config, field.name), str) and not getattr(config, field.name):
                    errors.append(f"Field cannot be empty: {field.name}")
        except (TypeError, AttributeError):
            errors.append("Configuration must be a dataclass instance")
        if errors:
            raise ConfigValidationError(errors)
        return config

    @classmethod
    def validate(cls, config: Union[Dict[str, Any], Config]) -> bool:  # NOSONAR
        """Validate configuration.

        Args:
            config: Configuration to validate

        Returns:
            bool: True if configuration is valid

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        if isinstance(config, dict):
            cls.validate_config_dict(config, [])
            if "dfn" in config:
                DFNConfigValidator.validate(config["dfn"])
            if "wazuh" in config:
                WazuhConfigValidator.validate(config["wazuh"])
            if "kafka" in config:
                KafkaConfigValidator.validate(config["kafka"])
            if "log" in config:
                LogConfigValidator.validate(config["log"])
            if "misc" in config:
                MiscConfigValidator.validate(config["misc"])
        else:
            cls.validate_dataclass(config)
            if hasattr(config, "dfn"):
                DFNConfigValidator.validate(config.dfn)
            if hasattr(config, "wazuh"):
                WazuhConfigValidator.validate(config.wazuh)
            if hasattr(config, "kafka"):
                KafkaConfigValidator.validate(config.kafka)
            if hasattr(config, "log"):
                LogConfigValidator.validate(config.log)
            if hasattr(config, "misc"):
                MiscConfigValidator.validate(config.misc)
        return True


class WazuhConfigValidator(ConfigValidator):
    """Validator for WazuhConfig."""

    @classmethod
    def validate(cls, config: Union[Dict[str, Any], Any]) -> bool:
        """Validate Wazuh configuration.

        Args:
            config: Configuration to validate

        Returns:
            bool: True if configuration is valid

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        if isinstance(config, dict):
            required_fields = [
                "json_alert_file",
                "unix_socket_path",
                "max_event_size",
                "json_alert_prefix",
                "json_alert_suffix",
                "json_alert_file_poll_interval",
            ]
            ConfigValidator.validate_config_dict(config, required_fields)

            # Validate max_event_size
            if config["max_event_size"] <= 0:
                raise ConfigValidationError([f"Invalid max_event_size: {config['max_event_size']}. Must be positive"])

            # Validate poll interval
            if config["json_alert_file_poll_interval"] <= 0:
                raise ConfigValidationError(
                    [
                        f"Invalid json_alert_file_poll_interval: {config['json_alert_file_poll_interval']}. Must be positive"
                    ]
                )
        else:
            ConfigValidator.validate_dataclass(config)

        return True


class DFNConfigValidator(ConfigValidator):
    """DFN configuration validator."""

    @classmethod
    def validate(cls, config: Union[DFNConfig, Dict[str, Any]]) -> bool:
        """Validate DFN configuration.

        Args:
            config: Configuration to validate

        Returns:
            bool: True if configuration is valid

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        if isinstance(config, dict):
            required_fields = ["dfn_broker"]
            ConfigValidator.validate_config_dict(config, required_fields)

            # Validate non-empty strings
            cls.validate_non_empty_string(config["dfn_broker"], "dfn_broker")
            if "dfn_id" in config:
                cls.validate_non_empty_string(config["dfn_id"], "dfn_id")

            # Validate optional paths if present
            if "dfn_ca" in config:
                cls.validate_optional_path(config["dfn_ca"], "dfn_ca")
            if "dfn_cert" in config:
                cls.validate_optional_path(config["dfn_cert"], "dfn_cert")
            if "dfn_key" in config:
                cls.validate_optional_path(config["dfn_key"], "dfn_key")

        else:
            ConfigValidator.validate_dataclass(config)

            # Validate non-empty strings
            cls.validate_non_empty_string(config.dfn_broker, "dfn_broker")
            if config.dfn_id:
                cls.validate_non_empty_string(config.dfn_id, "dfn_id")

            # Validate optional paths
            cls.validate_optional_path(config.dfn_ca, "dfn_ca")
            cls.validate_optional_path(config.dfn_cert, "dfn_cert")
            cls.validate_optional_path(config.dfn_key, "dfn_key")

        return True


class KafkaConfigValidator(ConfigValidator):
    """Validator for Kafka configuration."""

    @classmethod
    def validate(cls, config: KafkaConfig | dict) -> bool:
        """Validate Kafka configuration.

        Args:
            config: Configuration to validate, either as KafkaConfig or dict

        Returns:
            bool: True if configuration is valid

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        if isinstance(config, dict):
            # First validate the dict has all required fields
            required_fields = [
                "timeout",
                "retry_interval",
                "connection_max_retries",
                "send_max_retries",
                "max_wait_time",
                "admin_timeout",
                "producer_config",
            ]
            cls.validate_config_dict(config, required_fields)

            # Now validate each field
            try:
                cls.validate_positive_integer(config["timeout"], "timeout")
                cls.validate_positive_integer(config["retry_interval"], "retry_interval")
                cls.validate_positive_integer(config["connection_max_retries"], "connection_max_retries")
                cls.validate_positive_integer(config["send_max_retries"], "send_max_retries")
                cls.validate_positive_integer(config["max_wait_time"], "max_wait_time")
                cls.validate_positive_integer(config["admin_timeout"], "admin_timeout")

                if not isinstance(config["producer_config"], dict):
                    raise ConfigValidationError(
                        f"producer_config must be a dictionary, but got: {type(config['producer_config'])}"
                    )

                # Convert to KafkaConfig after validation
                config = KafkaConfig(**config)
            except (TypeError, ValueError) as e:
                raise ConfigValidationError(f"Invalid configuration: {str(e)}")

        else:
            # Validate KafkaConfig fields
            cls.validate_positive_integer(config.timeout, "timeout")
            cls.validate_positive_integer(config.retry_interval, "retry_interval")
            cls.validate_positive_integer(config.connection_max_retries, "connection_max_retries")
            cls.validate_positive_integer(config.send_max_retries, "send_max_retries")
            cls.validate_positive_integer(config.max_wait_time, "max_wait_time")
            cls.validate_positive_integer(config.admin_timeout, "admin_timeout")

            if not isinstance(config.producer_config, dict):
                raise ConfigValidationError(
                    f"producer_config must be a dictionary, but got: {type(config.producer_config)}"
                )

        return True


class LogConfigValidator(ConfigValidator):
    """Validator for log configuration."""

    VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

    @staticmethod
    def _validate_file_path(file_path: str) -> None:
        if ConfigValidator.skip_path_validation:
            return

        """Validate file path exists and is readable."""
        if not os.path.exists(file_path):
            raise ConfigValidationError(f"Log file path does not exist: {file_path}")
        if not os.access(file_path, os.R_OK):
            raise ConfigValidationError(f"Log file is not readable: {file_path}")

    @staticmethod
    def _validate_log_level(level: str) -> None:
        """Validate log level is valid."""
        if not level or level.upper() not in LogConfigValidator.VALID_LOG_LEVELS:
            raise ConfigValidationError(f"Invalid log level: {level}")

    @staticmethod
    def _validate_interval(interval: int) -> None:
        """Validate logging interval."""
        if not isinstance(interval, int) or interval <= 0:
            raise ConfigValidationError(f"Invalid interval: {interval}, must be a positive integer")

    @staticmethod
    def _validate_keep_files(keep_files: int) -> None:
        """Validate number of log files to keep."""
        if not isinstance(keep_files, int) or keep_files <= 0:
            raise ConfigValidationError(f"Invalid keep_files: {keep_files}, must be a positive integer")

    @staticmethod
    def validate(config: Union[Dict[str, Any], LogConfig]) -> bool:
        """Validate log configuration.

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        if not isinstance(config, (dict, LogConfig)):
            raise ConfigValidationError("Invalid log configuration type")

        config_dict = config if isinstance(config, dict) else config.__dict__

        # Required fields
        required = ["file_path"]
        for field in required:
            if field not in config_dict:
                raise ConfigValidationError(f"Missing required field: {field}")

        # Validate fields
        LogConfigValidator._validate_file_path(config_dict["file_path"])

        if "level" in config_dict:
            LogConfigValidator._validate_log_level(config_dict["level"])

        if "keep_files" in config_dict:
            LogConfigValidator._validate_keep_files(config_dict["keep_files"])

        if "interval" in config_dict:
            LogConfigValidator._validate_interval(config_dict["interval"])

        return True


class MiscConfigValidator(ConfigValidator):
    """Validator for miscellaneous configuration."""

    @staticmethod
    def _validate_num_workers(num_workers: int) -> None:
        """Validate number of worker threads."""
        if not isinstance(num_workers, int):
            raise ConfigValidationError("num_workers must be an integer")
        if num_workers <= 0:
            raise ConfigValidationError("num_workers must be positive")

    @staticmethod
    def _validate_cidr(cidr: str) -> None:
        """Validate CIDR notation."""
        if not cidr or "/" not in cidr:
            raise ConfigValidationError(f"Invalid CIDR format: {cidr}")
        try:
            import ipaddress

            ipaddress.ip_network(cidr, strict=True)
        except ValueError as e:
            raise ConfigValidationError(f"Invalid CIDR notation: {str(e)}")

    @staticmethod
    def validate(config: Union[MiscConfig, Dict[str, Any]]) -> bool:
        """Validate miscellaneous configuration.

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        if not isinstance(config, (dict, MiscConfig)):
            raise ConfigValidationError("Invalid configuration type")

        config_dict = config if isinstance(config, dict) else config.__dict__

        # Required fields
        if "num_workers" not in config_dict:
            raise ConfigValidationError("Missing required field: num_workers")

        # Validate fields
        MiscConfigValidator._validate_num_workers(config_dict["num_workers"])

        if config_dict.get("own_network"):
            MiscConfigValidator._validate_cidr(config_dict["own_network"])

        return True


class ValidatorFactory:
    """Factory for creating configuration validators."""

    @staticmethod
    def create_validator(config: Union[Dict[str, Any], Any]) -> ConfigValidator:  # NOSONAR
        """Create a validator for the given configuration.

        Args:
            config: Configuration to create validator for

        Returns:
            ConfigValidator: Validator for the configuration

        Raises:
            ValueError: If no validator is found for the configuration
        """
        # Check if config is a dataclass instance
        if isinstance(config, DFNConfig):
            return DFNConfigValidator()
        elif isinstance(config, WazuhConfig):
            return WazuhConfigValidator()
        elif isinstance(config, KafkaConfig):
            return KafkaConfigValidator()
        elif isinstance(config, LogConfig):
            return LogConfigValidator()
        elif isinstance(config, MiscConfig):
            return MiscConfigValidator()

        # Handle dictionary configs
        if isinstance(config, dict):
            # Check if config has DFN-specific fields
            if all(k in config for k in ["dfn_id", "dfn_broker"]):
                return DFNConfigValidator()

            # Check if config has Wazuh-specific fields
            if all(
                k in config for k in ["json_alert_file", "unix_socket_path", "json_alert_prefix", "json_alert_suffix"]
            ):
                return WazuhConfigValidator()

            # Check if config has Kafka-specific fields
            if all(k in config for k in ["timeout", "retry_interval", "producer_config"]):
                return KafkaConfigValidator()

            # Check if config has Log-specific fields
            if "log_level" in config and "log_file" in config:
                return LogConfigValidator()

            # Check if config has Misc-specific fields
            if all(k in config for k in ["max_message_size", "compression_type"]):
                return MiscConfigValidator()

        raise ValueError(f"No validator found for configuration: {config}")


def validate_config(config: Any) -> None:
    """Validate entire configuration.

    Args:
        config: Configuration to validate

    Raises:
        ConfigValidationError: If configuration is invalid
    """
    ValidatorFactory.create_validator(config.dfn).validate(config.dfn)
    ValidatorFactory.create_validator(config.wazuh).validate(config.wazuh)
    ValidatorFactory.create_validator(config.kafka).validate(config.kafka)
    ValidatorFactory.create_validator(config.log).validate(config.log)
    ValidatorFactory.create_validator(config.misc).validate(config.misc)
