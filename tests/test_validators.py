"""Test configuration validators."""

from dataclasses import dataclass

import pytest

from wazuh_dfn.exceptions import ConfigValidationError
from wazuh_dfn.validators import (
    ConfigValidator,
    DFNConfigValidator,
    KafkaConfigValidator,
    LogConfigValidator,
    MiscConfigValidator,
    ValidatorFactory,
    WazuhConfigValidator,
)


def test_config_validator_positive_integer():
    """Test positive integer validation."""
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_positive_integer(0, "test")
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_positive_integer(-1, "test")
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_positive_integer("1", "test")  # NOSONAR String should raise error

    # Should not raise
    ConfigValidator.validate_positive_integer(1, "test")  # Valid positive integer


def test_config_validator_non_empty_string():
    """Test non-empty string validation."""
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_non_empty_string("", "test")
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_non_empty_string(None, "test")  # NOSONAR
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_non_empty_string(1, "test")  # NOSONAR

    # Should not raise
    ConfigValidator.validate_non_empty_string("test", "test")


def test_kafka_config_validator():
    """Test KafkaConfigValidator with various configurations."""
    validator = KafkaConfigValidator()

    # Test valid config
    valid_config = {
        "timeout": 60,
        "retry_interval": 5,
        "connection_max_retries": 5,
        "send_max_retries": 5,
        "max_wait_time": 60,
        "admin_timeout": 10,
        "producer_config": {},
    }
    assert validator.validate(valid_config) is True

    # Test invalid timeout
    invalid_config = {
        "timeout": -1,  # Invalid: negative timeout
        "retry_interval": 5,
        "connection_max_retries": 5,
        "send_max_retries": 5,
        "max_wait_time": 60,
        "admin_timeout": 10,
        "producer_config": {},
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test missing field
    invalid_config = {
        "timeout": 60,
        # missing retry_interval
        "connection_max_retries": 5,
        "send_max_retries": 5,
        "max_wait_time": 60,
        "admin_timeout": 10,
        "producer_config": {},
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test non-integer field
    invalid_config = {
        "timeout": "60",  # Invalid: string instead of integer
        "retry_interval": 5,
        "connection_max_retries": 5,
        "send_max_retries": 5,
        "max_wait_time": 60,
        "admin_timeout": 10,
        "producer_config": {},
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test invalid retry interval
    invalid_config = {
        "timeout": 60,
        "retry_interval": -5,  # Invalid: negative retry interval
        "connection_max_retries": 5,
        "send_max_retries": 5,
        "max_wait_time": 60,
        "admin_timeout": 10,
        "producer_config": {},
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)


def test_dfn_config_validator():
    """Test DFNConfigValidator with various configurations."""
    validator = DFNConfigValidator()

    # Test valid config
    valid_config = {
        "dfn_id": "test-id",
        "dfn_broker": "test:9092",
        "dfn_ca": "ca.pem",
        "dfn_cert": "cert.pem",
        "dfn_key": "key.pem",
    }
    assert validator.validate(valid_config) is True

    # Test empty dfn_id
    invalid_config = {
        "dfn_id": "",  # Invalid: empty dfn_id
        "dfn_broker": "test:9092",
        "dfn_ca": "ca.pem",
        "dfn_cert": "cert.pem",
        "dfn_key": "key.pem",
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test empty dfn_broker
    invalid_config = {
        "dfn_id": "test-id",
        "dfn_broker": "",  # Invalid: empty broker
        "dfn_ca": "ca.pem",
        "dfn_cert": "cert.pem",
        "dfn_key": "key.pem",
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)


def test_wazuh_config_validator():
    """Test Wazuh configuration validation."""
    config = {
        "json_alert_file": "/var/ossec/logs/alerts/alerts.json",
        "unix_socket_path": "/var/ossec/queue/sockets/queue",
        "max_event_size": 65535,
        "json_alert_prefix": '{"timestamp"',
        "json_alert_suffix": "}",
        "json_alert_file_poll_interval": 1.0,
    }
    assert WazuhConfigValidator.validate(config) is True

    # Test missing required field
    config = {"unix_socket_path": "", "json_alert_file": ""}
    with pytest.raises(ConfigValidationError):
        WazuhConfigValidator.validate(config)

    # Test dictionary validation
    config_dict = {
        "json_alert_file": "/var/ossec/logs/alerts/alerts.json",
        "unix_socket_path": "/var/ossec/queue/sockets/queue",
        "max_event_size": 65535,
        "json_alert_prefix": '{"timestamp"',
        "json_alert_suffix": "}",
        "json_alert_file_poll_interval": 1.0,
    }
    assert WazuhConfigValidator.validate(config_dict) is True


def test_log_config_validator():
    """Test log configuration validation."""
    config = {"level": "INFO", "file_path": "/path/to/log"}
    assert LogConfigValidator.validate(config) is True

    # Test missing file_path
    config = {}
    with pytest.raises(ConfigValidationError):
        LogConfigValidator.validate(config)

    # Test invalid level
    config = {"level": "INVALID_LEVEL", "file_path": "/path/to/log"}
    with pytest.raises(ConfigValidationError):
        LogConfigValidator.validate(config)


def test_misc_config_validator():
    """Test misc configuration validation."""
    config = {"num_workers": 10}
    assert MiscConfigValidator.validate(config) is True

    # Test missing required field
    config = {"num_workers": 0}
    with pytest.raises(ConfigValidationError):
        MiscConfigValidator.validate(config)

    # Test dictionary validation
    config_dict = {"num_workers": 10}
    assert MiscConfigValidator.validate(config_dict) is True


def test_validator_factory():
    """Test ValidatorFactory with various validator types."""
    # Test kafka config validation
    kafka_config = {
        "timeout": 60,
        "retry_interval": 5,
        "connection_max_retries": 5,
        "send_max_retries": 5,
        "max_wait_time": 60,
        "admin_timeout": 10,
        "producer_config": {},
    }
    validator = ValidatorFactory.create_validator(kafka_config)
    assert isinstance(validator, KafkaConfigValidator)

    # Test DFN config validation
    dfn_config = {"dfn_id": "test", "dfn_broker": "localhost:9092"}
    validator = ValidatorFactory.create_validator(dfn_config)
    assert isinstance(validator, DFNConfigValidator)

    # Test Wazuh config validation
    wazuh_config = {
        "json_alert_file": "/var/ossec/logs/alerts/alerts.json",
        "unix_socket_path": "/var/ossec/queue/sockets/queue",
        "max_event_size": 65535,
        "json_alert_prefix": '{"timestamp"',
        "json_alert_suffix": "}",
        "json_alert_file_poll_interval": 1.0,
    }
    validator = ValidatorFactory.create_validator(wazuh_config)
    assert isinstance(validator, WazuhConfigValidator)

    # Test log config validation
    log_config = {"log_level": "INFO", "log_file": "/path/to/log"}
    validator = ValidatorFactory.create_validator(log_config)
    assert isinstance(validator, LogConfigValidator)

    # Test misc config validation
    misc_config = {"max_message_size": 1024, "compression_type": "gzip"}
    validator = ValidatorFactory.create_validator(misc_config)
    assert isinstance(validator, MiscConfigValidator)

    # Test invalid config
    with pytest.raises(ValueError):
        ValidatorFactory.create_validator({"invalid": "config"})


def test_misc_config_validator_edge_cases():
    """Test MiscConfigValidator with edge cases."""
    validator = MiscConfigValidator()

    # Test empty config
    with pytest.raises(ConfigValidationError):
        validator.validate({})

    # Test config with invalid types
    invalid_config = {
        "max_message_size": "1024",  # Should be int
        "compression_type": 123,  # Should be string
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test config with invalid compression type
    invalid_config = {
        "max_message_size": 1024,
        "compression_type": "invalid_type",  # Invalid compression type
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)


def test_log_config_validator_edge_cases():
    """Test LogConfigValidator with edge cases."""
    validator = LogConfigValidator()

    # Test empty config
    with pytest.raises(ConfigValidationError):
        validator.validate({})

    # Test config with invalid log level
    invalid_config = {
        "log_level": "INVALID_LEVEL",
        "log_file": "/path/to/log",
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test config with empty log file path
    invalid_config = {
        "log_level": "INFO",
        "log_file": "",
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)


def test_config_validator_dataclass():
    """Test validation of dataclass configurations."""

    @dataclass
    class TestConfig:
        value: int = 0

    # Test valid dataclass
    config = TestConfig(value=10)
    assert ConfigValidator.validate(config) is True

    # Test invalid dataclass
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate("not a dataclass")


def test_validate_dataclass_comprehensive():
    """Test comprehensive validation of dataclass configurations."""

    @dataclass
    class ComplexConfig:
        required_int: int
        required_str: str
        optional_str: str = "optional"
        optional_int: int = 0

    # Test valid dataclass with all fields
    config = ComplexConfig(required_int=10, required_str="test", optional_str="optional", optional_int=5)

    assert ConfigValidator.validate_dataclass(config) == config

    # Test valid dataclass with only required fields
    config = ComplexConfig(required_int=10, required_str="test")
    assert ConfigValidator.validate_dataclass(config) == config

    # Test invalid dataclass - missing required field
    @dataclass
    class InvalidConfig:
        required_field: str

    config = InvalidConfig(required_field="")
    with pytest.raises(ConfigValidationError) as exc_info:
        ConfigValidator.validate_dataclass(config)
    assert "Field cannot be empty: required_field" in str(exc_info.value)

    # Test non-dataclass object
    with pytest.raises(ConfigValidationError) as exc_info:
        ConfigValidator.validate_dataclass({"not": "a dataclass"})
    assert "Configuration must be a dataclass instance" in str(exc_info.value)

    # Test dataclass with missing attribute
    class BrokenConfig:
        def __init__(self):
            self._dataclass = True

    broken_config = BrokenConfig()
    with pytest.raises(ConfigValidationError) as exc_info:
        ConfigValidator.validate_dataclass(broken_config)
    assert "Configuration must be a dataclass instance" in str(exc_info.value)


def test_dfn_config_validator_edge_cases():
    """Test DFNConfigValidator with edge cases."""
    validator = DFNConfigValidator()

    # Test empty config
    with pytest.raises(ConfigValidationError):
        validator.validate({})

    # Test missing broker
    invalid_config = {
        "dfn_id": "test",
        # missing dfn_broker
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test empty dfn_id
    invalid_config = {"dfn_id": "", "dfn_broker": "localhost:9092"}
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)


def test_wazuh_config_validator_edge_cases():
    """Test WazuhConfigValidator with edge cases."""
    validator = WazuhConfigValidator()

    # Test empty config
    with pytest.raises(ConfigValidationError):
        validator.validate({})

    # Test missing required fields
    invalid_config = {
        "json_alert_file": "/var/ossec/logs/alerts/alerts.json",
        # missing unix_socket_path
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)

    # Test invalid max_event_size
    invalid_config = {
        "json_alert_file": "/var/ossec/logs/alerts/alerts.json",
        "unix_socket_path": "/var/ossec/queue/sockets/queue",
        "max_event_size": -1,  # Invalid: negative size
        "json_alert_prefix": '{"timestamp"',
        "json_alert_suffix": "}",
        "json_alert_file_poll_interval": 1.0,
    }
    with pytest.raises(ConfigValidationError):
        validator.validate(invalid_config)


def test_config_validator_non_negative_integer():
    """Test non-negative integer validation."""
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_non_negative_integer(-1, "test")
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_non_negative_integer("0", "test")  # String should raise error NOSONAR

    # Should not raise
    ConfigValidator.validate_non_negative_integer(0, "test")  # Valid: zero
    ConfigValidator.validate_non_negative_integer(1, "test")  # Valid: positive


def test_config_validator_path():
    """Test path validation."""
    # Test with skip_path_validation = False
    ConfigValidator.skip_path_validation = False

    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_path("", "test")
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_path(None, "test")  # NOSONAR
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_path("/nonexistent/path", "test")

    # Test with skip_path_validation = True
    ConfigValidator.skip_path_validation = True
    ConfigValidator.validate_path("/any/path", "test")  # Should not raise

    # Reset for other tests
    ConfigValidator.skip_path_validation = False


def test_config_validator_optional_path():
    """Test optional path validation."""
    # Test with skip_path_validation = False
    ConfigValidator.skip_path_validation = False

    # None should be valid for optional paths
    ConfigValidator.validate_optional_path(None, "test")

    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_optional_path("", "test")
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_optional_path("/nonexistent/path", "test")

    # Test with skip_path_validation = True
    ConfigValidator.skip_path_validation = True
    ConfigValidator.validate_optional_path("/any/path", "test")  # Should not raise

    # Reset for other tests
    ConfigValidator.skip_path_validation = False


def test_config_validator_dict_comprehensive():
    """Test comprehensive dictionary validation."""
    # Test empty required fields
    ConfigValidator.validate_config_dict({}, [])  # Should not raise

    # Test with required fields
    valid_config = {"field1": "value1", "field2": "value2"}
    ConfigValidator.validate_config_dict(valid_config, ["field1", "field2"])  # Should not raise

    # Test missing required field
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_config_dict({"field1": "value1"}, ["field1", "field2"])

    # Test empty string in required field
    with pytest.raises(ConfigValidationError):
        ConfigValidator.validate_config_dict({"field1": "", "field2": "value2"}, ["field1", "field2"])


def test_kafka_config_validator_producer_config():
    """Test KafkaConfigValidator producer config validation."""
    validator = KafkaConfigValidator()

    # Test with custom producer config
    config = {
        "timeout": 60,
        "retry_interval": 5,
        "connection_max_retries": 5,
        "send_max_retries": 5,
        "max_wait_time": 60,
        "admin_timeout": 10,
        "producer_config": {"batch.size": 32768, "compression.type": "lz4", "acks": "all", "enable.idempotence": True},
    }
    assert validator.validate(config) is True

    # Test with empty producer config
    config["producer_config"] = {}
    assert validator.validate(config) is True

    # Test with invalid producer config type
    config["producer_config"] = "invalid"
    with pytest.raises(ConfigValidationError):
        validator.validate(config)


def test_log_config_validator_comprehensive():
    """Test comprehensive log configuration validation."""
    validator = LogConfigValidator()

    # Test all valid log levels
    for level in LogConfigValidator.VALID_LOG_LEVELS:
        config = {"level": level, "console": True, "file_path": "/path/to/log"}
        assert validator.validate(config) is True

    # Test case insensitive log levels
    config = {"level": "debug", "console": True, "file_path": "/path/to/log"}
    assert validator.validate(config) is True

    # Test missing required fields
    config = {"level": "INFO"}  # Missing console and file_path
    with pytest.raises(ConfigValidationError):
        validator.validate(config)


def test_misc_config_validator_network():
    """Test MiscConfig network validation."""
    validator = MiscConfigValidator()

    # Test valid CIDR notation
    config = {"num_workers": 10, "own_network": "192.168.1.0/24"}
    assert validator.validate(config) is True

    # Test invalid CIDR notation
    config = {"num_workers": 10, "own_network": "192.168.1.0"}  # Missing prefix
    with pytest.raises(ConfigValidationError):
        validator.validate(config)

    config = {"num_workers": 10, "own_network": "invalid"}
    with pytest.raises(ConfigValidationError):
        validator.validate(config)

    # Test None network (optional)
    config = {"num_workers": 10, "own_network": None}
    assert validator.validate(config) is True
